// Package store persists PSIRTMap's product inventory in SQLite.
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	_ "modernc.org/sqlite"
)

const schemaVersion = 2

const (
	maxIdentifierLength  = 1024
	maxDescriptionLength = 8192
)

var (
	// ErrAlreadyExists is returned when an inventory object would duplicate an
	// existing object with the same identity.
	ErrAlreadyExists = errors.New("already exists")
	// ErrNotFound is returned when a referenced product or release is missing.
	ErrNotFound = errors.New("not found")
)

// DB is a SQLite-backed product inventory.
type DB struct {
	db   *sql.DB
	path string
}

// Product is a shipped product family.
type Product struct {
	Name        string    `json:"name"`
	Description string    `json:"description,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// Release is a released version of a product.
type Release struct {
	Product   string    `json:"product"`
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"created_at"`
}

// Component is a package included in a particular product release.
type Component struct {
	Product        string    `json:"product"`
	ReleaseVersion string    `json:"release"`
	Ecosystem      string    `json:"ecosystem"`
	Name           string    `json:"name"`
	Version        string    `json:"version"`
	PURL           string    `json:"purl,omitempty"`
	CreatedAt      time.Time `json:"created_at"`
}

// ComponentInput is one validated package identity to import into a release.
type ComponentInput struct {
	Ecosystem string
	Name      string
	Version   string
	PURL      string
}

// SBOMImportMetadata records the source document used to populate a release.
type SBOMImportMetadata struct {
	Format         string
	SpecVersion    string
	SerialNumber   string
	DocumentSHA256 string
	SourceName     string
	Discovered     int
	Skipped        int
	Duplicates     int
}

// ComponentImportResult reports the outcome of one atomic SBOM import.
type ComponentImportResult struct {
	Product        string `json:"product"`
	ReleaseVersion string `json:"release"`
	CreatedRelease bool   `json:"created_release"`
	Imported       int    `json:"imported"`
	AlreadyPresent int    `json:"already_present"`
}

// Open opens a database, creates its parent directory when needed, and applies
// the current schema. Opening the database is idempotent.
func Open(ctx context.Context, path string) (*DB, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, errors.New("database path is required")
	}

	if path != ":memory:" {
		parent := filepath.Dir(path)
		if err := os.MkdirAll(parent, 0o700); err != nil {
			return nil, fmt.Errorf("create database directory: %w", err)
		}
	}

	sqlDB, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	// One connection keeps SQLite PRAGMAs deterministic and is ample for a
	// local, single-process CLI.
	sqlDB.SetMaxOpenConns(1)

	database := &DB{db: sqlDB, path: path}
	if err := database.configure(ctx); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if err := database.migrate(ctx); err != nil {
		sqlDB.Close()
		return nil, err
	}
	if path != ":memory:" {
		if err := os.Chmod(path, 0o600); err != nil {
			sqlDB.Close()
			return nil, fmt.Errorf("secure database permissions: %w", err)
		}
	}

	return database, nil
}

func (d *DB) configure(ctx context.Context) error {
	for _, statement := range []string{
		"PRAGMA foreign_keys = ON",
		"PRAGMA busy_timeout = 5000",
		"PRAGMA journal_mode = WAL",
	} {
		if _, err := d.db.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("configure SQLite: %w", err)
		}
	}
	return nil
}

func (d *DB) migrate(ctx context.Context) error {
	transaction, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin schema migration: %w", err)
	}
	defer transaction.Rollback()

	var currentVersion int
	if err := transaction.QueryRowContext(ctx, "PRAGMA user_version").Scan(&currentVersion); err != nil {
		return fmt.Errorf("read schema version: %w", err)
	}
	if currentVersion > schemaVersion {
		return fmt.Errorf("database schema version %d is newer than supported version %d", currentVersion, schemaVersion)
	}

	if currentVersion < 1 {
		statements := []string{
			`CREATE TABLE products (
				id INTEGER PRIMARY KEY,
				name TEXT NOT NULL COLLATE NOCASE UNIQUE,
				description TEXT NOT NULL DEFAULT '',
				created_at TEXT NOT NULL
			)`,
			`CREATE TABLE releases (
				id INTEGER PRIMARY KEY,
				product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE,
				version TEXT NOT NULL,
				created_at TEXT NOT NULL,
				UNIQUE(product_id, version)
			)`,
			`CREATE TABLE components (
				id INTEGER PRIMARY KEY,
				release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
				ecosystem TEXT NOT NULL,
				name TEXT NOT NULL,
				version TEXT NOT NULL,
				created_at TEXT NOT NULL,
				UNIQUE(release_id, ecosystem, name, version)
			)`,
			`CREATE INDEX components_release_id_idx ON components(release_id)`,
			`PRAGMA user_version = 1`,
		}
		for _, statement := range statements {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply schema migration: %w", err)
			}
		}
	}

	if currentVersion < 2 {
		statements := []string{
			`ALTER TABLE components ADD COLUMN purl TEXT NOT NULL DEFAULT ''`,
			`CREATE TABLE sbom_imports (
				id INTEGER PRIMARY KEY,
				release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
				format TEXT NOT NULL,
				spec_version TEXT NOT NULL,
				serial_number TEXT NOT NULL DEFAULT '',
				document_sha256 TEXT NOT NULL,
				source_name TEXT NOT NULL DEFAULT '',
				components_discovered INTEGER NOT NULL,
				components_imported INTEGER NOT NULL,
				components_already_present INTEGER NOT NULL,
				components_skipped INTEGER NOT NULL,
				components_duplicated INTEGER NOT NULL,
				created_at TEXT NOT NULL
			)`,
			`CREATE INDEX sbom_imports_release_id_idx ON sbom_imports(release_id)`,
			`PRAGMA user_version = 2`,
		}
		for _, statement := range statements {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply schema migration: %w", err)
			}
		}
	}

	if err := transaction.Commit(); err != nil {
		return fmt.Errorf("commit schema migration: %w", err)
	}
	return nil
}

// Close closes the underlying database.
func (d *DB) Close() error {
	return d.db.Close()
}

// Path returns the configured database path.
func (d *DB) Path() string {
	return d.path
}

// CreateProduct adds a product to the inventory.
func (d *DB) CreateProduct(ctx context.Context, name, description string) (Product, error) {
	var err error
	name, err = cleanIdentifier("product name", name)
	if err != nil {
		return Product{}, err
	}
	description, err = cleanDescription(description)
	if err != nil {
		return Product{}, err
	}

	createdAt := time.Now().UTC().Truncate(time.Second)
	_, err = d.db.ExecContext(ctx,
		"INSERT INTO products(name, description, created_at) VALUES (?, ?, ?)",
		name, description, formatTime(createdAt),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return Product{}, fmt.Errorf("product %q: %w", name, ErrAlreadyExists)
		}
		return Product{}, fmt.Errorf("create product: %w", err)
	}
	return Product{Name: name, Description: description, CreatedAt: createdAt}, nil
}

// ListProducts returns products sorted by name.
func (d *DB) ListProducts(ctx context.Context) ([]Product, error) {
	rows, err := d.db.QueryContext(ctx,
		"SELECT name, description, created_at FROM products ORDER BY name COLLATE NOCASE",
	)
	if err != nil {
		return nil, fmt.Errorf("list products: %w", err)
	}
	defer rows.Close()

	products := make([]Product, 0)
	for rows.Next() {
		var product Product
		var createdAt string
		if err := rows.Scan(&product.Name, &product.Description, &createdAt); err != nil {
			return nil, fmt.Errorf("read product: %w", err)
		}
		product.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		products = append(products, product)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list products: %w", err)
	}
	return products, nil
}

// CreateRelease adds a version to an existing product.
func (d *DB) CreateRelease(ctx context.Context, productName, version string) (Release, error) {
	var err error
	productName, err = cleanIdentifier("product name", productName)
	if err != nil {
		return Release{}, err
	}
	version, err = cleanIdentifier("release version", version)
	if err != nil {
		return Release{}, err
	}

	productID, canonicalName, err := d.productID(ctx, productName)
	if err != nil {
		return Release{}, err
	}
	createdAt := time.Now().UTC().Truncate(time.Second)
	_, err = d.db.ExecContext(ctx,
		"INSERT INTO releases(product_id, version, created_at) VALUES (?, ?, ?)",
		productID, version, formatTime(createdAt),
	)
	if err != nil {
		if isUniqueConstraint(err) {
			return Release{}, fmt.Errorf("release %s@%s: %w", canonicalName, version, ErrAlreadyExists)
		}
		return Release{}, fmt.Errorf("create release: %w", err)
	}
	return Release{Product: canonicalName, Version: version, CreatedAt: createdAt}, nil
}

// GetRelease returns one release and its canonical product name.
func (d *DB) GetRelease(ctx context.Context, productName, version string) (Release, error) {
	var err error
	productName, err = cleanIdentifier("product name", productName)
	if err != nil {
		return Release{}, err
	}
	version, err = cleanIdentifier("release version", version)
	if err != nil {
		return Release{}, err
	}

	var release Release
	var createdAt string
	err = d.db.QueryRowContext(ctx, `SELECT p.name, r.version, r.created_at
		FROM releases r JOIN products p ON p.id = r.product_id
		WHERE p.name = ? COLLATE NOCASE AND r.version = ?`, productName, version,
	).Scan(&release.Product, &release.Version, &createdAt)
	if errors.Is(err, sql.ErrNoRows) {
		return Release{}, fmt.Errorf("release %s@%s: %w", productName, version, ErrNotFound)
	}
	if err != nil {
		return Release{}, fmt.Errorf("get release: %w", err)
	}
	release.CreatedAt, err = parseTime(createdAt)
	if err != nil {
		return Release{}, err
	}
	return release, nil
}

// ListReleases returns releases, optionally restricted to one product.
func (d *DB) ListReleases(ctx context.Context, productName string) ([]Release, error) {
	productName = strings.TrimSpace(productName)
	if productName != "" {
		var err error
		productName, err = cleanIdentifier("product name", productName)
		if err != nil {
			return nil, err
		}
	}
	query := `SELECT p.name, r.version, r.created_at
		FROM releases r JOIN products p ON p.id = r.product_id`
	var args []any
	if productName != "" {
		query += " WHERE p.name = ? COLLATE NOCASE"
		args = append(args, productName)
	}
	query += " ORDER BY p.name COLLATE NOCASE, r.version"

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list releases: %w", err)
	}
	defer rows.Close()

	releases := make([]Release, 0)
	for rows.Next() {
		var release Release
		var createdAt string
		if err := rows.Scan(&release.Product, &release.Version, &createdAt); err != nil {
			return nil, fmt.Errorf("read release: %w", err)
		}
		release.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		releases = append(releases, release)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list releases: %w", err)
	}
	return releases, nil
}

// CreateComponent records one package in a product release.
func (d *DB) CreateComponent(
	ctx context.Context,
	productName string,
	releaseVersion string,
	ecosystem string,
	name string,
	version string,
) (Component, error) {
	var err error
	for _, target := range []struct {
		label string
		value *string
	}{
		{label: "product name", value: &productName},
		{label: "release version", value: &releaseVersion},
		{label: "component ecosystem", value: &ecosystem},
		{label: "component name", value: &name},
		{label: "component version", value: &version},
	} {
		*target.value, err = cleanIdentifier(target.label, *target.value)
		if err != nil {
			return Component{}, err
		}
	}

	releaseID, canonicalProduct, err := d.releaseID(ctx, productName, releaseVersion)
	if err != nil {
		return Component{}, err
	}
	createdAt := time.Now().UTC().Truncate(time.Second)
	_, err = d.db.ExecContext(ctx, `INSERT INTO components(
		release_id, ecosystem, name, version, purl, created_at
	) VALUES (?, ?, ?, ?, '', ?)`, releaseID, ecosystem, name, version, formatTime(createdAt))
	if err != nil {
		if isUniqueConstraint(err) {
			return Component{}, fmt.Errorf(
				"component %s@%s in %s@%s: %w",
				name, version, canonicalProduct, releaseVersion, ErrAlreadyExists,
			)
		}
		return Component{}, fmt.Errorf("create component: %w", err)
	}
	return Component{
		Product:        canonicalProduct,
		ReleaseVersion: releaseVersion,
		Ecosystem:      ecosystem,
		Name:           name,
		Version:        version,
		CreatedAt:      createdAt,
	}, nil
}

// ImportReleaseComponents creates a missing release when necessary and merges
// a validated SBOM component set into it. The release, components, and import
// audit record are committed atomically.
func (d *DB) ImportReleaseComponents(
	ctx context.Context,
	productName string,
	releaseVersion string,
	components []ComponentInput,
	metadata SBOMImportMetadata,
) (ComponentImportResult, error) {
	var err error
	productName, err = cleanIdentifier("product name", productName)
	if err != nil {
		return ComponentImportResult{}, err
	}
	releaseVersion, err = cleanIdentifier("release version", releaseVersion)
	if err != nil {
		return ComponentImportResult{}, err
	}
	if len(components) == 0 {
		return ComponentImportResult{}, errors.New("SBOM has no importable components")
	}
	cleaned := make([]ComponentInput, len(components))
	for index, component := range components {
		for _, target := range []struct {
			label string
			value *string
		}{
			{label: "component ecosystem", value: &component.Ecosystem},
			{label: "component name", value: &component.Name},
			{label: "component version", value: &component.Version},
			{label: "component package URL", value: &component.PURL},
		} {
			*target.value, err = cleanIdentifier(target.label, *target.value)
			if err != nil {
				return ComponentImportResult{}, fmt.Errorf("component %d: %w", index+1, err)
			}
		}
		cleaned[index] = component
	}
	if err := validateImportMetadata(metadata); err != nil {
		return ComponentImportResult{}, err
	}

	transaction, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return ComponentImportResult{}, fmt.Errorf("begin SBOM import: %w", err)
	}
	defer transaction.Rollback()

	var productID int64
	var canonicalProduct string
	err = transaction.QueryRowContext(ctx,
		"SELECT id, name FROM products WHERE name = ? COLLATE NOCASE", productName,
	).Scan(&productID, &canonicalProduct)
	if errors.Is(err, sql.ErrNoRows) {
		return ComponentImportResult{}, fmt.Errorf("product %q: %w", productName, ErrNotFound)
	}
	if err != nil {
		return ComponentImportResult{}, fmt.Errorf("find product for SBOM import: %w", err)
	}

	result := ComponentImportResult{Product: canonicalProduct, ReleaseVersion: releaseVersion}
	var releaseID int64
	err = transaction.QueryRowContext(ctx,
		"SELECT id FROM releases WHERE product_id = ? AND version = ?", productID, releaseVersion,
	).Scan(&releaseID)
	if errors.Is(err, sql.ErrNoRows) {
		createdAt := time.Now().UTC().Truncate(time.Second)
		insert, insertErr := transaction.ExecContext(ctx,
			"INSERT INTO releases(product_id, version, created_at) VALUES (?, ?, ?)",
			productID, releaseVersion, formatTime(createdAt),
		)
		if insertErr != nil {
			return ComponentImportResult{}, fmt.Errorf("create release for SBOM import: %w", insertErr)
		}
		releaseID, err = insert.LastInsertId()
		if err != nil {
			return ComponentImportResult{}, fmt.Errorf("read imported release ID: %w", err)
		}
		result.CreatedRelease = true
	} else if err != nil {
		return ComponentImportResult{}, fmt.Errorf("find release for SBOM import: %w", err)
	}

	createdAt := time.Now().UTC().Truncate(time.Second)
	for _, component := range cleaned {
		insert, insertErr := transaction.ExecContext(ctx, `INSERT INTO components(
			release_id, ecosystem, name, version, purl, created_at
		) VALUES (?, ?, ?, ?, ?, ?)
		ON CONFLICT(release_id, ecosystem, name, version) DO NOTHING`, releaseID, component.Ecosystem, component.Name,
			component.Version, component.PURL, formatTime(createdAt))
		if insertErr != nil {
			return ComponentImportResult{}, fmt.Errorf("import component %s@%s: %w", component.Name, component.Version, insertErr)
		}
		rows, rowsErr := insert.RowsAffected()
		if rowsErr != nil {
			return ComponentImportResult{}, fmt.Errorf("read component import result: %w", rowsErr)
		}
		if rows == 1 {
			result.Imported++
		} else {
			result.AlreadyPresent++
			if _, updateErr := transaction.ExecContext(ctx, `UPDATE components
				SET purl = ?
				WHERE release_id = ? AND ecosystem = ? AND name = ? AND version = ? AND purl = ''`,
				component.PURL, releaseID, component.Ecosystem, component.Name, component.Version,
			); updateErr != nil {
				return ComponentImportResult{}, fmt.Errorf("backfill component package URL: %w", updateErr)
			}
		}
	}

	_, err = transaction.ExecContext(ctx, `INSERT INTO sbom_imports(
		release_id, format, spec_version, serial_number, document_sha256, source_name,
		components_discovered, components_imported, components_already_present,
		components_skipped, components_duplicated, created_at
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		releaseID, metadata.Format, metadata.SpecVersion, metadata.SerialNumber,
		metadata.DocumentSHA256, metadata.SourceName, metadata.Discovered, result.Imported,
		result.AlreadyPresent, metadata.Skipped, metadata.Duplicates, formatTime(createdAt),
	)
	if err != nil {
		return ComponentImportResult{}, fmt.Errorf("record SBOM import: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return ComponentImportResult{}, fmt.Errorf("commit SBOM import: %w", err)
	}
	return result, nil
}

// ListComponents returns the packages recorded for one product release.
func (d *DB) ListComponents(ctx context.Context, productName, releaseVersion string) ([]Component, error) {
	var err error
	productName, err = cleanIdentifier("product name", productName)
	if err != nil {
		return nil, err
	}
	releaseVersion, err = cleanIdentifier("release version", releaseVersion)
	if err != nil {
		return nil, err
	}
	if _, _, err := d.releaseID(ctx, productName, releaseVersion); err != nil {
		return nil, err
	}

	rows, err := d.db.QueryContext(ctx, `SELECT
		p.name, r.version, c.ecosystem, c.name, c.version, c.purl, c.created_at
		FROM components c
		JOIN releases r ON r.id = c.release_id
		JOIN products p ON p.id = r.product_id
		WHERE p.name = ? COLLATE NOCASE AND r.version = ?
		ORDER BY c.ecosystem, c.name, c.version`, productName, releaseVersion)
	if err != nil {
		return nil, fmt.Errorf("list components: %w", err)
	}
	defer rows.Close()

	components := make([]Component, 0)
	for rows.Next() {
		var component Component
		var createdAt string
		if err := rows.Scan(
			&component.Product,
			&component.ReleaseVersion,
			&component.Ecosystem,
			&component.Name,
			&component.Version,
			&component.PURL,
			&createdAt,
		); err != nil {
			return nil, fmt.Errorf("read component: %w", err)
		}
		component.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		components = append(components, component)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list components: %w", err)
	}
	return components, nil
}

// ListAllComponents returns every recorded package together with its owning
// product release. It is intended for inventory-wide views such as the local
// dashboard.
func (d *DB) ListAllComponents(ctx context.Context) ([]Component, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT
		p.name, r.version, c.ecosystem, c.name, c.version, c.purl, c.created_at
		FROM components c
		JOIN releases r ON r.id = c.release_id
		JOIN products p ON p.id = r.product_id
		ORDER BY p.name COLLATE NOCASE, r.version, c.ecosystem, c.name, c.version`)
	if err != nil {
		return nil, fmt.Errorf("list all components: %w", err)
	}
	defer rows.Close()

	components := make([]Component, 0)
	for rows.Next() {
		var component Component
		var createdAt string
		if err := rows.Scan(
			&component.Product,
			&component.ReleaseVersion,
			&component.Ecosystem,
			&component.Name,
			&component.Version,
			&component.PURL,
			&createdAt,
		); err != nil {
			return nil, fmt.Errorf("read component: %w", err)
		}
		component.CreatedAt, err = parseTime(createdAt)
		if err != nil {
			return nil, err
		}
		components = append(components, component)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list all components: %w", err)
	}
	return components, nil
}

func (d *DB) productID(ctx context.Context, name string) (int64, string, error) {
	var id int64
	var canonicalName string
	err := d.db.QueryRowContext(ctx,
		"SELECT id, name FROM products WHERE name = ? COLLATE NOCASE", name,
	).Scan(&id, &canonicalName)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf("product %q: %w", name, ErrNotFound)
	}
	if err != nil {
		return 0, "", fmt.Errorf("find product: %w", err)
	}
	return id, canonicalName, nil
}

func (d *DB) releaseID(ctx context.Context, productName, releaseVersion string) (int64, string, error) {
	var id int64
	var canonicalProduct string
	err := d.db.QueryRowContext(ctx, `SELECT r.id, p.name
		FROM releases r JOIN products p ON p.id = r.product_id
		WHERE p.name = ? COLLATE NOCASE AND r.version = ?`, productName, releaseVersion,
	).Scan(&id, &canonicalProduct)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, "", fmt.Errorf("release %s@%s: %w", productName, releaseVersion, ErrNotFound)
	}
	if err != nil {
		return 0, "", fmt.Errorf("find release: %w", err)
	}
	return id, canonicalProduct, nil
}

func isUniqueConstraint(err error) bool {
	return strings.Contains(strings.ToLower(err.Error()), "unique constraint failed")
}

func validateImportMetadata(metadata SBOMImportMetadata) error {
	for _, target := range []struct {
		label string
		value string
	}{
		{label: "SBOM format", value: metadata.Format},
		{label: "SBOM spec version", value: metadata.SpecVersion},
		{label: "SBOM document SHA-256", value: metadata.DocumentSHA256},
	} {
		if _, err := cleanIdentifier(target.label, target.value); err != nil {
			return err
		}
	}
	if len(metadata.DocumentSHA256) != 64 {
		return errors.New("SBOM document SHA-256 must contain 64 hexadecimal characters")
	}
	for _, character := range metadata.DocumentSHA256 {
		if !((character >= '0' && character <= '9') || (character >= 'a' && character <= 'f')) {
			return errors.New("SBOM document SHA-256 must contain lowercase hexadecimal characters")
		}
	}
	for _, target := range []struct {
		label string
		value string
	}{
		{label: "SBOM serial number", value: metadata.SerialNumber},
		{label: "SBOM source name", value: metadata.SourceName},
	} {
		if _, err := cleanImportText(target.label, target.value); err != nil {
			return err
		}
	}
	for _, target := range []struct {
		label string
		value int
	}{
		{label: "components discovered", value: metadata.Discovered},
		{label: "components skipped", value: metadata.Skipped},
		{label: "components duplicated", value: metadata.Duplicates},
	} {
		if target.value < 0 {
			return fmt.Errorf("%s cannot be negative", target.label)
		}
	}
	return nil
}

func formatTime(value time.Time) string {
	return value.Format(time.RFC3339)
}

func parseTime(value string) (time.Time, error) {
	parsed, err := time.Parse(time.RFC3339, value)
	if err != nil {
		return time.Time{}, fmt.Errorf("parse stored timestamp: %w", err)
	}
	return parsed, nil
}

func cleanIdentifier(label, value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("%s is required", label)
	}
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%s must be valid UTF-8", label)
	}
	if utf8.RuneCountInString(value) > maxIdentifierLength {
		return "", fmt.Errorf("%s exceeds %d characters", label, maxIdentifierLength)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%s cannot contain control characters", label)
	}
	return value, nil
}

func cleanImportText(label, value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%s must be valid UTF-8", label)
	}
	if utf8.RuneCountInString(value) > maxDescriptionLength {
		return "", fmt.Errorf("%s exceeds %d characters", label, maxDescriptionLength)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return "", fmt.Errorf("%s cannot contain control characters", label)
	}
	return value, nil
}

func cleanDescription(value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		return "", errors.New("product description must be valid UTF-8")
	}
	if utf8.RuneCountInString(value) > maxDescriptionLength {
		return "", fmt.Errorf("product description exceeds %d characters", maxDescriptionLength)
	}
	if strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t'
	}) >= 0 {
		return "", errors.New("product description contains an unsupported control character")
	}
	return value, nil
}
