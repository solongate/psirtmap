// Package store persists PSIRTMap's product inventory and local vulnerability
// intelligence in SQLite.
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/solongate/psirtmap/internal/kev"
	"github.com/solongate/psirtmap/internal/osv"
	_ "modernc.org/sqlite"
)

const schemaVersion = 7

const (
	AssessmentNeedsReview   = "needs-review"
	AssessmentInvestigating = "investigating"
	AssessmentAffected      = "affected"
	AssessmentNotAffected   = "not-affected"
	AssessmentFixed         = "fixed"
)

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
	// ErrSnapshotNotFound is returned when a package version has not been
	// synchronized into the local vulnerability snapshot.
	ErrSnapshotNotFound = errors.New("local vulnerability snapshot not found")
	// ErrAmbiguousFinding is returned when an assessment target matches more
	// than one component-level finding.
	ErrAmbiguousFinding = errors.New("finding reference is ambiguous")
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
	CreatedProduct bool   `json:"created_product,omitempty"`
	CreatedRelease bool   `json:"created_release"`
	Imported       int    `json:"imported"`
	AlreadyPresent int    `json:"already_present"`
}

// PackageVersion is one distinct package identity found in the inventory.
type PackageVersion struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
}

// PackageSnapshot contains the exact OSV query result for one package version.
type PackageSnapshot struct {
	Package         PackageVersion      `json:"package"`
	Vulnerabilities []osv.Vulnerability `json:"vulnerabilities"`
}

// VulnerabilitySync summarizes one successfully committed local snapshot.
type VulnerabilitySync struct {
	Source          string    `json:"source"`
	SynchronizedAt  time.Time `json:"synchronized_at"`
	Packages        int       `json:"packages"`
	Vulnerabilities int       `json:"vulnerabilities"`
}

// KEVSync summarizes one successfully committed CISA KEV catalog.
type KEVSync struct {
	Source         string    `json:"source"`
	CatalogVersion string    `json:"catalog_version"`
	DateReleased   time.Time `json:"date_released"`
	SynchronizedAt time.Time `json:"synchronized_at"`
	Entries        int       `json:"entries"`
}

// FindingMatch is one package-version vulnerability match produced by a
// trusted local snapshot scan.
type FindingMatch struct {
	Ecosystem        string
	Component        string
	ComponentVersion string
	VulnerabilityID  string
	Aliases          []string
	Summary          string
}

// Finding is a durable potential-impact record for one shipped release.
type Finding struct {
	FindingID         int64              `json:"finding_id"`
	Product           string             `json:"product"`
	Release           string             `json:"release"`
	Ecosystem         string             `json:"ecosystem"`
	Component         string             `json:"component"`
	ComponentVersion  string             `json:"component_version"`
	VulnerabilityID   string             `json:"id"`
	Aliases           []string           `json:"aliases"`
	Summary           string             `json:"summary,omitempty"`
	Status            string             `json:"status"`
	MatchStatus       string             `json:"match_status"`
	Active            bool               `json:"active"`
	FirstSeenAt       time.Time          `json:"first_seen_at"`
	LastSeenAt        time.Time          `json:"last_seen_at"`
	NoLongerMatchedAt *time.Time         `json:"no_longer_matched_at,omitempty"`
	KnownExploited    bool               `json:"known_exploited"`
	KEV               *kev.Vulnerability `json:"kev,omitempty"`
}

// FindingFilter limits a finding list to a release and optionally includes
// records that no longer match the current local vulnerability snapshot.
type FindingFilter struct {
	Product         string
	Release         string
	Status          string
	IncludeInactive bool
}

// AssessmentTarget identifies one component-level finding. Component fields
// may be omitted when product, release, and vulnerability identify exactly one
// finding.
type AssessmentTarget struct {
	Product          string
	Release          string
	VulnerabilityID  string
	Ecosystem        string
	Component        string
	ComponentVersion string
}

// AssessmentInput contains one human impact decision.
type AssessmentInput struct {
	Status   string
	Reason   string
	Reviewer string
	Evidence string
}

// Assessment is one append-only entry in a finding's human-review history.
type Assessment struct {
	AssessmentID     int64     `json:"assessment_id"`
	FindingID        int64     `json:"finding_id"`
	Product          string    `json:"product"`
	Release          string    `json:"release"`
	Ecosystem        string    `json:"ecosystem"`
	Component        string    `json:"component"`
	ComponentVersion string    `json:"component_version"`
	VulnerabilityID  string    `json:"id"`
	Status           string    `json:"status"`
	Reason           string    `json:"reason,omitempty"`
	Reviewer         string    `json:"reviewer"`
	Evidence         string    `json:"evidence,omitempty"`
	AssessedAt       time.Time `json:"assessed_at"`
}

// AssessmentFilter limits assessment history to a product release,
// vulnerability, and optional component identity.
type AssessmentFilter struct {
	Product          string
	Release          string
	VulnerabilityID  string
	Ecosystem        string
	Component        string
	ComponentVersion string
}

// FindingScanResult summarizes the lifecycle changes committed by a scan.
type FindingScanResult struct {
	Product         string    `json:"product"`
	Release         string    `json:"release"`
	ScannedAt       time.Time `json:"scanned_at"`
	Components      int       `json:"components"`
	Matched         int       `json:"matched"`
	New             int       `json:"new"`
	Existing        int       `json:"existing"`
	Reopened        int       `json:"reopened"`
	NoLongerMatched int       `json:"no_longer_matched"`
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

	if currentVersion < 3 {
		statements := []string{
			`CREATE TABLE vulnerability_syncs (
				id INTEGER PRIMARY KEY,
				source TEXT NOT NULL,
				synchronized_at TEXT NOT NULL,
				package_count INTEGER NOT NULL,
				vulnerability_count INTEGER NOT NULL
			)`,
			`CREATE TABLE package_snapshots (
				id INTEGER PRIMARY KEY,
				sync_id INTEGER NOT NULL REFERENCES vulnerability_syncs(id),
				ecosystem TEXT NOT NULL,
				name TEXT NOT NULL,
				version TEXT NOT NULL,
				UNIQUE(ecosystem, name, version)
			)`,
			`CREATE TABLE vulnerabilities (
				id INTEGER PRIMARY KEY,
				source TEXT NOT NULL,
				source_id TEXT NOT NULL,
				summary TEXT NOT NULL DEFAULT '',
				details TEXT NOT NULL DEFAULT '',
				published TEXT NOT NULL DEFAULT '',
				modified TEXT NOT NULL DEFAULT '',
				withdrawn TEXT NOT NULL DEFAULT '',
				aliases_json TEXT NOT NULL DEFAULT '[]',
				severity_json TEXT NOT NULL DEFAULT '[]',
				affected_json TEXT NOT NULL DEFAULT '[]',
				updated_at TEXT NOT NULL,
				UNIQUE(source, source_id)
			)`,
			`CREATE TABLE vulnerability_aliases (
				vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
				alias TEXT NOT NULL,
				PRIMARY KEY(vulnerability_id, alias)
			)`,
			`CREATE TABLE package_vulnerability_matches (
				package_snapshot_id INTEGER NOT NULL REFERENCES package_snapshots(id) ON DELETE CASCADE,
				vulnerability_id INTEGER NOT NULL REFERENCES vulnerabilities(id) ON DELETE CASCADE,
				PRIMARY KEY(package_snapshot_id, vulnerability_id)
			)`,
			`CREATE INDEX package_snapshots_sync_id_idx ON package_snapshots(sync_id)`,
			`CREATE INDEX vulnerability_aliases_alias_idx ON vulnerability_aliases(alias)`,
			`CREATE INDEX package_vulnerability_matches_vulnerability_idx ON package_vulnerability_matches(vulnerability_id)`,
			`PRAGMA user_version = 3`,
		}
		for _, statement := range statements {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply schema migration: %w", err)
			}
		}
	}

	if currentVersion < 4 {
		statements := []string{
			`CREATE TABLE finding_scans (
				id INTEGER PRIMARY KEY,
				release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
				data_source TEXT NOT NULL,
				synchronized_at TEXT NOT NULL DEFAULT '',
				scanned_at TEXT NOT NULL,
				component_count INTEGER NOT NULL,
				matched_count INTEGER NOT NULL,
				new_count INTEGER NOT NULL,
				existing_count INTEGER NOT NULL,
				reopened_count INTEGER NOT NULL,
				no_longer_matched_count INTEGER NOT NULL
			)`,
			`CREATE TABLE findings (
				id INTEGER PRIMARY KEY,
				release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE,
				ecosystem TEXT NOT NULL,
				component_name TEXT NOT NULL,
				component_version TEXT NOT NULL,
				vulnerability_id TEXT NOT NULL,
				aliases_json TEXT NOT NULL DEFAULT '[]',
				summary TEXT NOT NULL DEFAULT '',
				review_status TEXT NOT NULL DEFAULT 'needs-review',
				active INTEGER NOT NULL DEFAULT 1 CHECK(active IN (0, 1)),
				first_seen_at TEXT NOT NULL,
				last_seen_at TEXT NOT NULL,
				no_longer_matched_at TEXT NOT NULL DEFAULT '',
				last_scan_id INTEGER NOT NULL REFERENCES finding_scans(id),
				UNIQUE(release_id, ecosystem, component_name, component_version, vulnerability_id)
			)`,
			`CREATE INDEX finding_scans_release_id_idx ON finding_scans(release_id, scanned_at)`,
			`CREATE INDEX findings_release_active_idx ON findings(release_id, active)`,
			`CREATE INDEX findings_vulnerability_id_idx ON findings(vulnerability_id)`,
			`PRAGMA user_version = 4`,
		}
		for _, statement := range statements {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply schema migration: %w", err)
			}
		}
	}

	if currentVersion < 5 {
		statements := []string{
			`CREATE TABLE IF NOT EXISTS assessments (
				id INTEGER PRIMARY KEY,
				finding_id INTEGER NOT NULL REFERENCES findings(id) ON DELETE CASCADE,
				status TEXT NOT NULL CHECK(status IN ('investigating', 'affected', 'not-affected', 'fixed')),
				reason TEXT NOT NULL DEFAULT '',
				reviewer TEXT NOT NULL,
				evidence TEXT NOT NULL DEFAULT '',
				assessed_at TEXT NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS assessments_finding_time_idx ON assessments(finding_id, assessed_at, id)`,
			`PRAGMA user_version = 5`,
		}
		for _, statement := range statements {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply schema migration: %w", err)
			}
		}
	}

	if currentVersion < 6 {
		statements := []string{
			`CREATE TABLE IF NOT EXISTS kev_syncs (
				id INTEGER PRIMARY KEY,
				source TEXT NOT NULL,
				catalog_version TEXT NOT NULL,
				date_released TEXT NOT NULL,
				synchronized_at TEXT NOT NULL,
				entry_count INTEGER NOT NULL
			)`,
			`CREATE TABLE IF NOT EXISTS kev_entries (
				cve_id TEXT PRIMARY KEY COLLATE NOCASE,
				sync_id INTEGER NOT NULL REFERENCES kev_syncs(id) ON DELETE CASCADE,
				vendor_project TEXT NOT NULL,
				product TEXT NOT NULL,
				vulnerability_name TEXT NOT NULL,
				date_added TEXT NOT NULL,
				short_description TEXT NOT NULL,
				required_action TEXT NOT NULL,
				due_date TEXT NOT NULL,
				known_ransomware_campaign_use TEXT NOT NULL DEFAULT '',
				forensic_triage TEXT NOT NULL DEFAULT '',
				notes TEXT NOT NULL DEFAULT '',
				cwes_json TEXT NOT NULL DEFAULT '[]'
			)`,
			`CREATE INDEX IF NOT EXISTS kev_entries_sync_id_idx ON kev_entries(sync_id)`,
			`PRAGMA user_version = 6`,
		}
		for _, statement := range statements {
			if _, err := transaction.ExecContext(ctx, statement); err != nil {
				return fmt.Errorf("apply schema migration: %w", err)
			}
		}
	}

	if currentVersion < 7 {
		statements := []string{
			`CREATE TABLE IF NOT EXISTS feed_imports (
				id INTEGER PRIMARY KEY,
				format_version INTEGER NOT NULL,
				bundle_created_at TEXT NOT NULL,
				imported_at TEXT NOT NULL,
				source_name TEXT NOT NULL,
				manifest_sha256 TEXT NOT NULL,
				osv_synchronized_at TEXT NOT NULL,
				kev_synchronized_at TEXT NOT NULL,
				package_count INTEGER NOT NULL,
				vulnerability_count INTEGER NOT NULL,
				kev_entry_count INTEGER NOT NULL
			)`,
			`CREATE INDEX IF NOT EXISTS feed_imports_imported_at_idx ON feed_imports(imported_at)`,
			`PRAGMA user_version = 7`,
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
	return d.importReleaseComponents(ctx, productName, "", releaseVersion, components, metadata, false)
}

// ImportProductReleaseComponents creates a missing product and release when
// necessary, then merges a validated SBOM component set into the release. The
// complete onboarding import is committed atomically.
func (d *DB) ImportProductReleaseComponents(
	ctx context.Context,
	productName string,
	productDescription string,
	releaseVersion string,
	components []ComponentInput,
	metadata SBOMImportMetadata,
) (ComponentImportResult, error) {
	return d.importReleaseComponents(
		ctx, productName, productDescription, releaseVersion, components, metadata, true,
	)
}

func (d *DB) importReleaseComponents(
	ctx context.Context,
	productName string,
	productDescription string,
	releaseVersion string,
	components []ComponentInput,
	metadata SBOMImportMetadata,
	createMissingProduct bool,
) (ComponentImportResult, error) {
	var err error
	productName, err = cleanIdentifier("product name", productName)
	if err != nil {
		return ComponentImportResult{}, err
	}
	productDescription, err = cleanDescription(productDescription)
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
	createdProduct := false
	err = transaction.QueryRowContext(ctx,
		"SELECT id, name FROM products WHERE name = ? COLLATE NOCASE", productName,
	).Scan(&productID, &canonicalProduct)
	if errors.Is(err, sql.ErrNoRows) {
		if !createMissingProduct {
			return ComponentImportResult{}, fmt.Errorf("product %q: %w", productName, ErrNotFound)
		}
		createdAt := time.Now().UTC().Truncate(time.Second)
		insert, insertErr := transaction.ExecContext(ctx,
			"INSERT INTO products(name, description, created_at) VALUES (?, ?, ?)",
			productName, productDescription, formatTime(createdAt),
		)
		if insertErr != nil {
			return ComponentImportResult{}, fmt.Errorf("create product for SBOM import: %w", insertErr)
		}
		productID, err = insert.LastInsertId()
		if err != nil {
			return ComponentImportResult{}, fmt.Errorf("read imported product ID: %w", err)
		}
		canonicalProduct = productName
		createdProduct = true
		err = nil
	}
	if err != nil {
		return ComponentImportResult{}, fmt.Errorf("find product for SBOM import: %w", err)
	}

	result := ComponentImportResult{
		Product: canonicalProduct, ReleaseVersion: releaseVersion,
		CreatedProduct: createdProduct,
	}
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

// ListPackageVersions returns the unique package versions present anywhere in
// the shipped-product inventory.
func (d *DB) ListPackageVersions(ctx context.Context) ([]PackageVersion, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT DISTINCT ecosystem, name, version
		FROM components ORDER BY ecosystem, name, version`)
	if err != nil {
		return nil, fmt.Errorf("list package versions: %w", err)
	}
	defer rows.Close()

	packages := make([]PackageVersion, 0)
	for rows.Next() {
		var pkg PackageVersion
		if err := rows.Scan(&pkg.Ecosystem, &pkg.Name, &pkg.Version); err != nil {
			return nil, fmt.Errorf("read package version: %w", err)
		}
		packages = append(packages, pkg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list package versions: %w", err)
	}
	return packages, nil
}

// SaveOSVSnapshot atomically replaces the active package-version snapshot.
// Callers must fetch every package successfully before invoking it, so a
// network failure can never leave a partially updated local feed.
func (d *DB) SaveOSVSnapshot(ctx context.Context, snapshots []PackageSnapshot) (VulnerabilitySync, error) {
	result := VulnerabilitySync{
		Source:         "OSV",
		SynchronizedAt: time.Now().UTC().Truncate(time.Second),
		Packages:       len(snapshots),
	}
	seenPackages := make(map[PackageVersion]struct{}, len(snapshots))
	seenVulnerabilities := make(map[string]struct{})
	for _, snapshot := range snapshots {
		pkg := snapshot.Package
		if _, exists := seenPackages[pkg]; exists {
			return VulnerabilitySync{}, fmt.Errorf("duplicate package snapshot %s:%s@%s", pkg.Ecosystem, pkg.Name, pkg.Version)
		}
		seenPackages[pkg] = struct{}{}
		for _, vulnerability := range snapshot.Vulnerabilities {
			if strings.TrimSpace(vulnerability.ID) == "" {
				return VulnerabilitySync{}, errors.New("OSV vulnerability ID is required")
			}
			seenVulnerabilities[vulnerability.ID] = struct{}{}
		}
	}
	result.Vulnerabilities = len(seenVulnerabilities)

	transaction, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return VulnerabilitySync{}, fmt.Errorf("begin OSV snapshot: %w", err)
	}
	defer transaction.Rollback()

	insert, err := transaction.ExecContext(ctx, `INSERT INTO vulnerability_syncs(
		source, synchronized_at, package_count, vulnerability_count
	) VALUES (?, ?, ?, ?)`, result.Source, formatTime(result.SynchronizedAt), result.Packages, result.Vulnerabilities)
	if err != nil {
		return VulnerabilitySync{}, fmt.Errorf("record OSV sync: %w", err)
	}
	syncID, err := insert.LastInsertId()
	if err != nil {
		return VulnerabilitySync{}, fmt.Errorf("read OSV sync ID: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM package_snapshots"); err != nil {
		return VulnerabilitySync{}, fmt.Errorf("replace package snapshots: %w", err)
	}

	for _, snapshot := range snapshots {
		packageInsert, insertErr := transaction.ExecContext(ctx, `INSERT INTO package_snapshots(
			sync_id, ecosystem, name, version
		) VALUES (?, ?, ?, ?)`, syncID, snapshot.Package.Ecosystem, snapshot.Package.Name, snapshot.Package.Version)
		if insertErr != nil {
			return VulnerabilitySync{}, fmt.Errorf("store package snapshot %s@%s: %w", snapshot.Package.Name, snapshot.Package.Version, insertErr)
		}
		packageID, insertErr := packageInsert.LastInsertId()
		if insertErr != nil {
			return VulnerabilitySync{}, fmt.Errorf("read package snapshot ID: %w", insertErr)
		}

		for _, vulnerability := range snapshot.Vulnerabilities {
			aliasesJSON, marshalErr := json.Marshal(nonNilStrings(vulnerability.Aliases))
			if marshalErr != nil {
				return VulnerabilitySync{}, fmt.Errorf("encode aliases for %s: %w", vulnerability.ID, marshalErr)
			}
			severityJSON, marshalErr := json.Marshal(nonNilSeverities(vulnerability.Severity))
			if marshalErr != nil {
				return VulnerabilitySync{}, fmt.Errorf("encode severity for %s: %w", vulnerability.ID, marshalErr)
			}
			affectedJSON, marshalErr := json.Marshal(nonNilAffected(vulnerability.Affected))
			if marshalErr != nil {
				return VulnerabilitySync{}, fmt.Errorf("encode affected data for %s: %w", vulnerability.ID, marshalErr)
			}
			_, insertErr = transaction.ExecContext(ctx, `INSERT INTO vulnerabilities(
				source, source_id, summary, details, published, modified, withdrawn,
				aliases_json, severity_json, affected_json, updated_at
			) VALUES ('OSV', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(source, source_id) DO UPDATE SET
				summary = excluded.summary,
				details = excluded.details,
				published = excluded.published,
				modified = excluded.modified,
				withdrawn = excluded.withdrawn,
				aliases_json = excluded.aliases_json,
				severity_json = excluded.severity_json,
				affected_json = excluded.affected_json,
				updated_at = excluded.updated_at`,
				vulnerability.ID, vulnerability.Summary, vulnerability.Details,
				vulnerability.Published, vulnerability.Modified, vulnerability.Withdrawn,
				string(aliasesJSON), string(severityJSON), string(affectedJSON), formatTime(result.SynchronizedAt))
			if insertErr != nil {
				return VulnerabilitySync{}, fmt.Errorf("store vulnerability %s: %w", vulnerability.ID, insertErr)
			}

			var vulnerabilityID int64
			if err := transaction.QueryRowContext(ctx,
				"SELECT id FROM vulnerabilities WHERE source = 'OSV' AND source_id = ?", vulnerability.ID,
			).Scan(&vulnerabilityID); err != nil {
				return VulnerabilitySync{}, fmt.Errorf("read vulnerability %s: %w", vulnerability.ID, err)
			}
			if _, err := transaction.ExecContext(ctx, "DELETE FROM vulnerability_aliases WHERE vulnerability_id = ?", vulnerabilityID); err != nil {
				return VulnerabilitySync{}, fmt.Errorf("replace aliases for %s: %w", vulnerability.ID, err)
			}
			for _, alias := range vulnerability.Aliases {
				if _, err := transaction.ExecContext(ctx,
					"INSERT OR IGNORE INTO vulnerability_aliases(vulnerability_id, alias) VALUES (?, ?)", vulnerabilityID, alias,
				); err != nil {
					return VulnerabilitySync{}, fmt.Errorf("store alias for %s: %w", vulnerability.ID, err)
				}
			}
			if _, err := transaction.ExecContext(ctx, `INSERT OR IGNORE INTO package_vulnerability_matches(
				package_snapshot_id, vulnerability_id
			) VALUES (?, ?)`, packageID, vulnerabilityID); err != nil {
				return VulnerabilitySync{}, fmt.Errorf("store match for %s: %w", vulnerability.ID, err)
			}
		}
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM vulnerabilities
		WHERE id NOT IN (SELECT vulnerability_id FROM package_vulnerability_matches)`); err != nil {
		return VulnerabilitySync{}, fmt.Errorf("remove stale vulnerabilities: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return VulnerabilitySync{}, fmt.Errorf("commit OSV snapshot: %w", err)
	}
	return result, nil
}

// LookupOSVSnapshot returns the cached exact-match result and its sync time.
func (d *DB) LookupOSVSnapshot(ctx context.Context, pkg PackageVersion) ([]osv.Vulnerability, time.Time, error) {
	var packageID int64
	var synchronizedAt string
	err := d.db.QueryRowContext(ctx, `SELECT ps.id, vs.synchronized_at
		FROM package_snapshots ps
		JOIN vulnerability_syncs vs ON vs.id = ps.sync_id
		WHERE ps.ecosystem = ? AND ps.name = ? AND ps.version = ?`, pkg.Ecosystem, pkg.Name, pkg.Version,
	).Scan(&packageID, &synchronizedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, time.Time{}, fmt.Errorf("%s:%s@%s: %w", pkg.Ecosystem, pkg.Name, pkg.Version, ErrSnapshotNotFound)
	}
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("find local OSV snapshot: %w", err)
	}
	syncedAt, err := parseTime(synchronizedAt)
	if err != nil {
		return nil, time.Time{}, err
	}

	rows, err := d.db.QueryContext(ctx, `SELECT
		v.source_id, v.summary, v.details, v.published, v.modified, v.withdrawn,
		v.aliases_json, v.severity_json, v.affected_json
		FROM package_vulnerability_matches pvm
		JOIN vulnerabilities v ON v.id = pvm.vulnerability_id
		WHERE pvm.package_snapshot_id = ?
		ORDER BY v.source_id`, packageID)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("read local OSV matches: %w", err)
	}
	defer rows.Close()
	vulnerabilities := make([]osv.Vulnerability, 0)
	for rows.Next() {
		var vulnerability osv.Vulnerability
		var aliasesJSON, severityJSON, affectedJSON string
		if err := rows.Scan(
			&vulnerability.ID, &vulnerability.Summary, &vulnerability.Details,
			&vulnerability.Published, &vulnerability.Modified, &vulnerability.Withdrawn,
			&aliasesJSON, &severityJSON, &affectedJSON,
		); err != nil {
			return nil, time.Time{}, fmt.Errorf("read local OSV vulnerability: %w", err)
		}
		if err := json.Unmarshal([]byte(aliasesJSON), &vulnerability.Aliases); err != nil {
			return nil, time.Time{}, fmt.Errorf("decode aliases for %s: %w", vulnerability.ID, err)
		}
		if err := json.Unmarshal([]byte(severityJSON), &vulnerability.Severity); err != nil {
			return nil, time.Time{}, fmt.Errorf("decode severity for %s: %w", vulnerability.ID, err)
		}
		if err := json.Unmarshal([]byte(affectedJSON), &vulnerability.Affected); err != nil {
			return nil, time.Time{}, fmt.Errorf("decode affected data for %s: %w", vulnerability.ID, err)
		}
		vulnerabilities = append(vulnerabilities, vulnerability)
	}
	if err := rows.Err(); err != nil {
		return nil, time.Time{}, fmt.Errorf("read local OSV matches: %w", err)
	}
	return vulnerabilities, syncedAt, nil
}

// LatestVulnerabilitySync returns the most recently committed snapshot.
func (d *DB) LatestVulnerabilitySync(ctx context.Context) (VulnerabilitySync, error) {
	var result VulnerabilitySync
	var synchronizedAt string
	err := d.db.QueryRowContext(ctx, `SELECT source, synchronized_at, package_count, vulnerability_count
		FROM vulnerability_syncs ORDER BY id DESC LIMIT 1`).Scan(
		&result.Source, &synchronizedAt, &result.Packages, &result.Vulnerabilities,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return VulnerabilitySync{}, ErrSnapshotNotFound
	}
	if err != nil {
		return VulnerabilitySync{}, fmt.Errorf("read latest vulnerability sync: %w", err)
	}
	result.SynchronizedAt, err = parseTime(synchronizedAt)
	if err != nil {
		return VulnerabilitySync{}, err
	}
	return result, nil
}

// SaveKEVCatalog atomically replaces the active CISA KEV catalog. Validation
// completes before the transaction begins, so malformed input cannot disturb
// the last known-good local snapshot.
func (d *DB) SaveKEVCatalog(ctx context.Context, catalog kev.Catalog) (KEVSync, error) {
	if err := kev.ValidateCatalog(&catalog); err != nil {
		return KEVSync{}, err
	}
	dateReleased, err := time.Parse(time.RFC3339, catalog.DateReleased)
	if err != nil {
		return KEVSync{}, fmt.Errorf("parse CISA KEV release time: %w", err)
	}
	source := strings.TrimSpace(catalog.SourceURL)
	if source == "" {
		source = "CISA KEV"
	}
	result := KEVSync{
		Source: source, CatalogVersion: catalog.CatalogVersion,
		DateReleased:   dateReleased.UTC(),
		SynchronizedAt: time.Now().UTC().Truncate(time.Second),
		Entries:        len(catalog.Vulnerabilities),
	}

	transaction, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return KEVSync{}, fmt.Errorf("begin CISA KEV snapshot: %w", err)
	}
	defer transaction.Rollback()
	insert, err := transaction.ExecContext(ctx, `INSERT INTO kev_syncs(
		source, catalog_version, date_released, synchronized_at, entry_count
	) VALUES (?, ?, ?, ?, ?)`, result.Source, result.CatalogVersion,
		formatTime(result.DateReleased), formatTime(result.SynchronizedAt), result.Entries)
	if err != nil {
		return KEVSync{}, fmt.Errorf("record CISA KEV sync: %w", err)
	}
	syncID, err := insert.LastInsertId()
	if err != nil {
		return KEVSync{}, fmt.Errorf("read CISA KEV sync ID: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM kev_syncs WHERE id <> ?", syncID); err != nil {
		return KEVSync{}, fmt.Errorf("replace CISA KEV snapshot: %w", err)
	}
	for _, entry := range catalog.Vulnerabilities {
		cwesJSON, marshalErr := json.Marshal(nonNilStrings(entry.CWEs))
		if marshalErr != nil {
			return KEVSync{}, fmt.Errorf("encode CWEs for %s: %w", entry.CVEID, marshalErr)
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO kev_entries(
			cve_id, sync_id, vendor_project, product, vulnerability_name,
			date_added, short_description, required_action, due_date,
			known_ransomware_campaign_use, forensic_triage, notes, cwes_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.CVEID, syncID, entry.VendorProject, entry.Product,
			entry.VulnerabilityName, entry.DateAdded, entry.ShortDescription,
			entry.RequiredAction, entry.DueDate, entry.KnownRansomwareCampaignUse,
			entry.ForensicTriage, entry.Notes, string(cwesJSON),
		); err != nil {
			return KEVSync{}, fmt.Errorf("store CISA KEV entry %s: %w", entry.CVEID, err)
		}
	}
	if err := transaction.Commit(); err != nil {
		return KEVSync{}, fmt.Errorf("commit CISA KEV snapshot: %w", err)
	}
	return result, nil
}

// LatestKEVSync returns freshness metadata for the active CISA KEV snapshot.
func (d *DB) LatestKEVSync(ctx context.Context) (KEVSync, error) {
	var result KEVSync
	var dateReleased, synchronizedAt string
	err := d.db.QueryRowContext(ctx, `SELECT source, catalog_version, date_released,
		synchronized_at, entry_count FROM kev_syncs ORDER BY id DESC LIMIT 1`).Scan(
		&result.Source, &result.CatalogVersion, &dateReleased,
		&synchronizedAt, &result.Entries,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return KEVSync{}, ErrSnapshotNotFound
	}
	if err != nil {
		return KEVSync{}, fmt.Errorf("read latest CISA KEV sync: %w", err)
	}
	result.DateReleased, err = parseTime(dateReleased)
	if err != nil {
		return KEVSync{}, err
	}
	result.SynchronizedAt, err = parseTime(synchronizedAt)
	if err != nil {
		return KEVSync{}, err
	}
	return result, nil
}

// ListKEVEntries returns the active catalog in CVE order.
func (d *DB) ListKEVEntries(ctx context.Context) ([]kev.Vulnerability, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT cve_id, vendor_project, product,
		vulnerability_name, date_added, short_description, required_action,
		due_date, known_ransomware_campaign_use, forensic_triage, notes, cwes_json
		FROM kev_entries ORDER BY cve_id`)
	if err != nil {
		return nil, fmt.Errorf("list CISA KEV entries: %w", err)
	}
	defer rows.Close()
	entries := make([]kev.Vulnerability, 0)
	for rows.Next() {
		var entry kev.Vulnerability
		var cwesJSON string
		if err := rows.Scan(
			&entry.CVEID, &entry.VendorProject, &entry.Product,
			&entry.VulnerabilityName, &entry.DateAdded, &entry.ShortDescription,
			&entry.RequiredAction, &entry.DueDate,
			&entry.KnownRansomwareCampaignUse, &entry.ForensicTriage,
			&entry.Notes, &cwesJSON,
		); err != nil {
			return nil, fmt.Errorf("read CISA KEV entry: %w", err)
		}
		if err := json.Unmarshal([]byte(cwesJSON), &entry.CWEs); err != nil {
			return nil, fmt.Errorf("decode CWEs for %s: %w", entry.CVEID, err)
		}
		entry.CWEs = nonNilStrings(entry.CWEs)
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list CISA KEV entries: %w", err)
	}
	return entries, nil
}

// ReconcileFindings atomically records a local scan and updates the durable
// finding lifecycle for one release. Missing matches are retained as inactive
// evidence instead of being deleted.
func (d *DB) ReconcileFindings(
	ctx context.Context,
	productName string,
	releaseVersion string,
	matches []FindingMatch,
	dataSource string,
	synchronizedAt time.Time,
	componentCount int,
) (FindingScanResult, error) {
	var err error
	productName, err = cleanIdentifier("product name", productName)
	if err != nil {
		return FindingScanResult{}, err
	}
	releaseVersion, err = cleanIdentifier("release version", releaseVersion)
	if err != nil {
		return FindingScanResult{}, err
	}
	dataSource, err = cleanIdentifier("finding data source", dataSource)
	if err != nil {
		return FindingScanResult{}, err
	}
	if componentCount < 0 {
		return FindingScanResult{}, errors.New("component count cannot be negative")
	}

	type findingKey struct {
		ecosystem        string
		component        string
		componentVersion string
		vulnerabilityID  string
	}
	cleaned := make(map[findingKey]FindingMatch, len(matches))
	for index, match := range matches {
		for _, target := range []struct {
			label string
			value *string
		}{
			{label: "finding ecosystem", value: &match.Ecosystem},
			{label: "finding component", value: &match.Component},
			{label: "finding component version", value: &match.ComponentVersion},
			{label: "finding vulnerability ID", value: &match.VulnerabilityID},
		} {
			*target.value, err = cleanIdentifier(target.label, *target.value)
			if err != nil {
				return FindingScanResult{}, fmt.Errorf("match %d: %w", index+1, err)
			}
		}
		match.Summary, err = cleanDescription(match.Summary)
		if err != nil {
			return FindingScanResult{}, fmt.Errorf("match %d summary: %w", index+1, err)
		}
		aliases := make([]string, 0, len(match.Aliases))
		seenAliases := make(map[string]struct{}, len(match.Aliases))
		for _, alias := range match.Aliases {
			alias, err = cleanIdentifier("finding alias", alias)
			if err != nil {
				return FindingScanResult{}, fmt.Errorf("match %d: %w", index+1, err)
			}
			if _, exists := seenAliases[alias]; !exists {
				seenAliases[alias] = struct{}{}
				aliases = append(aliases, alias)
			}
		}
		match.Aliases = aliases
		key := findingKey{match.Ecosystem, match.Component, match.ComponentVersion, match.VulnerabilityID}
		cleaned[key] = match
	}

	transaction, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return FindingScanResult{}, fmt.Errorf("begin finding reconciliation: %w", err)
	}
	defer transaction.Rollback()

	var releaseID int64
	var canonicalProduct, canonicalRelease string
	err = transaction.QueryRowContext(ctx, `SELECT r.id, p.name, r.version
		FROM releases r JOIN products p ON p.id = r.product_id
		WHERE p.name = ? COLLATE NOCASE AND r.version = ?`, productName, releaseVersion,
	).Scan(&releaseID, &canonicalProduct, &canonicalRelease)
	if errors.Is(err, sql.ErrNoRows) {
		return FindingScanResult{}, fmt.Errorf("release %s@%s: %w", productName, releaseVersion, ErrNotFound)
	}
	if err != nil {
		return FindingScanResult{}, fmt.Errorf("find release for finding reconciliation: %w", err)
	}

	scannedAt := time.Now().UTC().Truncate(time.Second)
	synchronizedAtText := ""
	if !synchronizedAt.IsZero() {
		synchronizedAtText = formatTime(synchronizedAt.UTC().Truncate(time.Second))
	}
	scanInsert, err := transaction.ExecContext(ctx, `INSERT INTO finding_scans(
		release_id, data_source, synchronized_at, scanned_at, component_count,
		matched_count, new_count, existing_count, reopened_count, no_longer_matched_count
	) VALUES (?, ?, ?, ?, ?, 0, 0, 0, 0, 0)`,
		releaseID, dataSource, synchronizedAtText, formatTime(scannedAt), componentCount,
	)
	if err != nil {
		return FindingScanResult{}, fmt.Errorf("record finding scan: %w", err)
	}
	scanID, err := scanInsert.LastInsertId()
	if err != nil {
		return FindingScanResult{}, fmt.Errorf("read finding scan ID: %w", err)
	}

	type storedFinding struct {
		id     int64
		active bool
	}
	existing := make(map[findingKey]storedFinding)
	rows, err := transaction.QueryContext(ctx, `SELECT id, ecosystem, component_name,
		component_version, vulnerability_id, active FROM findings WHERE release_id = ?`, releaseID)
	if err != nil {
		return FindingScanResult{}, fmt.Errorf("read existing findings: %w", err)
	}
	for rows.Next() {
		var key findingKey
		var stored storedFinding
		var active int
		if err := rows.Scan(
			&stored.id, &key.ecosystem, &key.component, &key.componentVersion,
			&key.vulnerabilityID, &active,
		); err != nil {
			rows.Close()
			return FindingScanResult{}, fmt.Errorf("read existing finding: %w", err)
		}
		stored.active = active == 1
		existing[key] = stored
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return FindingScanResult{}, fmt.Errorf("read existing findings: %w", err)
	}
	if err := rows.Close(); err != nil {
		return FindingScanResult{}, fmt.Errorf("close existing findings: %w", err)
	}

	result := FindingScanResult{
		Product: canonicalProduct, Release: canonicalRelease, ScannedAt: scannedAt,
		Components: componentCount, Matched: len(cleaned),
	}
	for key, match := range cleaned {
		aliasesJSON, marshalErr := json.Marshal(nonNilStrings(match.Aliases))
		if marshalErr != nil {
			return FindingScanResult{}, fmt.Errorf("encode finding aliases for %s: %w", match.VulnerabilityID, marshalErr)
		}
		stored, exists := existing[key]
		if !exists {
			_, err = transaction.ExecContext(ctx, `INSERT INTO findings(
				release_id, ecosystem, component_name, component_version, vulnerability_id,
				aliases_json, summary, active, first_seen_at, last_seen_at,
				no_longer_matched_at, last_scan_id
			) VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, '', ?)`,
				releaseID, match.Ecosystem, match.Component, match.ComponentVersion,
				match.VulnerabilityID, string(aliasesJSON), match.Summary,
				formatTime(scannedAt), formatTime(scannedAt), scanID,
			)
			if err != nil {
				return FindingScanResult{}, fmt.Errorf("create finding %s: %w", match.VulnerabilityID, err)
			}
			result.New++
			continue
		}

		_, err = transaction.ExecContext(ctx, `UPDATE findings SET
			aliases_json = ?, summary = ?, active = 1, last_seen_at = ?,
			no_longer_matched_at = '', last_scan_id = ? WHERE id = ?`,
			string(aliasesJSON), match.Summary, formatTime(scannedAt), scanID, stored.id,
		)
		if err != nil {
			return FindingScanResult{}, fmt.Errorf("refresh finding %s: %w", match.VulnerabilityID, err)
		}
		if stored.active {
			result.Existing++
		} else {
			result.Reopened++
		}
	}

	for key, stored := range existing {
		if !stored.active {
			continue
		}
		if _, stillMatched := cleaned[key]; stillMatched {
			continue
		}
		_, err = transaction.ExecContext(ctx, `UPDATE findings SET
			active = 0, no_longer_matched_at = ?, last_scan_id = ? WHERE id = ?`,
			formatTime(scannedAt), scanID, stored.id,
		)
		if err != nil {
			return FindingScanResult{}, fmt.Errorf("close finding %s: %w", key.vulnerabilityID, err)
		}
		result.NoLongerMatched++
	}

	_, err = transaction.ExecContext(ctx, `UPDATE finding_scans SET
		matched_count = ?, new_count = ?, existing_count = ?, reopened_count = ?,
		no_longer_matched_count = ? WHERE id = ?`, result.Matched, result.New,
		result.Existing, result.Reopened, result.NoLongerMatched, scanID)
	if err != nil {
		return FindingScanResult{}, fmt.Errorf("finalize finding scan: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return FindingScanResult{}, fmt.Errorf("commit finding reconciliation: %w", err)
	}
	return result, nil
}

// ListFindings returns durable findings ordered by shipped release and
// vulnerability identity. Inactive records are excluded by default.
func (d *DB) ListFindings(ctx context.Context, filter FindingFilter) ([]Finding, error) {
	filter.Product = strings.TrimSpace(filter.Product)
	filter.Release = strings.TrimSpace(filter.Release)
	filter.Status = strings.TrimSpace(filter.Status)
	if filter.Release != "" && filter.Product == "" {
		return nil, errors.New("finding release filter requires a product")
	}
	var err error
	if filter.Product != "" {
		filter.Product, err = cleanIdentifier("product name", filter.Product)
		if err != nil {
			return nil, err
		}
	}
	if filter.Release != "" {
		filter.Release, err = cleanIdentifier("release version", filter.Release)
		if err != nil {
			return nil, err
		}
	}
	if filter.Status != "" {
		filter.Status, err = cleanReviewStatus(filter.Status, true)
		if err != nil {
			return nil, err
		}
	}

	query := `SELECT f.id, p.name, r.version, f.ecosystem, f.component_name,
		f.component_version, f.vulnerability_id, f.aliases_json, f.summary,
		f.review_status, f.active, f.first_seen_at, f.last_seen_at,
		f.no_longer_matched_at
		FROM findings f
		JOIN releases r ON r.id = f.release_id
		JOIN products p ON p.id = r.product_id WHERE 1 = 1`
	args := make([]any, 0, 2)
	if filter.Product != "" {
		query += " AND p.name = ? COLLATE NOCASE"
		args = append(args, filter.Product)
	}
	if filter.Release != "" {
		query += " AND r.version = ?"
		args = append(args, filter.Release)
	}
	if !filter.IncludeInactive {
		query += " AND f.active = 1"
	}
	if filter.Status != "" {
		query += " AND f.review_status = ?"
		args = append(args, filter.Status)
	}
	query += ` ORDER BY p.name COLLATE NOCASE, r.version, f.vulnerability_id,
		f.ecosystem, f.component_name, f.component_version`

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	defer rows.Close()
	findings := make([]Finding, 0)
	for rows.Next() {
		var finding Finding
		var aliasesJSON, reviewStatus, firstSeenAt, lastSeenAt, noLongerMatchedAt string
		var active int
		if err := rows.Scan(
			&finding.FindingID, &finding.Product, &finding.Release, &finding.Ecosystem, &finding.Component,
			&finding.ComponentVersion, &finding.VulnerabilityID, &aliasesJSON,
			&finding.Summary, &reviewStatus, &active, &firstSeenAt, &lastSeenAt,
			&noLongerMatchedAt,
		); err != nil {
			return nil, fmt.Errorf("read finding: %w", err)
		}
		if err := json.Unmarshal([]byte(aliasesJSON), &finding.Aliases); err != nil {
			return nil, fmt.Errorf("decode finding aliases for %s: %w", finding.VulnerabilityID, err)
		}
		finding.Aliases = nonNilStrings(finding.Aliases)
		finding.Active = active == 1
		finding.Status = reviewStatus
		finding.MatchStatus = "matched"
		if !finding.Active {
			finding.MatchStatus = "no-longer-matched"
		}
		finding.FirstSeenAt, err = parseTime(firstSeenAt)
		if err != nil {
			return nil, err
		}
		finding.LastSeenAt, err = parseTime(lastSeenAt)
		if err != nil {
			return nil, err
		}
		if noLongerMatchedAt != "" {
			value, parseErr := parseTime(noLongerMatchedAt)
			if parseErr != nil {
				return nil, parseErr
			}
			finding.NoLongerMatchedAt = &value
		}
		findings = append(findings, finding)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list findings: %w", err)
	}
	if err := rows.Close(); err != nil {
		return nil, fmt.Errorf("close finding list: %w", err)
	}
	entries, err := d.ListKEVEntries(ctx)
	if err != nil {
		return nil, err
	}
	enrichFindingsWithKEV(findings, entries)
	return findings, nil
}

func enrichFindingsWithKEV(findings []Finding, entries []kev.Vulnerability) {
	byCVE := make(map[string]kev.Vulnerability, len(entries))
	for _, entry := range entries {
		byCVE[strings.ToUpper(entry.CVEID)] = entry
	}
	for index := range findings {
		identifiers := append([]string{findings[index].VulnerabilityID}, findings[index].Aliases...)
		for _, identifier := range identifiers {
			entry, exists := byCVE[strings.ToUpper(strings.TrimSpace(identifier))]
			if !exists {
				continue
			}
			findings[index].KnownExploited = true
			entryCopy := entry
			findings[index].KEV = &entryCopy
			break
		}
	}
}

// CreateAssessment appends one human-review decision and updates the
// finding's current review status in the same transaction.
func (d *DB) CreateAssessment(
	ctx context.Context,
	target AssessmentTarget,
	input AssessmentInput,
) (Assessment, error) {
	var err error
	target, err = cleanAssessmentTarget(target)
	if err != nil {
		return Assessment{}, err
	}
	input.Status, err = cleanReviewStatus(input.Status, false)
	if err != nil {
		return Assessment{}, err
	}
	input.Reviewer, err = cleanIdentifier("assessment reviewer", input.Reviewer)
	if err != nil {
		return Assessment{}, err
	}
	input.Reason, err = cleanNarrative("assessment reason", input.Reason)
	if err != nil {
		return Assessment{}, err
	}
	input.Evidence, err = cleanNarrative("assessment evidence", input.Evidence)
	if err != nil {
		return Assessment{}, err
	}
	if input.Status != AssessmentInvestigating && input.Reason == "" {
		return Assessment{}, fmt.Errorf("assessment reason is required for status %q", input.Status)
	}

	transaction, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return Assessment{}, fmt.Errorf("begin assessment: %w", err)
	}
	defer transaction.Rollback()

	query := `SELECT f.id, p.name, r.version, f.ecosystem, f.component_name,
		f.component_version, f.vulnerability_id, f.aliases_json
		FROM findings f
		JOIN releases r ON r.id = f.release_id
		JOIN products p ON p.id = r.product_id
		WHERE p.name = ? COLLATE NOCASE AND r.version = ?`
	args := []any{target.Product, target.Release}
	if target.Component != "" {
		query += " AND f.ecosystem = ? AND f.component_name = ? AND f.component_version = ?"
		args = append(args, target.Ecosystem, target.Component, target.ComponentVersion)
	}
	query += " ORDER BY f.ecosystem, f.component_name, f.component_version"

	rows, err := transaction.QueryContext(ctx, query, args...)
	if err != nil {
		return Assessment{}, fmt.Errorf("find assessment target: %w", err)
	}
	matches := make([]Assessment, 0, 2)
	for rows.Next() {
		var assessment Assessment
		var aliasesJSON string
		if err := rows.Scan(
			&assessment.FindingID, &assessment.Product, &assessment.Release,
			&assessment.Ecosystem, &assessment.Component, &assessment.ComponentVersion,
			&assessment.VulnerabilityID, &aliasesJSON,
		); err != nil {
			rows.Close()
			return Assessment{}, fmt.Errorf("read assessment target: %w", err)
		}
		matched, matchErr := vulnerabilityIdentifierMatches(
			assessment.VulnerabilityID, aliasesJSON, target.VulnerabilityID,
		)
		if matchErr != nil {
			rows.Close()
			return Assessment{}, matchErr
		}
		if !matched {
			continue
		}
		matches = append(matches, assessment)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return Assessment{}, fmt.Errorf("read assessment target: %w", err)
	}
	if err := rows.Close(); err != nil {
		return Assessment{}, fmt.Errorf("close assessment target: %w", err)
	}
	if len(matches) == 0 {
		return Assessment{}, fmt.Errorf("finding %s in %s@%s: %w",
			target.VulnerabilityID, target.Product, target.Release, ErrNotFound)
	}
	if len(matches) > 1 {
		return Assessment{}, fmt.Errorf(
			"finding %s in %s@%s matches multiple components; specify a component: %w",
			target.VulnerabilityID, target.Product, target.Release, ErrAmbiguousFinding,
		)
	}

	assessment := matches[0]
	assessment.Status = input.Status
	assessment.Reason = input.Reason
	assessment.Reviewer = input.Reviewer
	assessment.Evidence = input.Evidence
	assessment.AssessedAt = time.Now().UTC().Truncate(time.Second)
	insert, err := transaction.ExecContext(ctx, `INSERT INTO assessments(
		finding_id, status, reason, reviewer, evidence, assessed_at
	) VALUES (?, ?, ?, ?, ?, ?)`, assessment.FindingID, assessment.Status,
		assessment.Reason, assessment.Reviewer, assessment.Evidence,
		formatTime(assessment.AssessedAt))
	if err != nil {
		return Assessment{}, fmt.Errorf("record assessment: %w", err)
	}
	assessment.AssessmentID, err = insert.LastInsertId()
	if err != nil {
		return Assessment{}, fmt.Errorf("read assessment ID: %w", err)
	}
	if _, err := transaction.ExecContext(ctx,
		"UPDATE findings SET review_status = ? WHERE id = ?",
		assessment.Status, assessment.FindingID,
	); err != nil {
		return Assessment{}, fmt.Errorf("update finding review status: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return Assessment{}, fmt.Errorf("commit assessment: %w", err)
	}
	return assessment, nil
}

// ListAssessments returns append-only human-review history, newest first.
func (d *DB) ListAssessments(ctx context.Context, filter AssessmentFilter) ([]Assessment, error) {
	var err error
	filter.Product = strings.TrimSpace(filter.Product)
	filter.Release = strings.TrimSpace(filter.Release)
	filter.VulnerabilityID = strings.TrimSpace(filter.VulnerabilityID)
	filter.Ecosystem = strings.TrimSpace(filter.Ecosystem)
	filter.Component = strings.TrimSpace(filter.Component)
	filter.ComponentVersion = strings.TrimSpace(filter.ComponentVersion)
	if filter.Release != "" && filter.Product == "" {
		return nil, errors.New("assessment release filter requires a product")
	}
	if filter.VulnerabilityID != "" && filter.Release == "" {
		return nil, errors.New("assessment vulnerability filter requires a product release")
	}
	componentFields := 0
	for _, value := range []string{filter.Ecosystem, filter.Component, filter.ComponentVersion} {
		if value != "" {
			componentFields++
		}
	}
	if componentFields != 0 && componentFields != 3 {
		return nil, errors.New("assessment component filter requires ecosystem, name, and version")
	}
	for _, target := range []struct {
		label string
		value *string
	}{
		{label: "product name", value: &filter.Product},
		{label: "release version", value: &filter.Release},
		{label: "finding vulnerability ID", value: &filter.VulnerabilityID},
		{label: "finding ecosystem", value: &filter.Ecosystem},
		{label: "finding component", value: &filter.Component},
		{label: "finding component version", value: &filter.ComponentVersion},
	} {
		if *target.value == "" {
			continue
		}
		*target.value, err = cleanIdentifier(target.label, *target.value)
		if err != nil {
			return nil, err
		}
	}

	query := `SELECT a.id, f.id, p.name, r.version, f.ecosystem,
		f.component_name, f.component_version, f.vulnerability_id, f.aliases_json,
		a.status, a.reason, a.reviewer, a.evidence, a.assessed_at
		FROM assessments a
		JOIN findings f ON f.id = a.finding_id
		JOIN releases r ON r.id = f.release_id
		JOIN products p ON p.id = r.product_id WHERE 1 = 1`
	args := make([]any, 0, 6)
	if filter.Product != "" {
		query += " AND p.name = ? COLLATE NOCASE"
		args = append(args, filter.Product)
	}
	if filter.Release != "" {
		query += " AND r.version = ?"
		args = append(args, filter.Release)
	}
	if filter.Component != "" {
		query += " AND f.ecosystem = ? AND f.component_name = ? AND f.component_version = ?"
		args = append(args, filter.Ecosystem, filter.Component, filter.ComponentVersion)
	}
	query += " ORDER BY a.assessed_at DESC, a.id DESC"

	rows, err := d.db.QueryContext(ctx, query, args...)
	if err != nil {
		return nil, fmt.Errorf("list assessments: %w", err)
	}
	defer rows.Close()
	assessments := make([]Assessment, 0)
	for rows.Next() {
		var assessment Assessment
		var aliasesJSON, assessedAt string
		if err := rows.Scan(
			&assessment.AssessmentID, &assessment.FindingID, &assessment.Product,
			&assessment.Release, &assessment.Ecosystem, &assessment.Component,
			&assessment.ComponentVersion, &assessment.VulnerabilityID,
			&aliasesJSON, &assessment.Status, &assessment.Reason, &assessment.Reviewer,
			&assessment.Evidence, &assessedAt,
		); err != nil {
			return nil, fmt.Errorf("read assessment: %w", err)
		}
		if filter.VulnerabilityID != "" {
			matched, matchErr := vulnerabilityIdentifierMatches(
				assessment.VulnerabilityID, aliasesJSON, filter.VulnerabilityID,
			)
			if matchErr != nil {
				return nil, matchErr
			}
			if !matched {
				continue
			}
		}
		assessment.AssessedAt, err = parseTime(assessedAt)
		if err != nil {
			return nil, err
		}
		assessments = append(assessments, assessment)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list assessments: %w", err)
	}
	return assessments, nil
}

func vulnerabilityIdentifierMatches(primary, aliasesJSON, requested string) (bool, error) {
	if strings.EqualFold(primary, requested) {
		return true, nil
	}
	var aliases []string
	if err := json.Unmarshal([]byte(aliasesJSON), &aliases); err != nil {
		return false, fmt.Errorf("decode finding aliases for %s: %w", primary, err)
	}
	for _, alias := range aliases {
		if strings.EqualFold(alias, requested) {
			return true, nil
		}
	}
	return false, nil
}

func cleanAssessmentTarget(target AssessmentTarget) (AssessmentTarget, error) {
	var err error
	for _, field := range []struct {
		label string
		value *string
	}{
		{label: "product name", value: &target.Product},
		{label: "release version", value: &target.Release},
		{label: "finding vulnerability ID", value: &target.VulnerabilityID},
	} {
		*field.value, err = cleanIdentifier(field.label, *field.value)
		if err != nil {
			return AssessmentTarget{}, err
		}
	}
	componentFields := 0
	for _, value := range []string{target.Ecosystem, target.Component, target.ComponentVersion} {
		if strings.TrimSpace(value) != "" {
			componentFields++
		}
	}
	if componentFields != 0 && componentFields != 3 {
		return AssessmentTarget{}, errors.New("assessment component target requires ecosystem, name, and version")
	}
	if componentFields == 3 {
		for _, field := range []struct {
			label string
			value *string
		}{
			{label: "finding ecosystem", value: &target.Ecosystem},
			{label: "finding component", value: &target.Component},
			{label: "finding component version", value: &target.ComponentVersion},
		} {
			*field.value, err = cleanIdentifier(field.label, *field.value)
			if err != nil {
				return AssessmentTarget{}, err
			}
		}
	}
	return target, nil
}

func cleanReviewStatus(value string, allowNeedsReview bool) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	valid := value == AssessmentInvestigating || value == AssessmentAffected ||
		value == AssessmentNotAffected || value == AssessmentFixed
	if allowNeedsReview && value == AssessmentNeedsReview {
		valid = true
	}
	if !valid {
		allowed := "investigating, affected, not-affected, fixed"
		if allowNeedsReview {
			allowed = "needs-review, " + allowed
		}
		return "", fmt.Errorf("invalid assessment status %q; expected one of: %s", value, allowed)
	}
	return value, nil
}

func nonNilStrings(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

func nonNilSeverities(values []osv.Severity) []osv.Severity {
	if values == nil {
		return []osv.Severity{}
	}
	return values
}

func nonNilAffected(values []osv.Affected) []osv.Affected {
	if values == nil {
		return []osv.Affected{}
	}
	return values
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
	return cleanNarrative("product description", value)
}

func cleanNarrative(label, value string) (string, error) {
	value = strings.TrimSpace(value)
	if !utf8.ValidString(value) {
		return "", fmt.Errorf("%s must be valid UTF-8", label)
	}
	if utf8.RuneCountInString(value) > maxDescriptionLength {
		return "", fmt.Errorf("%s exceeds %d characters", label, maxDescriptionLength)
	}
	if strings.IndexFunc(value, func(character rune) bool {
		return unicode.IsControl(character) && character != '\n' && character != '\r' && character != '\t'
	}) >= 0 {
		return "", fmt.Errorf("%s contains an unsupported control character", label)
	}
	return value, nil
}
