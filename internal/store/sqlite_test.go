package store

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func TestInventoryLifecyclePersists(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "nested", "inventory.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}

	product, err := database.CreateProduct(ctx, "  AG-200  ", "  Industrial gateway  ")
	if err != nil {
		t.Fatalf("CreateProduct() error = %v", err)
	}
	if product.Name != "AG-200" || product.Description != "Industrial gateway" {
		t.Fatalf("product = %+v", product)
	}
	if _, err := database.CreateProduct(ctx, "ag-200", "duplicate"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate CreateProduct() error = %v, want ErrAlreadyExists", err)
	}

	release, err := database.CreateRelease(ctx, "ag-200", "2.2")
	if err != nil {
		t.Fatalf("CreateRelease() error = %v", err)
	}
	if release.Product != "AG-200" || release.Version != "2.2" {
		t.Fatalf("release = %+v", release)
	}
	if _, err := database.CreateRelease(ctx, "missing", "1.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing product error = %v, want ErrNotFound", err)
	}
	if _, err := database.CreateRelease(ctx, "AG-200", "2.2"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate release error = %v, want ErrAlreadyExists", err)
	}

	component, err := database.CreateComponent(ctx, "AG-200", "2.2", "npm", "@scope/pkg", "1.2.3")
	if err != nil {
		t.Fatalf("CreateComponent() error = %v", err)
	}
	if component.Name != "@scope/pkg" || component.Product != "AG-200" {
		t.Fatalf("component = %+v", component)
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "9.9", "npm", "pkg", "1"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing release error = %v, want ErrNotFound", err)
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "2.2", "npm", "@scope/pkg", "1.2.3"); !errors.Is(err, ErrAlreadyExists) {
		t.Fatalf("duplicate component error = %v, want ErrAlreadyExists", err)
	}

	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if permissions := info.Mode().Perm(); permissions != 0o600 {
		t.Fatalf("database permissions = %o, want 600", permissions)
	}

	database, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("reopen database: %v", err)
	}
	defer database.Close()

	products, err := database.ListProducts(ctx)
	if err != nil || len(products) != 1 || products[0].Name != "AG-200" {
		t.Fatalf("ListProducts() = %+v, %v", products, err)
	}
	releases, err := database.ListReleases(ctx, "AG-200")
	if err != nil || len(releases) != 1 || releases[0].Version != "2.2" {
		t.Fatalf("ListReleases() = %+v, %v", releases, err)
	}
	storedRelease, err := database.GetRelease(ctx, "ag-200", "2.2")
	if err != nil || storedRelease.Product != "AG-200" {
		t.Fatalf("GetRelease() = %+v, %v", storedRelease, err)
	}
	if _, err := database.GetRelease(ctx, "AG-200", "missing"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("missing GetRelease() error = %v, want ErrNotFound", err)
	}
	components, err := database.ListComponents(ctx, "ag-200", "2.2")
	if err != nil || len(components) != 1 || components[0].Name != "@scope/pkg" {
		t.Fatalf("ListComponents() = %+v, %v", components, err)
	}
	allComponents, err := database.ListAllComponents(ctx)
	if err != nil || len(allComponents) != 1 || allComponents[0].Product != "AG-200" {
		t.Fatalf("ListAllComponents() = %+v, %v", allComponents, err)
	}
}

func TestListsAreSortedAndEmptyListsAreNonNil(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	products, err := database.ListProducts(ctx)
	if err != nil || products == nil || len(products) != 0 {
		t.Fatalf("empty ListProducts() = %#v, %v", products, err)
	}
	components, err := database.ListAllComponents(ctx)
	if err != nil || components == nil || len(components) != 0 {
		t.Fatalf("empty ListAllComponents() = %#v, %v", components, err)
	}
	for _, name := range []string{"Zulu", "alpha", "Bravo"} {
		if _, err := database.CreateProduct(ctx, name, ""); err != nil {
			t.Fatalf("CreateProduct(%q): %v", name, err)
		}
	}
	products, err = database.ListProducts(ctx)
	if err != nil {
		t.Fatalf("ListProducts() error = %v", err)
	}
	want := []string{"alpha", "Bravo", "Zulu"}
	for index := range want {
		if products[index].Name != want[index] {
			t.Fatalf("products = %+v, want order %v", products, want)
		}
	}
}

func TestConcurrentDuplicateProductCreation(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()

	const attempts = 12
	results := make(chan error, attempts)
	var group sync.WaitGroup
	for range attempts {
		group.Add(1)
		go func() {
			defer group.Done()
			_, createErr := database.CreateProduct(ctx, "AG-200", "")
			results <- createErr
		}()
	}
	group.Wait()
	close(results)

	var successes, duplicates int
	for result := range results {
		switch {
		case result == nil:
			successes++
		case errors.Is(result, ErrAlreadyExists):
			duplicates++
		default:
			t.Fatalf("unexpected CreateProduct() error = %v", result)
		}
	}
	if successes != 1 || duplicates != attempts-1 {
		t.Fatalf("successes = %d, duplicates = %d", successes, duplicates)
	}
}

func TestValidationAndNewerSchemaProtection(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "inventory.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	if _, err := database.CreateProduct(ctx, " ", ""); err == nil {
		t.Fatal("CreateProduct() error = nil for blank name")
	}
	if _, err := database.CreateRelease(ctx, "", "1"); err == nil {
		t.Fatal("CreateRelease() error = nil for blank product")
	}
	if _, err := database.CreateComponent(ctx, "p", "r", "", "n", "v"); err == nil {
		t.Fatal("CreateComponent() error = nil for blank ecosystem")
	}
	if _, err := database.CreateProduct(ctx, "evil\x1b[31m", ""); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("control-character product error = %v", err)
	}
	if _, err := database.CreateProduct(ctx, strings.Repeat("x", maxIdentifierLength+1), ""); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized product error = %v", err)
	}
	if _, err := database.CreateProduct(ctx, "safe", "bad\x00description"); err == nil || !strings.Contains(err.Error(), "control") {
		t.Fatalf("control-character description error = %v", err)
	}
	if _, err := database.db.ExecContext(ctx, "PRAGMA user_version = 999"); err != nil {
		t.Fatalf("set future schema: %v", err)
	}
	if err := database.Close(); err != nil {
		t.Fatalf("Close() error = %v", err)
	}

	_, err = Open(ctx, path)
	if err == nil || !strings.Contains(err.Error(), "newer than supported") {
		t.Fatalf("Open() future schema error = %v", err)
	}
}

func TestCanceledContextStopsWrites(t *testing.T) {
	t.Parallel()

	database, err := Open(context.Background(), ":memory:")
	if err != nil {
		t.Fatalf("Open() error = %v", err)
	}
	defer database.Close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err == nil {
		t.Fatal("CreateProduct() error = nil with canceled context")
	}
}

func TestImportReleaseComponentsIsAtomicAndIdempotent(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "AG-200", "2.2"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "2.2", "Alpine", "busybox", "1.36.0"); err != nil {
		t.Fatal(err)
	}
	components := []ComponentInput{
		{Ecosystem: "Alpine", Name: "busybox", Version: "1.36.0", PURL: "pkg:apk/alpine/busybox@1.36.0"},
		{Ecosystem: "Alpine", Name: "openssl", Version: "3.0.8-r0", PURL: "pkg:apk/alpine/openssl@3.0.8-r0"},
	}
	metadata := SBOMImportMetadata{
		Format: "CycloneDX JSON", SpecVersion: "1.6", SerialNumber: "urn:uuid:test",
		DocumentSHA256: strings.Repeat("a", 64), SourceName: "firmware.cdx.json",
		Discovered: 3, Skipped: 1,
	}

	result, err := database.ImportReleaseComponents(ctx, "ag-200", "2.2", components, metadata)
	if err != nil {
		t.Fatalf("ImportReleaseComponents() error = %v", err)
	}
	if result.Product != "AG-200" || result.CreatedRelease || result.Imported != 1 || result.AlreadyPresent != 1 {
		t.Fatalf("first import result = %+v", result)
	}
	stored, err := database.ListComponents(ctx, "AG-200", "2.2")
	if err != nil || len(stored) != 2 || stored[0].PURL == "" || stored[1].PURL == "" {
		t.Fatalf("ListComponents() = %+v, %v", stored, err)
	}

	result, err = database.ImportReleaseComponents(ctx, "AG-200", "2.2", components, metadata)
	if err != nil {
		t.Fatalf("second ImportReleaseComponents() error = %v", err)
	}
	if result.CreatedRelease || result.Imported != 0 || result.AlreadyPresent != 2 {
		t.Fatalf("second import result = %+v", result)
	}
	var importRecords int
	if err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM sbom_imports").Scan(&importRecords); err != nil {
		t.Fatal(err)
	}
	if importRecords != 2 {
		t.Fatalf("SBOM import records = %d, want 2", importRecords)
	}

	badMetadata := metadata
	badMetadata.DocumentSHA256 = "invalid"
	if _, err := database.ImportReleaseComponents(ctx, "AG-200", "3.0", components, badMetadata); err == nil {
		t.Fatal("invalid import metadata error = nil")
	}
	if _, err := database.GetRelease(ctx, "AG-200", "3.0"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("failed import created release; GetRelease() error = %v", err)
	}
}

func TestSchemaVersionOneMigratesWithoutLosingComponents(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v1.db")
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	statements := []string{
		`CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT NOT NULL COLLATE NOCASE UNIQUE, description TEXT NOT NULL DEFAULT '', created_at TEXT NOT NULL)`,
		`CREATE TABLE releases (id INTEGER PRIMARY KEY, product_id INTEGER NOT NULL REFERENCES products(id) ON DELETE CASCADE, version TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(product_id, version))`,
		`CREATE TABLE components (id INTEGER PRIMARY KEY, release_id INTEGER NOT NULL REFERENCES releases(id) ON DELETE CASCADE, ecosystem TEXT NOT NULL, name TEXT NOT NULL, version TEXT NOT NULL, created_at TEXT NOT NULL, UNIQUE(release_id, ecosystem, name, version))`,
		`CREATE INDEX components_release_id_idx ON components(release_id)`,
		`INSERT INTO products(id, name, description, created_at) VALUES (1, 'AG-200', '', '2026-09-29T00:00:00Z')`,
		`INSERT INTO releases(id, product_id, version, created_at) VALUES (1, 1, '2.2', '2026-09-29T00:00:00Z')`,
		`INSERT INTO components(release_id, ecosystem, name, version, created_at) VALUES (1, 'Alpine', 'openssl', '3.0.8', '2026-09-29T00:00:00Z')`,
		`PRAGMA user_version = 1`,
	}
	for _, statement := range statements {
		if _, err := raw.ExecContext(ctx, statement); err != nil {
			raw.Close()
			t.Fatalf("prepare v1 database: %v", err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	database, err := Open(ctx, path)
	if err != nil {
		t.Fatalf("Open(v1) error = %v", err)
	}
	defer database.Close()
	components, err := database.ListComponents(ctx, "AG-200", "2.2")
	if err != nil || len(components) != 1 || components[0].Name != "openssl" || components[0].PURL != "" {
		t.Fatalf("migrated components = %+v, %v", components, err)
	}
	var version int
	if err := database.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
}
