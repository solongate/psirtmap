package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solongate/psirtmap/internal/kev"
	"github.com/solongate/psirtmap/internal/osv"
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

func TestImportProductReleaseComponentsCreatesCompleteInventoryAtomically(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	components := []ComponentInput{{
		Ecosystem: "Alpine", Name: "openssl", Version: "3.0.8-r0",
		PURL: "pkg:apk/alpine/openssl@3.0.8-r0",
	}}
	metadata := SBOMImportMetadata{
		Format: "CycloneDX JSON", SpecVersion: "1.6",
		DocumentSHA256: strings.Repeat("a", 64), SourceName: "firmware.cdx.json",
		Discovered: 1,
	}
	result, err := database.ImportProductReleaseComponents(
		ctx, "Gateway-X", "Edge gateway", "1.0", components, metadata,
	)
	if err != nil {
		t.Fatalf("ImportProductReleaseComponents() error = %v", err)
	}
	if !result.CreatedProduct || !result.CreatedRelease || result.Imported != 1 {
		t.Fatalf("import result = %+v", result)
	}
	products, err := database.ListProducts(ctx)
	if err != nil || len(products) != 1 || products[0].Description != "Edge gateway" {
		t.Fatalf("products = %+v, %v", products, err)
	}

	badMetadata := metadata
	badMetadata.DocumentSHA256 = "bad"
	if _, err := database.ImportProductReleaseComponents(
		ctx, "Rolled-Back", "", "1.0", components, badMetadata,
	); err == nil {
		t.Fatal("invalid atomic onboarding import succeeded")
	}
	products, err = database.ListProducts(ctx)
	if err != nil || len(products) != 1 {
		t.Fatalf("failed onboarding import changed products = %+v, %v", products, err)
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

func TestOSVSnapshotLifecycleIsLocalAndAtomic(t *testing.T) {
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
	for _, release := range []string{"2.2", "2.3"} {
		if _, err := database.CreateRelease(ctx, "AG-200", release); err != nil {
			t.Fatal(err)
		}
		if _, err := database.CreateComponent(ctx, "AG-200", release, "Alpine", "openssl", "3.0.8"); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := database.CreateComponent(ctx, "AG-200", "2.3", "Alpine", "busybox", "1.36.0"); err != nil {
		t.Fatal(err)
	}

	packages, err := database.ListPackageVersions(ctx)
	if err != nil || len(packages) != 2 {
		t.Fatalf("ListPackageVersions() = %+v, %v", packages, err)
	}
	openssl := PackageVersion{Ecosystem: "Alpine", Name: "openssl", Version: "3.0.8"}
	busybox := PackageVersion{Ecosystem: "Alpine", Name: "busybox", Version: "1.36.0"}
	result, err := database.SaveOSVSnapshot(ctx, []PackageSnapshot{
		{Package: busybox, Vulnerabilities: []osv.Vulnerability{}},
		{Package: openssl, Vulnerabilities: []osv.Vulnerability{{
			ID: "CVE-2026-12345", Aliases: []string{"GHSA-test"}, Summary: "test advisory",
			Severity: []osv.Severity{{Type: "CVSS_V3", Score: "9.8"}},
			Affected: []osv.Affected{{
				Package: osv.Package{Ecosystem: "Alpine", Name: "openssl"},
				Ranges:  []osv.Range{{Type: "ECOSYSTEM", Events: []osv.RangeEvent{{Introduced: "0"}, {Fixed: "3.0.9"}}}},
			}},
		}}},
	})
	if err != nil {
		t.Fatalf("SaveOSVSnapshot() error = %v", err)
	}
	if result.Source != "OSV" || result.Packages != 2 || result.Vulnerabilities != 1 || result.SynchronizedAt.IsZero() {
		t.Fatalf("sync result = %+v", result)
	}

	vulnerabilities, syncedAt, err := database.LookupOSVSnapshot(ctx, openssl)
	if err != nil || len(vulnerabilities) != 1 || vulnerabilities[0].ID != "CVE-2026-12345" {
		t.Fatalf("LookupOSVSnapshot(openssl) = %+v, %v", vulnerabilities, err)
	}
	if syncedAt.IsZero() || len(vulnerabilities[0].Affected) != 1 || len(vulnerabilities[0].Aliases) != 1 {
		t.Fatalf("stored vulnerability = %+v, synced at %v", vulnerabilities[0], syncedAt)
	}
	vulnerabilities, _, err = database.LookupOSVSnapshot(ctx, busybox)
	if err != nil || vulnerabilities == nil || len(vulnerabilities) != 0 {
		t.Fatalf("LookupOSVSnapshot(busybox) = %#v, %v", vulnerabilities, err)
	}
	latest, err := database.LatestVulnerabilitySync(ctx)
	if err != nil || latest.Packages != 2 || !latest.SynchronizedAt.Equal(result.SynchronizedAt) {
		t.Fatalf("LatestVulnerabilitySync() = %+v, %v", latest, err)
	}

	_, err = database.SaveOSVSnapshot(ctx, []PackageSnapshot{{
		Package: openssl, Vulnerabilities: []osv.Vulnerability{{ID: ""}},
	}})
	if err == nil {
		t.Fatal("invalid SaveOSVSnapshot() error = nil")
	}
	vulnerabilities, afterFailure, err := database.LookupOSVSnapshot(ctx, openssl)
	if err != nil || len(vulnerabilities) != 1 || !afterFailure.Equal(syncedAt) {
		t.Fatalf("failed update changed snapshot: %+v, %v, %v", vulnerabilities, afterFailure, err)
	}
	_, err = database.SaveOSVSnapshot(ctx, []PackageSnapshot{{
		Package: openssl,
		Vulnerabilities: []osv.Vulnerability{{
			ID: "CVE-2026-BROKEN",
			Affected: []osv.Affected{{
				Package:           osv.Package{Ecosystem: "Alpine", Name: "openssl"},
				EcosystemSpecific: json.RawMessage(`{`),
			}},
		}},
	}})
	if err == nil {
		t.Fatal("transactional SaveOSVSnapshot() error = nil for malformed affected data")
	}
	vulnerabilities, afterFailure, err = database.LookupOSVSnapshot(ctx, openssl)
	if err != nil || len(vulnerabilities) != 1 || vulnerabilities[0].ID != "CVE-2026-12345" || !afterFailure.Equal(syncedAt) {
		t.Fatalf("rolled-back update changed snapshot: %+v, %v, %v", vulnerabilities, afterFailure, err)
	}

	replacement, err := database.SaveOSVSnapshot(ctx, []PackageSnapshot{{Package: busybox, Vulnerabilities: []osv.Vulnerability{}}})
	if err != nil {
		t.Fatal(err)
	}
	if replacement.Packages != 1 || replacement.Vulnerabilities != 0 {
		t.Fatalf("replacement = %+v", replacement)
	}
	if _, _, err := database.LookupOSVSnapshot(ctx, openssl); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("stale package lookup error = %v, want ErrSnapshotNotFound", err)
	}
	var vulnerabilityRows int
	if err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM vulnerabilities").Scan(&vulnerabilityRows); err != nil {
		t.Fatal(err)
	}
	if vulnerabilityRows != 0 {
		t.Fatalf("stale vulnerability rows = %d, want 0", vulnerabilityRows)
	}
}

func TestKEVCatalogLifecycleAndFindingAliasEnrichment(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.CreateProduct(ctx, "gateway", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "gateway", "1.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReconcileFindings(ctx, "gateway", "1.0", []FindingMatch{{
		Ecosystem: "npm", Component: "pkg", ComponentVersion: "1.0",
		VulnerabilityID: "GHSA-primary", Aliases: []string{"CVE-2026-12345"},
	}}, "local-osv-snapshot", time.Now(), 1); err != nil {
		t.Fatal(err)
	}

	catalog := kev.Catalog{
		CatalogVersion: "2026.10.01", DateReleased: "2026-10-01T12:00:00Z", Count: 1,
		SourceURL: "https://www.cisa.gov/kev.json",
		Vulnerabilities: []kev.Vulnerability{{
			CVEID: "CVE-2026-12345", VendorProject: "Vendor", Product: "Gateway",
			VulnerabilityName: "Known exploited issue", DateAdded: "2026-09-30",
			ShortDescription: "Actively exploited", RequiredAction: "Apply update",
			DueDate: "2026-10-21", KnownRansomwareCampaignUse: "Known",
			CWEs: []string{"CWE-79"},
		}},
	}
	syncResult, err := database.SaveKEVCatalog(ctx, catalog)
	if err != nil {
		t.Fatalf("SaveKEVCatalog() error = %v", err)
	}
	if syncResult.Entries != 1 || syncResult.CatalogVersion != catalog.CatalogVersion || syncResult.SynchronizedAt.IsZero() {
		t.Fatalf("KEV sync = %+v", syncResult)
	}
	latest, err := database.LatestKEVSync(ctx)
	if err != nil || latest.Source != catalog.SourceURL || !latest.DateReleased.Equal(syncResult.DateReleased) {
		t.Fatalf("LatestKEVSync() = %+v, %v", latest, err)
	}
	entries, err := database.ListKEVEntries(ctx)
	if err != nil || len(entries) != 1 || entries[0].CVEID != "CVE-2026-12345" || len(entries[0].CWEs) != 1 {
		t.Fatalf("ListKEVEntries() = %+v, %v", entries, err)
	}
	findings, err := database.ListFindings(ctx, FindingFilter{})
	if err != nil || len(findings) != 1 || !findings[0].KnownExploited || findings[0].KEV == nil {
		t.Fatalf("KEV-enriched findings = %+v, %v", findings, err)
	}
	if findings[0].KEV.RequiredAction != "Apply update" || findings[0].KEV.KnownRansomwareCampaignUse != "Known" {
		t.Fatalf("finding KEV metadata = %+v", findings[0].KEV)
	}

	invalid := catalog
	invalid.Count = 2
	if _, err := database.SaveKEVCatalog(ctx, invalid); err == nil {
		t.Fatal("invalid SaveKEVCatalog() error = nil")
	}
	entries, err = database.ListKEVEntries(ctx)
	if err != nil || len(entries) != 1 || entries[0].CVEID != "CVE-2026-12345" {
		t.Fatalf("failed update changed KEV snapshot: %+v, %v", entries, err)
	}

	replacement := kev.Catalog{
		CatalogVersion: "2026.10.02", DateReleased: "2026-10-02T12:00:00Z", Count: 1,
		Vulnerabilities: []kev.Vulnerability{{
			CVEID: "CVE-2026-99999", VendorProject: "Other", Product: "Other",
			VulnerabilityName: "Replacement", DateAdded: "2026-10-02",
			ShortDescription: "Replacement entry", RequiredAction: "Update",
			DueDate: "2026-10-23",
		}},
	}
	if _, err := database.SaveKEVCatalog(ctx, replacement); err != nil {
		t.Fatal(err)
	}
	findings, err = database.ListFindings(ctx, FindingFilter{})
	if err != nil || len(findings) != 1 || findings[0].KnownExploited || findings[0].KEV != nil {
		t.Fatalf("finding after KEV replacement = %+v, %v", findings, err)
	}
}

func TestFindingReconciliationPreservesLifecycleHistory(t *testing.T) {
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
	for _, release := range []string{"2.2", "2.3"} {
		if _, err := database.CreateRelease(ctx, "AG-200", release); err != nil {
			t.Fatal(err)
		}
	}

	match := FindingMatch{
		Ecosystem: "Alpine", Component: "openssl", ComponentVersion: "3.0.8",
		VulnerabilityID: "CVE-2026-12345", Aliases: []string{"GHSA-test", "GHSA-test"},
		Summary: "Potential OpenSSL impact",
	}
	first, err := database.ReconcileFindings(
		ctx, "ag-200", "2.2", []FindingMatch{match, match},
		"local-osv-snapshot", time.Now(), 1,
	)
	if err != nil {
		t.Fatalf("first ReconcileFindings() error = %v", err)
	}
	if first.Product != "AG-200" || first.Matched != 1 || first.New != 1 || first.Existing != 0 {
		t.Fatalf("first reconciliation = %+v", first)
	}
	findings, err := database.ListFindings(ctx, FindingFilter{})
	if err != nil || len(findings) != 1 {
		t.Fatalf("ListFindings() = %+v, %v", findings, err)
	}
	if !findings[0].Active || findings[0].Status != "needs-review" || len(findings[0].Aliases) != 1 {
		t.Fatalf("active finding = %+v", findings[0])
	}
	firstSeenAt := findings[0].FirstSeenAt

	second, err := database.ReconcileFindings(
		ctx, "AG-200", "2.2", []FindingMatch{match},
		"local-osv-snapshot", time.Now(), 1,
	)
	if err != nil || second.Existing != 1 || second.New != 0 || second.Reopened != 0 {
		t.Fatalf("second reconciliation = %+v, %v", second, err)
	}

	closed, err := database.ReconcileFindings(
		ctx, "AG-200", "2.2", nil, "local-osv-snapshot", time.Now(), 1,
	)
	if err != nil || closed.NoLongerMatched != 1 || closed.Matched != 0 {
		t.Fatalf("closed reconciliation = %+v, %v", closed, err)
	}
	active, err := database.ListFindings(ctx, FindingFilter{})
	if err != nil || active == nil || len(active) != 0 {
		t.Fatalf("active findings after close = %#v, %v", active, err)
	}
	all, err := database.ListFindings(ctx, FindingFilter{IncludeInactive: true})
	if err != nil || len(all) != 1 || all[0].Active || all[0].Status != "needs-review" || all[0].MatchStatus != "no-longer-matched" || all[0].NoLongerMatchedAt == nil {
		t.Fatalf("all findings after close = %+v, %v", all, err)
	}

	reopened, err := database.ReconcileFindings(
		ctx, "AG-200", "2.2", []FindingMatch{match},
		"local-osv-snapshot", time.Now(), 1,
	)
	if err != nil || reopened.Reopened != 1 || reopened.New != 0 {
		t.Fatalf("reopened reconciliation = %+v, %v", reopened, err)
	}
	findings, err = database.ListFindings(ctx, FindingFilter{Product: "AG-200", Release: "2.2"})
	if err != nil || len(findings) != 1 || !findings[0].FirstSeenAt.Equal(firstSeenAt) || findings[0].NoLongerMatchedAt != nil {
		t.Fatalf("reopened finding = %+v, %v", findings, err)
	}

	otherRelease, err := database.ListFindings(ctx, FindingFilter{Product: "AG-200", Release: "2.3", IncludeInactive: true})
	if err != nil || otherRelease == nil || len(otherRelease) != 0 {
		t.Fatalf("other release findings = %#v, %v", otherRelease, err)
	}
	var scans int
	if err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM finding_scans").Scan(&scans); err != nil {
		t.Fatal(err)
	}
	if scans != 4 {
		t.Fatalf("finding scan audit rows = %d, want 4", scans)
	}
}

func TestFindingReconciliationRejectsInvalidInputWithoutWriting(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.CreateProduct(ctx, "gateway", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "gateway", "1.0"); err != nil {
		t.Fatal(err)
	}
	_, err = database.ReconcileFindings(ctx, "gateway", "1.0", []FindingMatch{{
		Ecosystem: "npm", Component: "pkg", ComponentVersion: "1.0",
	}}, "local-osv-snapshot", time.Time{}, 1)
	if err == nil || !strings.Contains(err.Error(), "vulnerability ID") {
		t.Fatalf("invalid reconciliation error = %v", err)
	}
	var scans, findings int
	if err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM finding_scans").Scan(&scans); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings").Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if scans != 0 || findings != 0 {
		t.Fatalf("invalid reconciliation wrote scans=%d findings=%d", scans, findings)
	}

	if _, err := database.db.ExecContext(ctx, `CREATE TRIGGER reject_finding_insert
		BEFORE INSERT ON findings BEGIN SELECT RAISE(ABORT, 'forced finding failure'); END`); err != nil {
		t.Fatal(err)
	}
	_, err = database.ReconcileFindings(ctx, "gateway", "1.0", []FindingMatch{{
		Ecosystem: "npm", Component: "pkg", ComponentVersion: "1.0",
		VulnerabilityID: "CVE-2026-ROLLBACK",
	}}, "local-osv-snapshot", time.Time{}, 1)
	if err == nil || !strings.Contains(err.Error(), "forced finding failure") {
		t.Fatalf("forced transaction error = %v", err)
	}
	if err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM finding_scans").Scan(&scans); err != nil {
		t.Fatal(err)
	}
	if err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM findings").Scan(&findings); err != nil {
		t.Fatal(err)
	}
	if scans != 0 || findings != 0 {
		t.Fatalf("failed transaction wrote scans=%d findings=%d", scans, findings)
	}
}

func TestAssessmentHistoryIsAppendOnlyAndPreservesFindingLifecycle(t *testing.T) {
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
	match := FindingMatch{
		Ecosystem: "Alpine", Component: "openssl", ComponentVersion: "3.0.8",
		VulnerabilityID: "GHSA-PRIMARY", Aliases: []string{"CVE-2026-12345"}, Summary: "OpenSSL impact",
	}
	if _, err := database.ReconcileFindings(ctx, "AG-200", "2.2", []FindingMatch{match}, "local-osv-snapshot", time.Now(), 1); err != nil {
		t.Fatal(err)
	}
	target := AssessmentTarget{Product: "ag-200", Release: "2.2", VulnerabilityID: "CVE-2026-12345"}
	first, err := database.CreateAssessment(ctx, target, AssessmentInput{
		Status: AssessmentInvestigating, Reviewer: "emirhan",
	})
	if err != nil {
		t.Fatalf("CreateAssessment(investigating) error = %v", err)
	}
	second, err := database.CreateAssessment(ctx, target, AssessmentInput{
		Status: AssessmentAffected, Reviewer: "psirt@example.com",
		Reason: "The vulnerable feature is enabled.", Evidence: "SEC-123",
	})
	if err != nil {
		t.Fatalf("CreateAssessment(affected) error = %v", err)
	}
	if first.AssessmentID == second.AssessmentID || second.Product != "AG-200" || second.Status != AssessmentAffected {
		t.Fatalf("assessments = first %+v, second %+v", first, second)
	}

	history, err := database.ListAssessments(ctx, AssessmentFilter{
		Product: "AG-200", Release: "2.2", VulnerabilityID: "CVE-2026-12345",
	})
	if err != nil || len(history) != 2 {
		t.Fatalf("ListAssessments() = %+v, %v", history, err)
	}
	if history[0].Status != AssessmentAffected || history[0].Reason == "" || history[0].Evidence != "SEC-123" || history[1].Status != AssessmentInvestigating {
		t.Fatalf("assessment history = %+v", history)
	}
	findings, err := database.ListFindings(ctx, FindingFilter{Status: AssessmentAffected})
	if err != nil || len(findings) != 1 || findings[0].Status != AssessmentAffected || findings[0].MatchStatus != "matched" {
		t.Fatalf("affected findings = %+v, %v", findings, err)
	}

	// A new scan refreshes matching evidence without erasing the human decision.
	if _, err := database.ReconcileFindings(ctx, "AG-200", "2.2", []FindingMatch{match}, "local-osv-snapshot", time.Now(), 1); err != nil {
		t.Fatal(err)
	}
	findings, err = database.ListFindings(ctx, FindingFilter{})
	if err != nil || len(findings) != 1 || findings[0].Status != AssessmentAffected {
		t.Fatalf("finding after rescan = %+v, %v", findings, err)
	}
	if _, err := database.ReconcileFindings(ctx, "AG-200", "2.2", nil, "local-osv-snapshot", time.Now(), 1); err != nil {
		t.Fatal(err)
	}
	findings, err = database.ListFindings(ctx, FindingFilter{IncludeInactive: true})
	if err != nil || len(findings) != 1 || findings[0].Status != AssessmentAffected || findings[0].MatchStatus != "no-longer-matched" {
		t.Fatalf("inactive assessed finding = %+v, %v", findings, err)
	}
}

func TestAssessmentValidationAmbiguityAndAtomicity(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	database, err := Open(ctx, ":memory:")
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	if _, err := database.CreateProduct(ctx, "gateway", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "gateway", "1.0"); err != nil {
		t.Fatal(err)
	}
	matches := []FindingMatch{
		{Ecosystem: "npm", Component: "pkg-a", ComponentVersion: "1.0", VulnerabilityID: "CVE-2026-SHARED"},
		{Ecosystem: "npm", Component: "pkg-b", ComponentVersion: "2.0", VulnerabilityID: "CVE-2026-SHARED"},
	}
	if _, err := database.ReconcileFindings(ctx, "gateway", "1.0", matches, "local-osv-snapshot", time.Now(), 2); err != nil {
		t.Fatal(err)
	}
	baseTarget := AssessmentTarget{Product: "gateway", Release: "1.0", VulnerabilityID: "CVE-2026-SHARED"}
	if _, err := database.CreateAssessment(ctx, baseTarget, AssessmentInput{
		Status: AssessmentInvestigating, Reviewer: "reviewer",
	}); !errors.Is(err, ErrAmbiguousFinding) {
		t.Fatalf("ambiguous assessment error = %v", err)
	}
	for _, input := range []AssessmentInput{
		{Status: "unknown", Reviewer: "reviewer"},
		{Status: AssessmentAffected, Reviewer: "reviewer"},
		{Status: AssessmentInvestigating},
	} {
		if _, err := database.CreateAssessment(ctx, AssessmentTarget{
			Product: "gateway", Release: "1.0", VulnerabilityID: "CVE-2026-SHARED",
			Ecosystem: "npm", Component: "pkg-a", ComponentVersion: "1.0",
		}, input); err == nil {
			t.Fatalf("invalid assessment %+v succeeded", input)
		}
	}

	target := AssessmentTarget{
		Product: "gateway", Release: "1.0", VulnerabilityID: "CVE-2026-SHARED",
		Ecosystem: "npm", Component: "pkg-a", ComponentVersion: "1.0",
	}
	if _, err := database.db.ExecContext(ctx, `CREATE TRIGGER reject_review_status
		BEFORE UPDATE OF review_status ON findings BEGIN SELECT RAISE(ABORT, 'forced review failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateAssessment(ctx, target, AssessmentInput{
		Status: AssessmentNotAffected, Reviewer: "reviewer", Reason: "Not reachable",
	}); err == nil || !strings.Contains(err.Error(), "forced review failure") {
		t.Fatalf("forced transaction error = %v", err)
	}
	var count int
	if err := database.db.QueryRowContext(ctx, "SELECT COUNT(*) FROM assessments").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("rolled-back assessment count = %d", count)
	}
}

func TestSchemaVersionFourMigratesWithoutLosingFindings(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v4.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateProduct(ctx, "gateway", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "gateway", "1.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReconcileFindings(ctx, "gateway", "1.0", []FindingMatch{{
		Ecosystem: "npm", Component: "pkg", ComponentVersion: "1.0", VulnerabilityID: "CVE-2026-MIGRATE",
	}}, "local-osv-snapshot", time.Now(), 1); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, "DROP TABLE assessments"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if _, err := raw.ExecContext(ctx, "PRAGMA user_version = 4"); err != nil {
		raw.Close()
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	database, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("Open(v4) error = %v", err)
	}
	defer database.Close()
	findings, err := database.ListFindings(ctx, FindingFilter{})
	if err != nil || len(findings) != 1 || findings[0].VulnerabilityID != "CVE-2026-MIGRATE" {
		t.Fatalf("migrated findings = %+v, %v", findings, err)
	}
	history, err := database.ListAssessments(ctx, AssessmentFilter{})
	if err != nil || history == nil || len(history) != 0 {
		t.Fatalf("migrated assessment history = %#v, %v", history, err)
	}
}

func TestSchemaVersionFiveMigratesWithoutLosingAssessments(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v5.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateProduct(ctx, "gateway", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "gateway", "1.0"); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ReconcileFindings(ctx, "gateway", "1.0", []FindingMatch{{
		Ecosystem: "npm", Component: "pkg", ComponentVersion: "1.0",
		VulnerabilityID: "CVE-2026-MIGRATE",
	}}, "local-osv-snapshot", time.Now(), 1); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateAssessment(ctx, AssessmentTarget{
		Product: "gateway", Release: "1.0", VulnerabilityID: "CVE-2026-MIGRATE",
	}, AssessmentInput{
		Status: AssessmentNotAffected, Reviewer: "reviewer", Reason: "Feature disabled",
	}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"DROP TABLE kev_entries",
		"DROP TABLE kev_syncs",
		"PRAGMA user_version = 5",
	} {
		if _, err := raw.ExecContext(ctx, statement); err != nil {
			raw.Close()
			t.Fatalf("prepare v5 database: %v", err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("Open(v5) error = %v", err)
	}
	defer database.Close()
	findings, err := database.ListFindings(ctx, FindingFilter{})
	if err != nil || len(findings) != 1 || findings[0].Status != AssessmentNotAffected {
		t.Fatalf("migrated findings = %+v, %v", findings, err)
	}
	history, err := database.ListAssessments(ctx, AssessmentFilter{})
	if err != nil || len(history) != 1 || history[0].Reason != "Feature disabled" {
		t.Fatalf("migrated assessments = %+v, %v", history, err)
	}
	if _, err := database.LatestKEVSync(ctx); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("empty migrated KEV snapshot error = %v", err)
	}
}

func TestSchemaVersionThreeMigratesWithoutLosingLocalSnapshot(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	path := filepath.Join(t.TempDir(), "v3.db")
	database, err := Open(ctx, path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateProduct(ctx, "AG-200", ""); err != nil {
		t.Fatal(err)
	}
	if _, err := database.CreateRelease(ctx, "AG-200", "2.2"); err != nil {
		t.Fatal(err)
	}
	pkg := PackageVersion{Ecosystem: "Alpine", Name: "openssl", Version: "3.0.8"}
	if _, err := database.CreateComponent(ctx, "AG-200", "2.2", pkg.Ecosystem, pkg.Name, pkg.Version); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SaveOSVSnapshot(ctx, []PackageSnapshot{{
		Package: pkg, Vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-MIGRATION"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if err := database.Close(); err != nil {
		t.Fatal(err)
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, statement := range []string{
		"DROP TABLE findings",
		"DROP TABLE finding_scans",
		"PRAGMA user_version = 3",
	} {
		if _, err := raw.ExecContext(ctx, statement); err != nil {
			raw.Close()
			t.Fatalf("prepare v3 database: %v", err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	database, err = Open(ctx, path)
	if err != nil {
		t.Fatalf("Open(v3) error = %v", err)
	}
	defer database.Close()
	vulnerabilities, _, err := database.LookupOSVSnapshot(ctx, pkg)
	if err != nil || len(vulnerabilities) != 1 || vulnerabilities[0].ID != "CVE-2026-MIGRATION" {
		t.Fatalf("migrated snapshot = %+v, %v", vulnerabilities, err)
	}
	findings, err := database.ListFindings(ctx, FindingFilter{})
	if err != nil || findings == nil || len(findings) != 0 {
		t.Fatalf("migrated findings = %#v, %v", findings, err)
	}
	var version int
	if err := database.db.QueryRowContext(ctx, "PRAGMA user_version").Scan(&version); err != nil {
		t.Fatal(err)
	}
	if version != schemaVersion {
		t.Fatalf("schema version = %d, want %d", version, schemaVersion)
	}
}

func TestFeedImportIsAtomicAndRecordsProvenance(t *testing.T) {
	t.Parallel()
	ctx := context.Background()
	database, err := Open(ctx, filepath.Join(t.TempDir(), "feed.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	oldPackage := PackageVersion{Ecosystem: "npm", Name: "old", Version: "1.0.0"}
	if _, err := database.SaveOSVSnapshot(ctx, []PackageSnapshot{{
		Package: oldPackage, Vulnerabilities: []osv.Vulnerability{{ID: "OSV-OLD"}},
	}}); err != nil {
		t.Fatal(err)
	}
	if _, err := database.SaveKEVCatalog(ctx, testFeedCatalog("old", "CVE-2025-1000")); err != nil {
		t.Fatal(err)
	}

	synchronizedAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	newPackage := PackageVersion{Ecosystem: "npm", Name: "new", Version: "2.0.0"}
	snapshot := IntelligenceSnapshot{
		OSVSync: VulnerabilitySync{
			Source: "OSV", SynchronizedAt: synchronizedAt, Packages: 1, Vulnerabilities: 1,
		},
		Packages: []PackageSnapshot{{
			Package:         newPackage,
			Vulnerabilities: []osv.Vulnerability{{ID: "OSV-NEW", Aliases: []string{"CVE-2026-12345"}}},
		}},
		KEVSync: KEVSync{
			Source: "https://example.test/kev.json", CatalogVersion: "new",
			DateReleased: synchronizedAt, SynchronizedAt: synchronizedAt, Entries: 1,
		},
		KEVEntries: testFeedCatalog("new", "CVE-2026-12345").Vulnerabilities,
	}
	metadata := FeedImportMetadata{
		FormatVersion: 1, BundleCreatedAt: synchronizedAt.Add(time.Minute),
		SourceName: "transfer.bundle", ManifestSHA256: strings.Repeat("a", 64),
	}
	if _, err := database.db.ExecContext(ctx, `CREATE TRIGGER fail_feed_import
		BEFORE INSERT ON kev_syncs WHEN NEW.catalog_version = 'new'
		BEGIN SELECT RAISE(ABORT, 'forced import failure'); END`); err != nil {
		t.Fatal(err)
	}
	if _, err := database.ImportIntelligence(ctx, snapshot, metadata); err == nil {
		t.Fatal("ImportIntelligence() error = nil, want forced failure")
	}
	oldMatches, _, err := database.LookupOSVSnapshot(ctx, oldPackage)
	if err != nil || len(oldMatches) != 1 || oldMatches[0].ID != "OSV-OLD" {
		t.Fatalf("OSV snapshot after rollback = %+v, %v", oldMatches, err)
	}
	oldKEV, err := database.LatestKEVSync(ctx)
	if err != nil || oldKEV.CatalogVersion != "old" {
		t.Fatalf("KEV snapshot after rollback = %+v, %v", oldKEV, err)
	}
	if _, err := database.LatestFeedImport(ctx); !errors.Is(err, ErrSnapshotNotFound) {
		t.Fatalf("feed import after rollback error = %v", err)
	}
	if _, err := database.db.ExecContext(ctx, "DROP TRIGGER fail_feed_import"); err != nil {
		t.Fatal(err)
	}

	result, err := database.ImportIntelligence(ctx, snapshot, metadata)
	if err != nil {
		t.Fatalf("ImportIntelligence() error = %v", err)
	}
	if result.Packages != 1 || result.Vulnerabilities != 1 || result.KEVEntries != 1 {
		t.Fatalf("ImportIntelligence() = %+v", result)
	}
	newMatches, gotSynchronizedAt, err := database.LookupOSVSnapshot(ctx, newPackage)
	if err != nil || len(newMatches) != 1 || newMatches[0].ID != "OSV-NEW" || !gotSynchronizedAt.Equal(synchronizedAt) {
		t.Fatalf("imported OSV snapshot = %+v, %v, %v", newMatches, gotSynchronizedAt, err)
	}
	provenance, err := database.LatestFeedImport(ctx)
	if err != nil || provenance.SourceName != metadata.SourceName || provenance.ManifestSHA256 != metadata.ManifestSHA256 {
		t.Fatalf("LatestFeedImport() = %+v, %v", provenance, err)
	}
}

func testFeedCatalog(version, cveID string) kev.Catalog {
	return kev.Catalog{
		CatalogVersion: version,
		DateReleased:   time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		Count:          1,
		SourceURL:      "https://example.test/kev.json",
		Vulnerabilities: []kev.Vulnerability{{
			CVEID: cveID, VendorProject: "Example", Product: "Demo",
			VulnerabilityName: "Example vulnerability", DateAdded: "2026-09-01",
			ShortDescription: "Example", RequiredAction: "Apply update",
			DueDate: "2026-10-01",
		}},
	}
}
