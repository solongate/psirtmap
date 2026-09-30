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
	if err != nil || len(all) != 1 || all[0].Active || all[0].Status != "no-longer-matched" || all[0].NoLongerMatchedAt == nil {
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
