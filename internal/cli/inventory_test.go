package cli_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/solongate/psirtmap/internal/cli"
	"github.com/solongate/psirtmap/internal/kev"
	"github.com/solongate/psirtmap/internal/osv"
)

type packageResult struct {
	vulnerabilities []osv.Vulnerability
	err             error
}

type inventoryQuerier struct {
	mu      sync.Mutex
	results map[string]packageResult
	calls   []string
}

type inventoryKEVFetcher struct {
	catalog kev.Catalog
	err     error
	calls   int
}

func (f *inventoryKEVFetcher) Fetch(_ context.Context) (kev.Catalog, error) {
	f.calls++
	return f.catalog, f.err
}

func (q *inventoryQuerier) Query(_ context.Context, pkg osv.Package, version string) ([]osv.Vulnerability, error) {
	key := fmt.Sprintf("%s:%s@%s", pkg.Ecosystem, pkg.Name, version)
	q.mu.Lock()
	defer q.mu.Unlock()
	q.calls = append(q.calls, key)
	result := q.results[key]
	return result.vulnerabilities, result.err
}

func runWithDatabase(
	t *testing.T,
	databasePath string,
	querier cli.VulnerabilityQuerier,
	args ...string,
) (int, string, string) {
	t.Helper()
	arguments := append([]string{"--database", databasePath}, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := cli.Run(context.Background(), arguments, &stdout, &stderr, querier)
	return exitCode, stdout.String(), stderr.String()
}

func runWithSourcesDatabase(
	t *testing.T,
	databasePath string,
	querier cli.VulnerabilityQuerier,
	kevFetcher cli.KEVFetcher,
	args ...string,
) (int, string, string) {
	t.Helper()
	arguments := append([]string{"--database", databasePath}, args...)
	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := cli.RunWithSources(
		context.Background(), arguments, &stdout, &stderr, querier, kevFetcher,
	)
	return exitCode, stdout.String(), stderr.String()
}

func requireSuccess(t *testing.T, exitCode int, stderr string) {
	t.Helper()
	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %q", exitCode, stderr)
	}
}

func TestInventoryCLIWorkflowAndScan(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "data", "psirtmap.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"Alpine:openssl@3.0.8": {vulnerabilities: []osv.Vulnerability{{
			ID: "OSV-2026-B", Summary: "second finding",
		}, {
			ID: "OSV-2026-A", Summary: "first finding", Aliases: []string{"CVE-2026-1000"},
		}}},
		"npm:@scope/pkg@2.1.0": {},
	}}

	exitCode, stdout, stderr := runWithDatabase(t, path, querier, "init")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, path) {
		t.Fatalf("init stdout = %q, want database path", stdout)
	}

	exitCode, stdout, stderr = runWithDatabase(
		t, path, querier, "product", "add", "AG-200", "--description", "Industrial gateway",
	)
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "Created product:\nAG-200") {
		t.Fatalf("product add stdout = %q", stdout)
	}

	exitCode, _, stderr = runWithDatabase(t, path, querier, "release", "create", "ag-200", "2.2")
	requireSuccess(t, exitCode, stderr)
	exitCode, _, stderr = runWithDatabase(
		t, path, querier, "component", "add", "AG-200@2.2", "openssl@3.0.8", "-e", "Alpine",
	)
	requireSuccess(t, exitCode, stderr)
	exitCode, _, stderr = runWithDatabase(
		t, path, querier, "component", "add", "AG-200@2.2", "@scope/pkg@2.1.0", "--ecosystem=npm",
	)
	requireSuccess(t, exitCode, stderr)

	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "product", "list")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "AG-200") || !strings.Contains(stdout, "Industrial gateway") {
		t.Fatalf("product list stdout = %q", stdout)
	}
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "component", "list", "AG-200@2.2")
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"Alpine", "openssl", "3.0.8", "@scope/pkg", "2.1.0"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("component list stdout = %q, want %q", stdout, expected)
		}
	}
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "release", "list", "AG-200", "--json")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, `"version": "2.2"`) || !strings.Contains(stdout, `"product": "AG-200"`) {
		t.Fatalf("release list stdout = %q", stdout)
	}

	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "sync")
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"VULNERABILITY DATA UPDATED", "Packages         2", "Vulnerabilities  2"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("sync stdout = %q, want %q", stdout, expected)
		}
	}

	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "scan", "AG-200@2.2")
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"Local OSV snapshot", "POTENTIAL FINDINGS\n2", "OSV-2026-A", "OSV-2026-B", "needs-review"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("scan stdout = %q, want %q", stdout, expected)
		}
	}
	if strings.Index(stdout, "OSV-2026-A") > strings.Index(stdout, "OSV-2026-B") {
		t.Fatalf("scan output is not sorted: %q", stdout)
	}

	querier.mu.Lock()
	calls := append([]string(nil), querier.calls...)
	querier.mu.Unlock()
	if len(calls) != 2 {
		t.Fatalf("OSV calls = %v, want 2", calls)
	}
}

func TestCISAKEVSyncEnrichesScanAndPersistedFindings(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "psirtmap.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"Alpine:openssl@3.0.8": {vulnerabilities: []osv.Vulnerability{{
			ID:      "GHSA-TEST-0001",
			Aliases: []string{"CVE-2026-12345"},
			Summary: "OpenSSL test vulnerability",
		}}},
	}}
	kevFetcher := &inventoryKEVFetcher{catalog: kev.Catalog{
		CatalogVersion: "2026.10.01",
		DateReleased:   "2026-10-01T12:00:00Z",
		Count:          1,
		SourceURL:      "https://www.cisa.gov/test-kev.json",
		Vulnerabilities: []kev.Vulnerability{{
			CVEID:                      "CVE-2026-12345",
			VendorProject:              "OpenSSL",
			Product:                    "OpenSSL",
			VulnerabilityName:          "OpenSSL test vulnerability",
			DateAdded:                  "2026-10-01",
			ShortDescription:           "Known exploitation test record.",
			RequiredAction:             "Apply vendor mitigations.",
			DueDate:                    "2026-10-22",
			KnownRansomwareCampaignUse: "Known",
			CWEs:                       []string{"CWE-787"},
		}},
	}}

	for _, arguments := range [][]string{
		{"product", "add", "Gateway"},
		{"release", "add", "Gateway", "1.0"},
		{"component", "add", "Gateway@1.0", "openssl@3.0.8", "--ecosystem", "Alpine"},
	} {
		exitCode, _, stderr := runWithSourcesDatabase(t, path, querier, kevFetcher, arguments...)
		requireSuccess(t, exitCode, stderr)
	}

	exitCode, stdout, stderr := runWithSourcesDatabase(t, path, querier, kevFetcher, "sync")
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"OSV              ready", "CISA KEV         ready", "KEV entries      1"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("sync stdout = %q, want %q", stdout, expected)
		}
	}
	if kevFetcher.calls != 1 {
		t.Fatalf("KEV fetch calls = %d, want 1", kevFetcher.calls)
	}

	exitCode, stdout, stderr = runWithSourcesDatabase(t, path, querier, kevFetcher, "scan", "Gateway@1.0")
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"Known exploited  1", "GHSA-TEST-0001", "YES"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("scan stdout = %q, want %q", stdout, expected)
		}
	}

	exitCode, stdout, stderr = runWithSourcesDatabase(
		t, path, querier, kevFetcher, "findings", "Gateway@1.0", "--json",
	)
	requireSuccess(t, exitCode, stderr)
	var findings []struct {
		ID             string             `json:"id"`
		KnownExploited bool               `json:"known_exploited"`
		KEV            *kev.Vulnerability `json:"kev"`
	}
	if err := json.Unmarshal([]byte(stdout), &findings); err != nil {
		t.Fatalf("decode findings JSON %q: %v", stdout, err)
	}
	if len(findings) != 1 || findings[0].ID != "GHSA-TEST-0001" ||
		!findings[0].KnownExploited || findings[0].KEV == nil ||
		findings[0].KEV.CVEID != "CVE-2026-12345" {
		t.Fatalf("KEV-enriched findings = %+v", findings)
	}
}

func TestCISAKEVFailurePreservesLastSuccessfulIntelligence(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "psirtmap.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:pkg@1.0": {vulnerabilities: []osv.Vulnerability{{
			ID: "CVE-2026-11111",
		}}},
	}}
	kevFetcher := &inventoryKEVFetcher{catalog: kev.Catalog{
		CatalogVersion: "1",
		DateReleased:   "2026-10-01T12:00:00Z",
		Count:          1,
		Vulnerabilities: []kev.Vulnerability{{
			CVEID:             "CVE-2026-11111",
			VendorProject:     "Vendor",
			Product:           "Package",
			VulnerabilityName: "Known exploited test",
			DateAdded:         "2026-10-01",
			ShortDescription:  "Test record.",
			RequiredAction:    "Apply mitigations.",
			DueDate:           "2026-10-22",
		}},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "Gateway"},
		{"release", "add", "Gateway", "1.0"},
		{"component", "add", "Gateway@1.0", "pkg@1.0", "--ecosystem", "npm"},
		{"sync"},
	} {
		exitCode, _, stderr := runWithSourcesDatabase(t, path, querier, kevFetcher, arguments...)
		requireSuccess(t, exitCode, stderr)
	}

	querier.mu.Lock()
	querier.results["npm:pkg@1.0"] = packageResult{vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-22222"}}}
	querier.mu.Unlock()
	kevFetcher.err = errors.New("CISA unavailable")

	exitCode, _, stderr := runWithSourcesDatabase(t, path, querier, kevFetcher, "sync")
	if exitCode != 1 || !strings.Contains(stderr, "CISA unavailable") {
		t.Fatalf("failed sync = code %d, stderr %q", exitCode, stderr)
	}
	exitCode, stdout, stderr := runWithSourcesDatabase(t, path, querier, kevFetcher, "scan", "Gateway@1.0")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "CVE-2026-11111") || !strings.Contains(stdout, "YES") || strings.Contains(stdout, "CVE-2026-22222") {
		t.Fatalf("scan after failed KEV update = %q", stdout)
	}
}

func TestOfflineFeedExportImportWorkflow(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	sourceDB := filepath.Join(directory, "connected.db")
	targetDB := filepath.Join(directory, "isolated.db")
	bundlePath := filepath.Join(directory, "transfer.bundle")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:demo@1.0.0": {vulnerabilities: []osv.Vulnerability{{
			ID: "GHSA-DEMO-2026", Aliases: []string{"CVE-2026-12345"},
			Summary: "Portable test vulnerability",
		}}},
	}}
	kevFetcher := &inventoryKEVFetcher{catalog: kev.Catalog{
		CatalogVersion: "2026.10.01",
		DateReleased:   time.Now().UTC().Add(-time.Hour).Format(time.RFC3339),
		Count:          1,
		Vulnerabilities: []kev.Vulnerability{{
			CVEID: "CVE-2026-12345", VendorProject: "Example", Product: "Demo",
			VulnerabilityName: "Portable test vulnerability", DateAdded: "2026-09-01",
			ShortDescription: "Example", RequiredAction: "Apply update",
			DueDate: "2026-10-01",
		}},
		SourceURL: "https://example.test/kev.json",
	}}

	for _, command := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "demo@1.0.0", "--ecosystem", "npm"},
	} {
		exitCode, _, stderr := runWithSourcesDatabase(t, sourceDB, querier, kevFetcher, command...)
		requireSuccess(t, exitCode, stderr)
	}
	exitCode, stdout, stderr := runWithSourcesDatabase(t, sourceDB, querier, kevFetcher, "feed", "pull")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "CISA KEV         ready") {
		t.Fatalf("feed pull stdout = %q", stdout)
	}
	exitCode, stdout, stderr = runWithSourcesDatabase(t, sourceDB, nil, nil, "feed", "export", bundlePath)
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"OFFLINE FEED EXPORTED", "Packages         1", "Vulnerabilities  1", "KEV entries      1"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("feed export stdout = %q, want %q", stdout, expected)
		}
	}

	for _, command := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "demo@1.0.0", "--ecosystem", "npm"},
	} {
		exitCode, _, stderr = runWithSourcesDatabase(t, targetDB, nil, nil, command...)
		requireSuccess(t, exitCode, stderr)
	}
	exitCode, stdout, stderr = runWithSourcesDatabase(t, targetDB, nil, nil, "feed", "import", bundlePath)
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"OFFLINE FEED IMPORTED", "SHA-256 checksums verified", "Packages         1", "KEV entries      1"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("feed import stdout = %q, want %q", stdout, expected)
		}
	}
	exitCode, stdout, stderr = runWithSourcesDatabase(t, targetDB, nil, nil, "scan", "gateway@1.0")
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"GHSA-DEMO-2026", "Known exploited  1", "YES"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("offline scan stdout = %q, want %q", stdout, expected)
		}
	}
}

func TestInventoryJSONOutputIsStable(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.db")
	querier := &inventoryQuerier{results: map[string]packageResult{}}
	exitCode, stdout, stderr := runWithDatabase(
		t, path, querier, "product", "add", "Gateway", "--json",
	)
	requireSuccess(t, exitCode, stderr)
	var product map[string]any
	if err := json.Unmarshal([]byte(stdout), &product); err != nil {
		t.Fatalf("decode product JSON %q: %v", stdout, err)
	}
	if product["name"] != "Gateway" {
		t.Fatalf("product JSON = %#v", product)
	}

	exitCode, _, stderr = runWithDatabase(t, path, querier, "release", "add", "Gateway", "1.0")
	requireSuccess(t, exitCode, stderr)
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "scan", "Gateway@1.0", "--json")
	requireSuccess(t, exitCode, stderr)
	var scan struct {
		Product    string            `json:"product"`
		Release    string            `json:"release"`
		Components int               `json:"components"`
		Findings   []json.RawMessage `json:"findings"`
	}
	if err := json.Unmarshal([]byte(stdout), &scan); err != nil {
		t.Fatalf("decode scan JSON %q: %v", stdout, err)
	}
	if scan.Product != "Gateway" || scan.Release != "1.0" || scan.Components != 0 || scan.Findings == nil {
		t.Fatalf("scan JSON = %+v", scan)
	}
}

func TestReleaseImportCycloneDXWorkflow(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.db")
	querier := &inventoryQuerier{results: map[string]packageResult{}}
	example := filepath.Join("..", "..", "examples", "ag-200", "firmware-2.2.cdx.json")

	exitCode, _, stderr := runWithDatabase(t, path, querier, "product", "add", "AG-200")
	requireSuccess(t, exitCode, stderr)
	exitCode, stdout, stderr := runWithDatabase(t, path, querier, "release", "import", "AG-200@2.2", example)
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{
		"CycloneDX JSON detected", "Release created: yes", "Components discovered: 3",
		"Imported:              3", "Skipped:               0",
	} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("release import stdout = %q, want %q", stdout, expected)
		}
	}

	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "component", "list", "AG-200@2.2", "--json")
	requireSuccess(t, exitCode, stderr)
	var components []struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
		PURL      string `json:"purl"`
	}
	if err := json.Unmarshal([]byte(stdout), &components); err != nil {
		t.Fatalf("decode imported components %q: %v", stdout, err)
	}
	if len(components) != 3 || components[0].Ecosystem != "Alpine" || !strings.HasPrefix(components[0].PURL, "pkg:apk/alpine/") {
		t.Fatalf("imported components = %+v", components)
	}

	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "release", "import", "AG-200@2.2", example, "--json")
	requireSuccess(t, exitCode, stderr)
	var second struct {
		CreatedRelease bool `json:"created_release"`
		Imported       int  `json:"imported"`
		AlreadyPresent int  `json:"already_present"`
	}
	if err := json.Unmarshal([]byte(stdout), &second); err != nil {
		t.Fatalf("decode repeated import %q: %v", stdout, err)
	}
	if second.CreatedRelease || second.Imported != 0 || second.AlreadyPresent != 3 {
		t.Fatalf("repeated import = %+v", second)
	}
}

func TestReleaseImportRejectsInvalidSBOMWithoutCreatingRelease(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	databasePath := filepath.Join(directory, "inventory.db")
	invalidPath := filepath.Join(directory, "invalid.cdx.json")
	if err := os.WriteFile(invalidPath, []byte(`{"bomFormat":"SPDX","specVersion":"1.6","version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	querier := &inventoryQuerier{}
	exitCode, _, stderr := runWithDatabase(t, databasePath, querier, "product", "add", "AG-200")
	requireSuccess(t, exitCode, stderr)
	exitCode, _, stderr = runWithDatabase(t, databasePath, querier, "release", "import", "AG-200@2.2", invalidPath)
	if exitCode != 1 || !strings.Contains(stderr, "expected CycloneDX") {
		t.Fatalf("invalid import = code %d, stderr %q", exitCode, stderr)
	}
	exitCode, stdout, stderr := runWithDatabase(t, databasePath, querier, "release", "list", "AG-200", "--json")
	requireSuccess(t, exitCode, stderr)
	if strings.TrimSpace(stdout) != "[]" {
		t.Fatalf("failed import created release: %q", stdout)
	}
}

func TestInventoryCLIReportsConflictsAndMissingParents(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.db")
	querier := &inventoryQuerier{}
	exitCode, _, stderr := runWithDatabase(t, path, querier, "product", "add", "AG-200")
	requireSuccess(t, exitCode, stderr)

	exitCode, _, stderr = runWithDatabase(t, path, querier, "product", "add", "ag-200")
	if exitCode != 1 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("duplicate product = code %d, stderr %q", exitCode, stderr)
	}
	exitCode, _, stderr = runWithDatabase(t, path, querier, "release", "add", "missing", "1.0")
	if exitCode != 1 || !strings.Contains(stderr, "not found") {
		t.Fatalf("missing product = code %d, stderr %q", exitCode, stderr)
	}
	exitCode, _, stderr = runWithDatabase(t, path, querier, "component", "list", "bad-reference")
	if exitCode != 2 || !strings.Contains(stderr, "expected name@version") {
		t.Fatalf("bad reference = code %d, stderr %q", exitCode, stderr)
	}
}

func TestScanReportsComponentQueryFailure(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"PyPI:jinja2@2.4.1": {err: errors.New("network unavailable")},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "jinja2@2.4.1", "-e", "PyPI"},
	} {
		exitCode, _, stderr := runWithDatabase(t, path, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}

	exitCode, _, stderr := runWithDatabase(t, path, querier, "scan", "gateway@1.0", "--live")
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	for _, expected := range []string{"PyPI", "jinja2@2.4.1", "network unavailable"} {
		if !strings.Contains(stderr, expected) {
			t.Errorf("stderr = %q, want %q", stderr, expected)
		}
	}
}

func TestSyncFailurePreservesPreviousLocalSnapshot(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:pkg@1.0": {vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-OLD"}}},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "pkg@1.0", "-e", "npm"},
		{"sync"},
	} {
		exitCode, _, stderr := runWithDatabase(t, path, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}

	querier.mu.Lock()
	querier.results["npm:pkg@1.0"] = packageResult{err: errors.New("OSV unavailable")}
	querier.mu.Unlock()
	exitCode, _, stderr := runWithDatabase(t, path, querier, "sync")
	if exitCode != 1 || !strings.Contains(stderr, "OSV unavailable") {
		t.Fatalf("failed sync = code %d, stderr %q", exitCode, stderr)
	}

	exitCode, stdout, stderr := runWithDatabase(t, path, querier, "scan", "gateway@1.0", "--json")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, `"id": "CVE-2026-OLD"`) || !strings.Contains(stdout, `"data_source": "local-osv-snapshot"`) {
		t.Fatalf("local scan after failed sync = %q", stdout)
	}
}

func TestScanRequiresLocalSnapshotUnlessLive(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:pkg@1.0": {vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-LIVE"}}},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "pkg@1.0", "-e", "npm"},
	} {
		exitCode, _, stderr := runWithDatabase(t, path, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}

	exitCode, _, stderr := runWithDatabase(t, path, querier, "scan", "gateway@1.0")
	if exitCode != 1 || !strings.Contains(stderr, "run \"psirtmap sync\"") {
		t.Fatalf("unsynchronized scan = code %d, stderr %q", exitCode, stderr)
	}
	exitCode, stdout, stderr := runWithDatabase(t, path, querier, "scan", "--live", "gateway@1.0")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "OSV live query") || !strings.Contains(stdout, "CVE-2026-LIVE") {
		t.Fatalf("live scan stdout = %q", stdout)
	}
}

func TestLocalScanPersistsFindingLifecycleAndLiveScanDoesNot(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "inventory.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:pkg@1.0": {vulnerabilities: []osv.Vulnerability{{
			ID: "CVE-2026-PERSISTED", Aliases: []string{"GHSA-persisted"}, Summary: "stored match",
		}}},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "pkg@1.0", "-e", "npm"},
		{"sync"},
	} {
		exitCode, _, stderr := runWithDatabase(t, path, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}

	exitCode, stdout, stderr := runWithDatabase(t, path, querier, "scan", "gateway@1.0")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "New 1  Existing 0  Reopened 0  No longer matched 0") {
		t.Fatalf("first scan stdout = %q", stdout)
	}
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "scan", "gateway@1.0")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "New 0  Existing 1  Reopened 0  No longer matched 0") {
		t.Fatalf("second scan stdout = %q", stdout)
	}
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "findings", "gateway@1.0", "--json")
	requireSuccess(t, exitCode, stderr)
	var active []struct {
		ID     string `json:"id"`
		Status string `json:"status"`
		Active bool   `json:"active"`
	}
	if err := json.Unmarshal([]byte(stdout), &active); err != nil {
		t.Fatalf("decode active findings %q: %v", stdout, err)
	}
	if len(active) != 1 || active[0].ID != "CVE-2026-PERSISTED" || active[0].Status != "needs-review" || !active[0].Active {
		t.Fatalf("active findings = %+v", active)
	}

	querier.mu.Lock()
	querier.results["npm:pkg@1.0"] = packageResult{vulnerabilities: []osv.Vulnerability{}}
	querier.mu.Unlock()
	for _, arguments := range [][]string{{"sync"}, {"scan", "gateway@1.0"}} {
		exitCode, stdout, stderr = runWithDatabase(t, path, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}
	if !strings.Contains(stdout, "No longer matched 1") || !strings.Contains(stdout, "No known vulnerabilities found") {
		t.Fatalf("closing scan stdout = %q", stdout)
	}
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "findings")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "No active findings found") {
		t.Fatalf("active findings stdout = %q", stdout)
	}
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "findings", "--all")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "CVE-2026-PERSISTED") || !strings.Contains(stdout, "no-longer-matched") {
		t.Fatalf("historical findings stdout = %q", stdout)
	}

	querier.mu.Lock()
	querier.results["npm:pkg@1.0"] = packageResult{vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-PERSISTED"}}}
	querier.mu.Unlock()
	for _, arguments := range [][]string{{"sync"}, {"scan", "gateway@1.0"}} {
		exitCode, stdout, stderr = runWithDatabase(t, path, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}
	if !strings.Contains(stdout, "New 0  Existing 0  Reopened 1  No longer matched 0") {
		t.Fatalf("reopened scan stdout = %q", stdout)
	}

	querier.mu.Lock()
	querier.results["npm:pkg@1.0"] = packageResult{vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-LIVE-ONLY"}}}
	querier.mu.Unlock()
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "scan", "gateway@1.0", "--live")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "Live results are diagnostic and were not saved") {
		t.Fatalf("live scan stdout = %q", stdout)
	}
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "findings", "--all", "--json")
	requireSuccess(t, exitCode, stderr)
	if strings.Contains(stdout, "CVE-2026-LIVE-ONLY") || !strings.Contains(stdout, "CVE-2026-PERSISTED") {
		t.Fatalf("findings after live scan = %q", stdout)
	}
}

func TestAssessmentCLIRecordsFiltersAndShowsImmutableHistory(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "assessment.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:pkg@1.0": {vulnerabilities: []osv.Vulnerability{{
			ID: "CVE-2026-ASSESS", Summary: "human review required",
		}}},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "pkg@1.0", "-e", "npm"},
		{"sync"},
		{"scan", "gateway@1.0"},
	} {
		exitCode, _, stderr := runWithDatabase(t, path, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}

	exitCode, stdout, stderr := runWithDatabase(t, path, querier,
		"assess", "gateway@1.0", "CVE-2026-ASSESS",
		"--status", "investigating", "--reviewer", "emirhan",
	)
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"ASSESSMENT RECORDED", "investigating", "emirhan", "npm:pkg@1.0"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("investigating stdout = %q, want %q", stdout, expected)
		}
	}

	exitCode, _, stderr = runWithDatabase(t, path, querier,
		"assess", "gateway@1.0", "CVE-2026-ASSESS",
		"--status", "affected", "--reviewer", "emirhan",
	)
	if exitCode != 1 || !strings.Contains(stderr, "reason is required") {
		t.Fatalf("missing reason = code %d, stderr %q", exitCode, stderr)
	}

	exitCode, stdout, stderr = runWithDatabase(t, path, querier,
		"assess", "gateway@1.0", "CVE-2026-ASSESS",
		"--status=not-affected", "--reviewer=emirhan",
		"--reason=Feature disabled", "--evidence=SEC-123", "--json",
	)
	requireSuccess(t, exitCode, stderr)
	var latest struct {
		Status   string `json:"status"`
		Reason   string `json:"reason"`
		Evidence string `json:"evidence"`
	}
	if err := json.Unmarshal([]byte(stdout), &latest); err != nil {
		t.Fatalf("decode assessment %q: %v", stdout, err)
	}
	if latest.Status != "not-affected" || latest.Reason != "Feature disabled" || latest.Evidence != "SEC-123" {
		t.Fatalf("assessment = %+v", latest)
	}

	exitCode, stdout, stderr = runWithDatabase(t, path, querier,
		"findings", "gateway@1.0", "--status", "not-affected",
	)
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"CVE-2026-ASSESS", "not-affected", "matched"} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("filtered findings stdout = %q, want %q", stdout, expected)
		}
	}

	exitCode, stdout, stderr = runWithDatabase(t, path, querier,
		"assess", "history", "gateway@1.0", "CVE-2026-ASSESS", "--json",
	)
	requireSuccess(t, exitCode, stderr)
	var history []struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal([]byte(stdout), &history); err != nil {
		t.Fatalf("decode history %q: %v", stdout, err)
	}
	if len(history) != 2 || history[0].Status != "not-affected" || history[1].Status != "investigating" {
		t.Fatalf("history = %+v", history)
	}
	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "scan", "gateway@1.0")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "not-affected") || strings.Contains(stdout, "needs-review") {
		t.Fatalf("assessed rescan stdout = %q", stdout)
	}
}

func TestAssessmentCLIRequiresComponentWhenFindingIsAmbiguous(t *testing.T) {
	t.Parallel()

	path := filepath.Join(t.TempDir(), "ambiguous.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:pkg-a@1.0": {vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-SHARED"}}},
		"npm:pkg-b@2.0": {vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-SHARED"}}},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "pkg-a@1.0", "-e", "npm"},
		{"component", "add", "gateway@1.0", "pkg-b@2.0", "-e", "npm"},
		{"sync"},
		{"scan", "gateway@1.0"},
	} {
		exitCode, _, stderr := runWithDatabase(t, path, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}
	exitCode, _, stderr := runWithDatabase(t, path, querier,
		"assess", "gateway@1.0", "CVE-2026-SHARED",
		"--status", "investigating", "--reviewer", "emirhan",
	)
	if exitCode != 1 || !strings.Contains(stderr, "multiple components") {
		t.Fatalf("ambiguous assessment = code %d, stderr %q", exitCode, stderr)
	}
	exitCode, stdout, stderr := runWithDatabase(t, path, querier,
		"assess", "gateway@1.0", "CVE-2026-SHARED",
		"--status", "investigating", "--reviewer", "emirhan",
		"--component", "npm:pkg-a@1.0",
	)
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "npm:pkg-a@1.0") {
		t.Fatalf("component assessment stdout = %q", stdout)
	}
}

func TestGlobalDatabaseOptionValidation(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := cli.Run(
		context.Background(),
		[]string{"--database=", "product", "list"},
		&stdout,
		&stderr,
		&inventoryQuerier{},
	)
	if exitCode != 2 || !strings.Contains(stderr.String(), "database path cannot be empty") {
		t.Fatalf("exit code = %d, stderr = %q", exitCode, stderr.String())
	}
}

func TestInventoryHelpDoesNotCreateDatabase(t *testing.T) {
	t.Parallel()

	for _, command := range []string{"init", "product", "release", "component", "sync", "feed", "scan", "findings", "assess", "dashboard", "ui"} {
		command := command
		t.Run(command, func(t *testing.T) {
			t.Parallel()
			path := filepath.Join(t.TempDir(), "should-not-exist.db")
			exitCode, stdout, stderr := runWithDatabase(t, path, &inventoryQuerier{}, command, "--help")
			requireSuccess(t, exitCode, stderr)
			if !strings.Contains(stdout, "Usage:") {
				t.Fatalf("help stdout = %q", stdout)
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("help created database %q; stat error = %v", path, err)
			}
		})
	}
}

func TestRootCommandsAndUsageErrors(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		args       []string
		wantCode   int
		wantOutput string
		useStderr  bool
	}{
		{name: "root help", args: []string{"--help"}, wantCode: 0, wantOutput: "Inventory commands:"},
		{name: "version", args: []string{"version"}, wantCode: 0, wantOutput: "0.0.9"},
		{name: "unknown", args: []string{"wat"}, wantCode: 2, wantOutput: "unknown command", useStderr: true},
		{name: "missing database value", args: []string{"--database"}, wantCode: 2, wantOutput: "requires a value", useStderr: true},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout bytes.Buffer
			var stderr bytes.Buffer
			exitCode := cli.Run(context.Background(), test.args, &stdout, &stderr, &inventoryQuerier{})
			if exitCode != test.wantCode {
				t.Fatalf("exit code = %d, want %d", exitCode, test.wantCode)
			}
			output := stdout.String()
			if test.useStderr {
				output = stderr.String()
			}
			if !strings.Contains(output, test.wantOutput) {
				t.Fatalf("output = %q, want %q", output, test.wantOutput)
			}
		})
	}
}
