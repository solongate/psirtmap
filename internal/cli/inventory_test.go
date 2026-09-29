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

	"github.com/solongate/psirtmap/internal/cli"
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

	exitCode, stdout, stderr = runWithDatabase(t, path, querier, "scan", "AG-200@2.2")
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"POTENTIAL FINDINGS\n2", "OSV-2026-A", "OSV-2026-B", "needs-review"} {
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

	exitCode, _, stderr := runWithDatabase(t, path, querier, "scan", "gateway@1.0")
	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	for _, expected := range []string{"PyPI", "jinja2@2.4.1", "network unavailable"} {
		if !strings.Contains(stderr, expected) {
			t.Errorf("stderr = %q, want %q", stderr, expected)
		}
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

	for _, command := range []string{"init", "product", "release", "component", "scan", "dashboard", "ui"} {
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
		{name: "version", args: []string{"version"}, wantCode: 0, wantOutput: "0.0.3"},
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
