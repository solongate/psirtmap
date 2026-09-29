package cli_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/solongate/psirtmap/internal/cli"
	"github.com/solongate/psirtmap/internal/osv"
)

type fakeQuerier struct {
	packageValue osv.Package
	version      string
	result       []osv.Vulnerability
	err          error
}

func (f *fakeQuerier) Query(_ context.Context, pkg osv.Package, version string) ([]osv.Vulnerability, error) {
	f.packageValue = pkg
	f.version = version
	return f.result, f.err
}

func TestRunCheckPrintsVulnerabilities(t *testing.T) {
	t.Parallel()

	querier := &fakeQuerier{result: []osv.Vulnerability{{
		ID:      "PYSEC-2021-13",
		Summary: "A vulnerability in Jinja2",
		Aliases: []string{"CVE-2020-28493"},
	}}}
	var stdout bytes.Buffer
	var stderr bytes.Buffer

	exitCode := cli.Run(
		context.Background(),
		[]string{"check", "jinja2", "2.4.1", "--ecosystem", "PyPI"},
		&stdout,
		&stderr,
		querier,
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if querier.packageValue.Name != "jinja2" || querier.packageValue.Ecosystem != "PyPI" {
		t.Fatalf("package = %+v", querier.packageValue)
	}
	if querier.version != "2.4.1" {
		t.Fatalf("version = %q, want 2.4.1", querier.version)
	}
	for _, expected := range []string{"Found 1 OSV vulnerability record.", "PYSEC-2021-13", "CVE-2020-28493"} {
		if !strings.Contains(stdout.String(), expected) {
			t.Errorf("stdout = %q, want it to contain %q", stdout.String(), expected)
		}
	}
}

func TestRunCheckRequiresEcosystem(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := cli.Run(
		context.Background(),
		[]string{"check", "jinja2", "2.4.1"},
		&stdout,
		&stderr,
		&fakeQuerier{},
	)

	if exitCode != 2 {
		t.Fatalf("exit code = %d, want 2", exitCode)
	}
	if !strings.Contains(stderr.String(), "--ecosystem is required") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunCheckReportsQueryError(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := cli.Run(
		context.Background(),
		[]string{"check", "jinja2", "2.4.1", "-e", "PyPI"},
		&stdout,
		&stderr,
		&fakeQuerier{err: errors.New("network unavailable")},
	)

	if exitCode != 1 {
		t.Fatalf("exit code = %d, want 1", exitCode)
	}
	if !strings.Contains(stderr.String(), "network unavailable") {
		t.Fatalf("stderr = %q", stderr.String())
	}
}

func TestRunCheckJSONUsesEmptyArrayForNoMatches(t *testing.T) {
	t.Parallel()

	var stdout bytes.Buffer
	var stderr bytes.Buffer
	exitCode := cli.Run(
		context.Background(),
		[]string{"check", "safe-package", "1.0.0", "--ecosystem=npm", "--json"},
		&stdout,
		&stderr,
		&fakeQuerier{},
	)

	if exitCode != 0 {
		t.Fatalf("exit code = %d, want 0; stderr = %q", exitCode, stderr.String())
	}
	if !strings.Contains(stdout.String(), `"vulnerabilities": []`) {
		t.Fatalf("stdout = %q", stdout.String())
	}
}
