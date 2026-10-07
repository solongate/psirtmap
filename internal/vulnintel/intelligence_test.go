package vulnintel

import (
	"reflect"
	"testing"

	"github.com/solongate/psirtmap/internal/osv"
)

func TestAnalyzeSelectsHighestCVSSAndContext(t *testing.T) {
	record := osv.Vulnerability{
		Published: "2026-01-02T03:04:05Z",
		Modified:  "2026-02-03T04:05:06Z",
		Severity: []osv.Severity{
			{Type: "CVSS_V3", Score: "CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N"},
			{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"},
		},
		Affected: []osv.Affected{{
			Package: osv.Package{Ecosystem: "Alpine", Name: "openssl"},
			Ranges:  []osv.Range{{Events: []osv.RangeEvent{{Fixed: "3.0.9"}, {Fixed: "3.0.10"}, {Fixed: "3.0.9"}}}},
		}},
		References: []osv.Reference{
			{Type: "ADVISORY", URL: "https://example.test/advisory"},
			{Type: "REPORT", URL: "javascript:alert(1)"},
		},
	}

	got := Analyze(record, "alpine", "OpenSSL")
	if got.CVSSScore == nil || *got.CVSSScore != 9.3 || got.Severity != SeverityCritical || got.CVSSVersion != "4.0" {
		t.Fatalf("Analyze() CVSS = %+v", got)
	}
	if !reflect.DeepEqual(got.FixedVersions, []string{"3.0.10", "3.0.9"}) {
		t.Fatalf("Analyze() fixed versions = %v", got.FixedVersions)
	}
	if len(got.References) != 1 || got.References[0].URL != "https://example.test/advisory" {
		t.Fatalf("Analyze() references = %+v", got.References)
	}
}

func TestAnalyzeLeavesInvalidOrMissingCVSSUnknown(t *testing.T) {
	got := Analyze(osv.Vulnerability{
		Severity: []osv.Severity{{Type: "CVSS_V3", Score: "not-a-vector"}},
	}, "npm", "left-pad")
	if got.CVSSScore != nil || got.Severity != SeverityUnknown {
		t.Fatalf("Analyze() = %+v", got)
	}
}

func TestAnalyzeSupportsDeclaredCVSSVersions(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name     string
		severity osv.Severity
		version  string
		label    string
		score    float64
	}{
		{name: "2.0", severity: osv.Severity{Type: "CVSS_V2", Score: "AV:N/AC:L/Au:N/C:C/I:C/A:C"}, version: "2.0", label: SeverityCritical, score: 10},
		{name: "3.0", severity: osv.Severity{Type: "CVSS_V3", Score: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, version: "3.0", label: SeverityCritical, score: 9.8},
		{name: "3.1", severity: osv.Severity{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}, version: "3.1", label: SeverityCritical, score: 9.8},
		{name: "4.0", severity: osv.Severity{Type: "CVSS_V4", Score: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}, version: "4.0", label: SeverityCritical, score: 9.3},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			got := Analyze(osv.Vulnerability{Severity: []osv.Severity{test.severity}}, "npm", "pkg")
			if got.CVSSScore == nil || *got.CVSSScore != test.score || got.CVSSVersion != test.version || got.Severity != test.label {
				t.Fatalf("Analyze() = %+v", got)
			}
		})
	}
}

func TestSeverityRank(t *testing.T) {
	ordered := []string{SeverityUnknown, SeverityNone, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
	for index, value := range ordered {
		if got := SeverityRank(value); got != index {
			t.Fatalf("SeverityRank(%q) = %d, want %d", value, got, index)
		}
	}
}
