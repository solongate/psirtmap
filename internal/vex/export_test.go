// SPDX-License-Identifier: Apache-2.0
// Copyright (c) PSIRTMap contributors

package vex

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/solongate/psirtmap/internal/osv"
	"github.com/solongate/psirtmap/internal/store"
)

func TestBuildMapsLatestAssessmentsToCycloneDXVEX(t *testing.T) {
	t.Parallel()

	first := time.Date(2026, time.September, 1, 10, 0, 0, 0, time.UTC)
	latest := first.Add(48 * time.Hour)
	generated := latest.Add(time.Hour)
	score := 9.3
	release := store.Release{Product: "AG-200", Version: "2.2"}
	components := []store.Component{
		{Ecosystem: "Alpine:v3.18", Name: "openssl", Version: "3.0.8", PURL: "pkg:apk/alpine/openssl@3.0.8?distro=alpine-3.18.0"},
		{Ecosystem: "npm", Name: "affected", Version: "1.0.0"},
		{Ecosystem: "npm", Name: "fixed", Version: "2.0.0"},
		{Ecosystem: "npm", Name: "triage", Version: "3.0.0"},
	}
	findings := []store.Finding{
		{FindingID: 4, Product: "AG-200", Release: "2.2", Ecosystem: "npm", Component: "triage", ComponentVersion: "3.0.0", VulnerabilityID: "CVE-2026-0004", Source: "OSV", MatchStatus: "matched", Active: true},
		{FindingID: 2, Product: "AG-200", Release: "2.2", Ecosystem: "npm", Component: "affected", ComponentVersion: "1.0.0", VulnerabilityID: "CVE-2026-0002", Source: "OSV", MatchStatus: "matched", Active: true},
		{FindingID: 1, Product: "AG-200", Release: "2.2", Ecosystem: "Alpine:v3.18", Component: "openssl", ComponentVersion: "3.0.8", VulnerabilityID: "CVE-2026-0001", Aliases: []string{"GHSA-example", "CVE-2026-0001"}, Summary: "OpenSSL test vulnerability", Severity: "critical", CVSSScore: &score, CVSSVersion: "4.0", CVSSVector: "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", Published: "2026-08-01T12:00:00Z", Modified: "2026-08-02T12:00:00Z", References: []osv.Reference{{Type: "ADVISORY", URL: "https://example.test/advisory"}}, Source: "OSV", MatchStatus: "no-longer-matched", Active: false, KnownExploited: true},
		{FindingID: 3, Product: "AG-200", Release: "2.2", Ecosystem: "npm", Component: "fixed", ComponentVersion: "2.0.0", VulnerabilityID: "CVE-2026-0003", Source: "OSV", MatchStatus: "matched", Active: true},
		{FindingID: 5, Product: "AG-200", Release: "2.2", Ecosystem: "npm", Component: "unreviewed", ComponentVersion: "4.0.0", VulnerabilityID: "CVE-2026-UNREVIEWED", Source: "OSV", MatchStatus: "matched", Active: true},
	}
	assessments := []store.Assessment{
		{AssessmentID: 2, FindingID: 1, Status: store.AssessmentNotAffected, Reason: "Feature disabled", Reviewer: "emirhan", Evidence: "SEC-123", AssessedAt: latest},
		{AssessmentID: 1, FindingID: 1, Status: store.AssessmentInvestigating, Reviewer: "emirhan", AssessedAt: first},
		{AssessmentID: 3, FindingID: 2, Status: store.AssessmentAffected, Reason: "Reachable vulnerable path", Reviewer: "reviewer", AssessedAt: latest},
		{AssessmentID: 4, FindingID: 3, Status: store.AssessmentFixed, Reason: "Fixed in firmware rebuild", Reviewer: "reviewer", AssessedAt: latest},
		{AssessmentID: 5, FindingID: 4, Status: store.AssessmentInvestigating, Reviewer: "reviewer", AssessedAt: latest},
	}

	document, err := Build(
		release, components, findings, assessments, "0.1.0", generated,
		"urn:uuid:11111111-2222-4333-8444-555555555555",
	)
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	if document.Components != 4 || document.Vulnerabilities != 4 ||
		document.AssessmentsExported != 4 || document.AssessmentHistoryEntries != 5 {
		t.Fatalf("document counts = %+v", document)
	}
	if document.BOM.SpecVersion != cdx.SpecVersion1_6 || document.BOM.JSONSchema != schemaURL {
		t.Fatalf("document schema = %s, spec = %s", document.BOM.JSONSchema, document.BOM.SpecVersion)
	}
	if document.BOM.Metadata == nil || document.BOM.Metadata.Component == nil ||
		document.BOM.Metadata.Component.Name != "AG-200" || document.BOM.Metadata.Component.Version != "2.2" {
		t.Fatalf("metadata component = %+v", document.BOM.Metadata)
	}
	if document.BOM.Metadata.Timestamp != generated.Format(time.RFC3339) {
		t.Fatalf("metadata timestamp = %q", document.BOM.Metadata.Timestamp)
	}
	if document.BOM.Metadata.Tools == nil || document.BOM.Metadata.Tools.Components == nil ||
		len(*document.BOM.Metadata.Tools.Components) != 1 || (*document.BOM.Metadata.Tools.Components)[0].Version != "0.1.0" {
		t.Fatalf("metadata tools = %+v", document.BOM.Metadata.Tools)
	}

	wantStates := map[string]cdx.ImpactAnalysisState{
		"CVE-2026-0001": cdx.IASNotAffected,
		"CVE-2026-0002": cdx.IASExploitable,
		"CVE-2026-0003": cdx.IASResolved,
		"CVE-2026-0004": cdx.IASInTriage,
	}
	if document.BOM.Vulnerabilities == nil {
		t.Fatal("Vulnerabilities is nil")
	}
	for index, vulnerability := range *document.BOM.Vulnerabilities {
		if index > 0 && (*document.BOM.Vulnerabilities)[index-1].ID > vulnerability.ID {
			t.Fatalf("vulnerabilities are not sorted: %+v", *document.BOM.Vulnerabilities)
		}
		if vulnerability.Analysis == nil || vulnerability.Analysis.State != wantStates[vulnerability.ID] {
			t.Fatalf("analysis for %s = %+v", vulnerability.ID, vulnerability.Analysis)
		}
		if vulnerability.Analysis.Justification != "" {
			t.Fatalf("analysis for %s inferred justification %q", vulnerability.ID, vulnerability.Analysis.Justification)
		}
	}

	firstVulnerability := (*document.BOM.Vulnerabilities)[0]
	if firstVulnerability.Analysis.Detail != "Feature disabled" ||
		firstVulnerability.Analysis.FirstIssued != first.Format(time.RFC3339) ||
		firstVulnerability.Analysis.LastUpdated != latest.Format(time.RFC3339) {
		t.Fatalf("latest analysis = %+v", firstVulnerability.Analysis)
	}
	if firstVulnerability.Ratings == nil || len(*firstVulnerability.Ratings) != 1 ||
		(*firstVulnerability.Ratings)[0].Method != cdx.ScoringMethodCVSSv4 {
		t.Fatalf("ratings = %+v", firstVulnerability.Ratings)
	}
	if firstVulnerability.Advisories == nil || len(*firstVulnerability.Advisories) != 1 {
		t.Fatalf("advisories = %+v", firstVulnerability.Advisories)
	}
	properties := propertyMap(*firstVulnerability.Properties)
	for name, want := range map[string]string{
		"psirtmap:assessment:status":        "not-affected",
		"psirtmap:assessment:reviewer":      "emirhan",
		"psirtmap:assessment:evidence":      "SEC-123",
		"psirtmap:finding:match-status":     "no-longer-matched",
		"psirtmap:finding:active":           "false",
		"psirtmap:cisa-kev:known-exploited": "true",
	} {
		if properties[name] != want {
			t.Errorf("property %s = %q, want %q", name, properties[name], want)
		}
	}
	if document.BOM.Components == nil || (*document.BOM.Components)[0].BOMRef == "" {
		t.Fatalf("components = %+v", document.BOM.Components)
	}
	foundPURLReference := false
	for _, component := range *document.BOM.Components {
		if component.PackageURL != "" && component.BOMRef == component.PackageURL {
			foundPURLReference = true
		}
	}
	if !foundPURLReference {
		t.Fatal("component with purl did not use purl as bom-ref")
	}
}

func TestBuildRejectsInvalidOrMissingAssessmentData(t *testing.T) {
	t.Parallel()

	release := store.Release{Product: "gateway", Version: "1.0"}
	finding := store.Finding{FindingID: 1, Product: "gateway", Release: "1.0", Ecosystem: "npm", Component: "pkg", ComponentVersion: "1.0", VulnerabilityID: "CVE-2026-1"}
	_, err := Build(release, nil, []store.Finding{finding}, nil, "test", time.Now(), "")
	if err == nil || !strings.Contains(err.Error(), "no human assessments") {
		t.Fatalf("missing assessment error = %v", err)
	}
	_, err = Build(release, nil, []store.Finding{finding}, []store.Assessment{{
		AssessmentID: 1, FindingID: 1, Status: "unknown", AssessedAt: time.Now(),
	}}, "test", time.Now(), "")
	if err == nil || !strings.Contains(err.Error(), "unsupported assessment status") {
		t.Fatalf("unsupported status error = %v", err)
	}
	_, err = Build(release, nil, []store.Finding{finding}, []store.Assessment{{
		AssessmentID: 1, FindingID: 1, Status: store.AssessmentAffected, AssessedAt: time.Now(),
	}}, "test", time.Now(), "urn:uuid:not-a-uuid")
	if err == nil || !strings.Contains(err.Error(), "valid UUID") {
		t.Fatalf("invalid serial error = %v", err)
	}
}

func TestWriteProducesCycloneDX16AndNeverOverwrites(t *testing.T) {
	t.Parallel()

	release := store.Release{Product: "gateway", Version: "1.0"}
	finding := store.Finding{FindingID: 1, Product: "gateway", Release: "1.0", Ecosystem: "npm", Component: "pkg", ComponentVersion: "1.0", VulnerabilityID: "CVE-2026-1", Source: "OSV", MatchStatus: "matched", Active: true}
	assessment := store.Assessment{AssessmentID: 1, FindingID: 1, Status: store.AssessmentInvestigating, Reviewer: "reviewer", AssessedAt: time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)}
	document, err := Build(release, nil, []store.Finding{finding}, []store.Assessment{assessment}, "test", assessment.AssessedAt, "urn:uuid:11111111-2222-4333-8444-555555555555")
	if err != nil {
		t.Fatalf("Build() error = %v", err)
	}
	path := filepath.Join(t.TempDir(), "gateway.vex.cdx.json")
	if err := Write(path, document.BOM); err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	for _, expected := range []string{`"bomFormat": "CycloneDX"`, `"specVersion": "1.6"`, `"state": "in_triage"`} {
		if !bytes.Contains(data, []byte(expected)) {
			t.Errorf("output missing %s:\n%s", expected, data)
		}
	}
	var decoded cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&decoded); err != nil {
		t.Fatalf("decode generated CycloneDX: %v", err)
	}
	if decoded.SpecVersion != cdx.SpecVersion1_6 || decoded.SerialNumber != document.BOM.SerialNumber {
		t.Fatalf("decoded BOM = spec %s serial %q", decoded.SpecVersion, decoded.SerialNumber)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if info.Mode().Perm()&0o077 != 0 {
		t.Fatalf("output permissions = %o, want private", info.Mode().Perm())
	}
	if err := Write(path, document.BOM); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Write() error = %v", err)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile() after second write error = %v", err)
	}
	if !bytes.Equal(data, after) {
		t.Fatal("existing VEX output changed after refused overwrite")
	}
}

func TestDefaultFilenameIsPortableAndBounded(t *testing.T) {
	t.Parallel()

	filename := DefaultFilename("Industrial Gateway / Europe", strings.Repeat("ü", 150))
	if strings.ContainsAny(filename, "/\\ ") || !strings.HasSuffix(filename, ".vex.cdx.json") {
		t.Fatalf("DefaultFilename() = %q", filename)
	}
	if len(filename) > 220 {
		t.Fatalf("DefaultFilename() length = %d", len(filename))
	}
}

func propertyMap(properties []cdx.Property) map[string]string {
	result := make(map[string]string, len(properties))
	for _, property := range properties {
		result[property.Name] = property.Value
	}
	return result
}
