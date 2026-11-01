// SPDX-License-Identifier: Apache-2.0
// Copyright (c) PSIRTMap contributors

package cli_test

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/solongate/psirtmap/internal/osv"
)

func TestVEXExportCLIProducesReviewedReleaseDocument(t *testing.T) {
	t.Parallel()

	directory := t.TempDir()
	databasePath := filepath.Join(directory, "psirtmap.db")
	outputPath := filepath.Join(directory, "gateway-1.0.vex.cdx.json")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:pkg@1.0": {vulnerabilities: []osv.Vulnerability{{
			ID: "CVE-2026-VEX", Summary: "reviewed vulnerability", Aliases: []string{"GHSA-vex-test"},
		}}},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "pkg@1.0", "--ecosystem", "npm"},
		{"sync"},
		{"scan", "gateway@1.0"},
		{"assess", "gateway@1.0", "CVE-2026-VEX", "--status", "not-affected", "--reviewer", "emirhan", "--reason", "Feature disabled", "--evidence", "SEC-123"},
	} {
		exitCode, _, stderr := runWithDatabase(t, databasePath, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}

	exitCode, stdout, stderr := runWithDatabase(
		t, databasePath, querier, "vex", "export", "gateway@1.0", outputPath, "--json",
	)
	requireSuccess(t, exitCode, stderr)
	summary := requireJSONObjectKeys(t, stdout,
		"format", "spec_version", "product", "release", "path", "components",
		"vulnerabilities", "assessments_exported", "assessment_history_entries", "generated_at",
	)
	if summary["format"] != "CycloneDX" || summary["spec_version"] != "1.6" ||
		summary["assessments_exported"] != float64(1) {
		t.Fatalf("VEX summary = %+v", summary)
	}

	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatalf("ReadFile() error = %v", err)
	}
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		t.Fatalf("decode generated VEX: %v", err)
	}
	if bom.SpecVersion != cdx.SpecVersion1_6 || bom.Vulnerabilities == nil || len(*bom.Vulnerabilities) != 1 {
		t.Fatalf("generated BOM = %+v", bom)
	}
	vulnerability := (*bom.Vulnerabilities)[0]
	if vulnerability.ID != "CVE-2026-VEX" || vulnerability.Analysis == nil ||
		vulnerability.Analysis.State != cdx.IASNotAffected || vulnerability.Analysis.Detail != "Feature disabled" {
		t.Fatalf("generated vulnerability = %+v", vulnerability)
	}

	textOutputPath := filepath.Join(directory, "gateway-1.0-text.vex.cdx.json")
	exitCode, stdout, stderr = runWithDatabase(
		t, databasePath, querier, "vex", "export", "gateway@1.0", textOutputPath,
	)
	requireSuccess(t, exitCode, stderr)
	for _, expected := range []string{"VEX EXPORTED", "CycloneDX 1.6 JSON", "1 current (1 history entry)", textOutputPath} {
		if !strings.Contains(stdout, expected) {
			t.Errorf("text export stdout = %q, want %q", stdout, expected)
		}
	}

	exitCode, _, stderr = runWithDatabase(
		t, databasePath, querier, "vex", "export", "gateway@1.0", outputPath,
	)
	if exitCode != 1 || !strings.Contains(stderr, "already exists") {
		t.Fatalf("overwrite attempt = code %d, stderr %q", exitCode, stderr)
	}
}

func TestVEXExportCLIRequiresAnAssessment(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "psirtmap.db")
	querier := &inventoryQuerier{results: map[string]packageResult{
		"npm:pkg@1.0": {vulnerabilities: []osv.Vulnerability{{ID: "CVE-2026-UNREVIEWED"}}},
	}}
	for _, arguments := range [][]string{
		{"product", "add", "gateway"},
		{"release", "add", "gateway", "1.0"},
		{"component", "add", "gateway@1.0", "pkg@1.0", "--ecosystem", "npm"},
		{"sync"},
		{"scan", "gateway@1.0"},
	} {
		exitCode, _, stderr := runWithDatabase(t, databasePath, querier, arguments...)
		requireSuccess(t, exitCode, stderr)
	}
	outputPath := filepath.Join(t.TempDir(), "unreviewed.vex.cdx.json")
	exitCode, _, stderr := runWithDatabase(
		t, databasePath, querier, "vex", "export", "gateway@1.0", outputPath,
	)
	if exitCode != 1 || !strings.Contains(stderr, "no human assessments") {
		t.Fatalf("unreviewed export = code %d, stderr %q", exitCode, stderr)
	}
	if _, err := os.Stat(outputPath); !os.IsNotExist(err) {
		t.Fatalf("unreviewed export created output, stat error = %v", err)
	}
}

func TestVEXHelpDoesNotRequireDatabase(t *testing.T) {
	t.Parallel()

	databasePath := filepath.Join(t.TempDir(), "should-not-exist.db")
	exitCode, stdout, stderr := runWithDatabase(t, databasePath, &inventoryQuerier{}, "vex", "--help")
	requireSuccess(t, exitCode, stderr)
	if !strings.Contains(stdout, "CycloneDX VEX") {
		t.Fatalf("vex help = %q", stdout)
	}
	if _, err := os.Stat(databasePath); !os.IsNotExist(err) {
		t.Fatalf("vex help created database, stat error = %v", err)
	}
}
