// SPDX-License-Identifier: Apache-2.0
// Copyright (c) PSIRTMap contributors

package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"time"

	"github.com/solongate/psirtmap/internal/store"
	"github.com/solongate/psirtmap/internal/vex"
)

func runVEX(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
) int {
	if len(args) == 0 || (len(args) == 1 && (isHelp(args[0]) || args[0] == "help")) {
		printVEXUsage(stdout)
		return 0
	}
	if args[0] != "export" {
		return usageError(stderr, fmt.Errorf("unknown vex command %q", args[0]), printVEXUsage)
	}
	return runVEXExport(ctx, args[1:], stdout, stderr, database)
}

func runVEXExport(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
) int {
	positionals, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printVEXUsage)
	}
	if help {
		printVEXUsage(stdout)
		return 0
	}
	if len(positionals) < 1 || len(positionals) > 2 {
		return usageError(stderr, errors.New("vex export requires a product@release and optional output path"), printVEXUsage)
	}
	product, releaseVersion, err := splitReference(positionals[0], "release")
	if err != nil {
		return usageError(stderr, err, printVEXUsage)
	}
	outputPath := vex.DefaultFilename(product, releaseVersion)
	if len(positionals) == 2 {
		outputPath = strings.TrimSpace(positionals[1])
		if outputPath == "" {
			return usageError(stderr, errors.New("VEX output path cannot be empty"), printVEXUsage)
		}
	}

	generatedAt := time.Now().UTC().Truncate(time.Second)
	summary, err := exportVEXRelease(ctx, database, product, releaseVersion, outputPath, generatedAt)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, summary)
	}
	fmt.Fprintln(stdout, "VEX EXPORTED")
	fmt.Fprintf(stdout, "Release:         %s@%s\n", summary.Product, summary.Release)
	fmt.Fprintf(stdout, "Format:          CycloneDX %s JSON\n", summary.SpecVersion)
	fmt.Fprintf(stdout, "Components:      %d\n", summary.Components)
	historyUnit := "entries"
	if summary.AssessmentHistoryEntries == 1 {
		historyUnit = "entry"
	}
	fmt.Fprintf(stdout, "Decisions:       %d current (%d history %s)\n", summary.AssessmentsExported, summary.AssessmentHistoryEntries, historyUnit)
	fmt.Fprintf(stdout, "Vulnerabilities: %d\n", summary.Vulnerabilities)
	fmt.Fprintf(stdout, "Output:          %s\n", summary.Path)
	return 0
}

func exportVEXRelease(
	ctx context.Context,
	database *store.DB,
	product string,
	releaseVersion string,
	outputPath string,
	generatedAt time.Time,
) (vex.Summary, error) {
	outputPath = strings.TrimSpace(outputPath)
	if outputPath == "" {
		return vex.Summary{}, errors.New("VEX output path is required")
	}
	absolutePath, err := filepath.Abs(outputPath)
	if err != nil {
		return vex.Summary{}, fmt.Errorf("resolve VEX output path: %w", err)
	}
	release, err := database.GetRelease(ctx, product, releaseVersion)
	if err != nil {
		return vex.Summary{}, err
	}
	components, err := database.ListComponents(ctx, product, releaseVersion)
	if err != nil {
		return vex.Summary{}, err
	}
	findings, err := database.ListFindings(ctx, store.FindingFilter{
		Product: product, Release: releaseVersion, IncludeInactive: true,
	})
	if err != nil {
		return vex.Summary{}, err
	}
	assessments, err := database.ListAssessments(ctx, store.AssessmentFilter{
		Product: product, Release: releaseVersion,
	})
	if err != nil {
		return vex.Summary{}, err
	}
	document, err := vex.Build(
		release, components, findings, assessments, version, generatedAt, "",
	)
	if err != nil {
		return vex.Summary{}, err
	}
	if err := vex.Write(outputPath, document.BOM); err != nil {
		return vex.Summary{}, err
	}
	return vex.Summary{
		Format: "CycloneDX", SpecVersion: vex.SpecVersion,
		Product: release.Product, Release: release.Version, Path: absolutePath,
		Components: document.Components, Vulnerabilities: document.Vulnerabilities,
		AssessmentsExported:      document.AssessmentsExported,
		AssessmentHistoryEntries: document.AssessmentHistoryEntries,
		GeneratedAt:              generatedAt,
	}, nil
}
