package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"text/tabwriter"

	"github.com/solongate/psirtmap/internal/sbom"
	"github.com/solongate/psirtmap/internal/store"
)

type releaseImportOutput struct {
	Product              string                  `json:"product"`
	Release              string                  `json:"release"`
	CreatedRelease       bool                    `json:"created_release"`
	Source               string                  `json:"source"`
	Format               string                  `json:"format"`
	SpecVersion          string                  `json:"spec_version"`
	SerialNumber         string                  `json:"serial_number,omitempty"`
	DocumentSHA256       string                  `json:"document_sha256"`
	ComponentsDiscovered int                     `json:"components_discovered"`
	ImportCandidates     int                     `json:"import_candidates"`
	Imported             int                     `json:"imported"`
	AlreadyPresent       int                     `json:"already_present"`
	DuplicatesInSBOM     int                     `json:"duplicates_in_sbom"`
	Skipped              int                     `json:"skipped"`
	SkippedComponents    []sbom.SkippedComponent `json:"skipped_components"`
}

func runReleaseImport(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
) int {
	positional, jsonOutput, help, err := parseImportOptions(args)
	if err != nil {
		return usageError(stderr, err, printReleaseUsage)
	}
	if help {
		printReleaseUsage(stdout)
		return 0
	}
	if len(positional) != 2 {
		return usageError(stderr, errors.New("release import requires a product@release reference and CycloneDX JSON file"), printReleaseUsage)
	}
	productName, releaseVersion, err := splitReference(positional[0], "release")
	if err != nil {
		return usageError(stderr, err, printReleaseUsage)
	}
	sourcePath := positional[1]
	output, err := importReleaseSBOM(ctx, database, productName, releaseVersion, sourcePath)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, output)
	}
	return printReleaseImport(stdout, stderr, output)
}

func importReleaseSBOM(
	ctx context.Context,
	database *store.DB,
	productName string,
	releaseVersion string,
	sourcePath string,
) (releaseImportOutput, error) {
	report, err := sbom.ParseFile(sourcePath)
	if err != nil {
		return releaseImportOutput{}, err
	}
	if len(report.Components) == 0 {
		return releaseImportOutput{}, fmt.Errorf(
			"SBOM contains %d components but none have a supported package URL and version",
			report.Discovered,
		)
	}

	components := make([]store.ComponentInput, len(report.Components))
	for index, component := range report.Components {
		components[index] = store.ComponentInput{
			Ecosystem: component.Ecosystem,
			Name:      component.Name,
			Version:   component.Version,
			PURL:      component.PURL,
		}
	}
	result, err := database.ImportReleaseComponents(
		ctx,
		productName,
		releaseVersion,
		components,
		store.SBOMImportMetadata{
			Format:         report.Format,
			SpecVersion:    report.SpecVersion,
			SerialNumber:   report.SerialNumber,
			DocumentSHA256: report.DocumentSHA256,
			SourceName:     filepath.Base(sourcePath),
			Discovered:     report.Discovered,
			Skipped:        len(report.Skipped),
			Duplicates:     report.Duplicates,
		},
	)
	if err != nil {
		return releaseImportOutput{}, err
	}

	return releaseImportOutput{
		Product:              result.Product,
		Release:              result.ReleaseVersion,
		CreatedRelease:       result.CreatedRelease,
		Source:               sourcePath,
		Format:               report.Format,
		SpecVersion:          report.SpecVersion,
		SerialNumber:         report.SerialNumber,
		DocumentSHA256:       report.DocumentSHA256,
		ComponentsDiscovered: report.Discovered,
		ImportCandidates:     len(report.Components),
		Imported:             result.Imported,
		AlreadyPresent:       result.AlreadyPresent,
		DuplicatesInSBOM:     report.Duplicates,
		Skipped:              len(report.Skipped),
		SkippedComponents:    report.Skipped,
	}, nil
}

func parseImportOptions(args []string) (positional []string, jsonOutput bool, help bool, err error) {
	optionsEnded := false
	for _, argument := range args {
		switch {
		case !optionsEnded && argument == "--":
			optionsEnded = true
		case !optionsEnded && argument == "--json":
			jsonOutput = true
		case !optionsEnded && isHelp(argument):
			help = true
		case !optionsEnded && strings.HasPrefix(argument, "-"):
			return nil, false, false, fmt.Errorf("unknown option %q", argument)
		default:
			positional = append(positional, argument)
		}
	}
	return positional, jsonOutput, help, nil
}

func printReleaseImport(stdout io.Writer, stderr io.Writer, result releaseImportOutput) int {
	fmt.Fprintln(stdout, "✓ CycloneDX JSON detected")
	fmt.Fprintf(stdout, "\nProduct: %s\nRelease: %s\n", result.Product, result.Release)
	if result.CreatedRelease {
		fmt.Fprintln(stdout, "Release created: yes")
	} else {
		fmt.Fprintln(stdout, "Release created: no (existing release)")
	}
	fmt.Fprintf(stdout, "Source: %s\nCycloneDX spec: %s\nSHA-256: %s\n", oneLine(result.Source), result.SpecVersion, result.DocumentSHA256)
	fmt.Fprintf(stdout, `
Components discovered: %d
Import candidates:     %d
Imported:              %d
Already present:       %d
Duplicates in SBOM:    %d
Skipped:               %d
`, result.ComponentsDiscovered, result.ImportCandidates, result.Imported,
		result.AlreadyPresent, result.DuplicatesInSBOM, result.Skipped)

	if len(result.SkippedComponents) == 0 {
		return 0
	}
	fmt.Fprintln(stdout, "\nSkipped components:")
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "COMPONENT\tVERSION\tREASON")
	limit := min(10, len(result.SkippedComponents))
	for _, skipped := range result.SkippedComponents[:limit] {
		name := skipped.Name
		if name == "" {
			name = skipped.BOMRef
		}
		if name == "" {
			name = "(unnamed)"
		}
		fmt.Fprintf(table, "%s\t%s\t%s\n", oneLine(name), oneLine(skipped.Version), oneLine(skipped.Reason))
	}
	if err := table.Flush(); err != nil {
		return commandError(stderr, fmt.Errorf("write import summary: %w", err))
	}
	if len(result.SkippedComponents) > limit {
		fmt.Fprintf(stdout, "...and %d more skipped components. Use --json for the complete list.\n", len(result.SkippedComponents)-limit)
	}
	return 0
}
