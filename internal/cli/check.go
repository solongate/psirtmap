package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/solongate/psirtmap/internal/osv"
)

type checkOptions struct {
	packageName string
	version     string
	ecosystem   string
	jsonOutput  bool
	help        bool
}

func runCheck(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	querier VulnerabilityQuerier,
) int {
	options, err := parseCheckOptions(args)
	if err != nil {
		return usageError(stderr, err, printCheckUsage)
	}
	if options.help {
		printCheckUsage(stdout)
		return 0
	}
	if querier == nil {
		return commandError(stderr, errors.New("vulnerability service is unavailable"))
	}

	vulnerabilities, err := querier.Query(ctx, osv.Package{
		Name:      options.packageName,
		Ecosystem: options.ecosystem,
	}, options.version)
	if err != nil {
		return commandError(stderr, err)
	}

	if options.jsonOutput {
		return printJSON(stdout, stderr, checkResult{
			Package:         options.packageName,
			Version:         options.version,
			Ecosystem:       options.ecosystem,
			Vulnerabilities: nonNilVulnerabilities(vulnerabilities),
		})
	}
	printTextResult(stdout, options, vulnerabilities)
	return 0
}

func parseCheckOptions(args []string) (checkOptions, error) {
	var options checkOptions
	var positional []string

	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--help" || argument == "-h":
			options.help = true
		case argument == "--json":
			options.jsonOutput = true
		case argument == "--ecosystem" || argument == "-e":
			if index+1 >= len(args) {
				return options, fmt.Errorf("%s requires a value", argument)
			}
			index++
			options.ecosystem = args[index]
		case strings.HasPrefix(argument, "--ecosystem="):
			options.ecosystem = strings.TrimPrefix(argument, "--ecosystem=")
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown option %q", argument)
		default:
			positional = append(positional, argument)
		}
	}

	if options.help {
		return options, nil
	}
	if len(positional) != 2 {
		return options, errors.New("check requires a package and version")
	}
	if strings.TrimSpace(options.ecosystem) == "" {
		return options, errors.New("--ecosystem is required (for example: PyPI, npm, Go)")
	}

	options.packageName = strings.TrimSpace(positional[0])
	options.version = strings.TrimSpace(positional[1])
	options.ecosystem = strings.TrimSpace(options.ecosystem)
	for _, target := range []struct {
		label string
		value string
	}{
		{label: "package", value: options.packageName},
		{label: "version", value: options.version},
		{label: "ecosystem", value: options.ecosystem},
	} {
		if err := validateCLIIdentifier(target.label, target.value); err != nil {
			return options, err
		}
	}
	return options, nil
}

type checkResult struct {
	Package         string              `json:"package"`
	Version         string              `json:"version"`
	Ecosystem       string              `json:"ecosystem"`
	Vulnerabilities []osv.Vulnerability `json:"vulnerabilities"`
}

func printJSON(stdout io.Writer, stderr io.Writer, value any) int {
	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(value); err != nil {
		fmt.Fprintf(stderr, "Error: write JSON output: %v\n", err)
		return 1
	}
	return 0
}

func nonNilVulnerabilities(vulnerabilities []osv.Vulnerability) []osv.Vulnerability {
	if vulnerabilities == nil {
		return []osv.Vulnerability{}
	}
	return vulnerabilities
}

func printTextResult(stdout io.Writer, options checkOptions, vulnerabilities []osv.Vulnerability) {
	fmt.Fprintf(stdout, "Package: %s@%s\n", options.packageName, options.version)
	fmt.Fprintf(stdout, "Ecosystem: %s\n\n", options.ecosystem)

	if len(vulnerabilities) == 0 {
		fmt.Fprintln(stdout, "No known vulnerabilities found.")
		return
	}

	recordLabel := "records"
	if len(vulnerabilities) == 1 {
		recordLabel = "record"
	}
	fmt.Fprintf(stdout, "Found %d OSV vulnerability %s.\n", len(vulnerabilities), recordLabel)
	for _, vulnerability := range vulnerabilities {
		fmt.Fprintf(stdout, "\n%s\n", oneLine(vulnerability.ID))
		if vulnerability.Summary != "" {
			fmt.Fprintf(stdout, "  %s\n", oneLine(vulnerability.Summary))
		}
		if len(vulnerability.Aliases) > 0 {
			fmt.Fprintf(stdout, "  Aliases: %s\n", oneLine(strings.Join(vulnerability.Aliases, ", ")))
		}
		fmt.Fprintf(stdout, "  https://osv.dev/vulnerability/%s\n", url.PathEscape(vulnerability.ID))
	}
}

func oneLine(value string) string {
	value = strings.Map(func(character rune) rune {
		if unicode.IsControl(character) {
			return ' '
		}
		return character
	}, value)
	return strings.Join(strings.Fields(value), " ")
}

func validateCLIIdentifier(label, value string) error {
	if value == "" {
		return fmt.Errorf("%s cannot be empty", label)
	}
	if !utf8.ValidString(value) {
		return fmt.Errorf("%s must be valid UTF-8", label)
	}
	if utf8.RuneCountInString(value) > 1024 {
		return fmt.Errorf("%s exceeds 1024 characters", label)
	}
	if strings.IndexFunc(value, unicode.IsControl) >= 0 {
		return fmt.Errorf("%s cannot contain control characters", label)
	}
	return nil
}
