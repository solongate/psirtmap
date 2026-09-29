// Package cli implements the PSIRTMap command-line interface.
package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/solongate/psirtmap/internal/osv"
)

const version = "0.0.1"

// VulnerabilityQuerier is implemented by the OSV client.
type VulnerabilityQuerier interface {
	Query(context.Context, osv.Package, string) ([]osv.Vulnerability, error)
}

// Run executes the CLI and returns a process exit code.
func Run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	querier VulnerabilityQuerier,
) int {
	if len(args) == 0 {
		printUsage(stdout)
		return 0
	}

	switch args[0] {
	case "check":
		return runCheck(ctx, args[1:], stdout, stderr, querier)
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	case "version", "--version":
		fmt.Fprintln(stdout, version)
		return 0
	default:
		fmt.Fprintf(stderr, "Error: unknown command %q\n\n", args[0])
		printUsage(stderr)
		return 2
	}
}

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
		fmt.Fprintf(stderr, "Error: %v\n\n", err)
		printCheckUsage(stderr)
		return 2
	}
	if options.help {
		printCheckUsage(stdout)
		return 0
	}

	vulnerabilities, err := querier.Query(ctx, osv.Package{
		Name:      options.packageName,
		Ecosystem: options.ecosystem,
	}, options.version)
	if err != nil {
		if errors.Is(err, context.Canceled) {
			fmt.Fprintln(stderr, "Error: request canceled")
		} else {
			fmt.Fprintf(stderr, "Error: %v\n", err)
		}
		return 1
	}

	if options.jsonOutput {
		return printJSONResult(stdout, stderr, options, vulnerabilities)
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

	options.packageName = positional[0]
	options.version = positional[1]
	return options, nil
}

type checkResult struct {
	Package         string              `json:"package"`
	Version         string              `json:"version"`
	Ecosystem       string              `json:"ecosystem"`
	Vulnerabilities []osv.Vulnerability `json:"vulnerabilities"`
}

func printJSONResult(
	stdout io.Writer,
	stderr io.Writer,
	options checkOptions,
	vulnerabilities []osv.Vulnerability,
) int {
	if vulnerabilities == nil {
		vulnerabilities = []osv.Vulnerability{}
	}

	encoder := json.NewEncoder(stdout)
	encoder.SetIndent("", "  ")
	err := encoder.Encode(checkResult{
		Package:         options.packageName,
		Version:         options.version,
		Ecosystem:       options.ecosystem,
		Vulnerabilities: vulnerabilities,
	})
	if err != nil {
		fmt.Fprintf(stderr, "Error: write JSON output: %v\n", err)
		return 1
	}
	return 0
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
		fmt.Fprintf(stdout, "\n%s\n", vulnerability.ID)
		if vulnerability.Summary != "" {
			fmt.Fprintf(stdout, "  %s\n", oneLine(vulnerability.Summary))
		}
		if len(vulnerability.Aliases) > 0 {
			fmt.Fprintf(stdout, "  Aliases: %s\n", strings.Join(vulnerability.Aliases, ", "))
		}
		fmt.Fprintf(stdout, "  https://osv.dev/vulnerability/%s\n", vulnerability.ID)
	}
}

func oneLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}

func printUsage(writer io.Writer) {
	fmt.Fprintln(writer, `PSIRTMap maps vulnerabilities to software you ship.

Usage:
  psirtmap <command>

Commands:
  check       Query OSV for a package version
  version     Print the PSIRTMap version

Run "psirtmap check --help" for command details.`)
}

func printCheckUsage(writer io.Writer) {
	fmt.Fprintln(writer, `Query OSV for known vulnerabilities affecting a package version.

Usage:
  psirtmap check <package> <version> --ecosystem <ecosystem> [--json]

Examples:
  psirtmap check jinja2 2.4.1 --ecosystem PyPI
  psirtmap check lodash 4.17.20 --ecosystem npm --json

OSV ecosystem names are case-sensitive.`)
}
