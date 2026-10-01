package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/solongate/psirtmap/internal/store"
)

type findingsOptions struct {
	reference       string
	status          string
	jsonOutput      bool
	includeInactive bool
	help            bool
}

func runFindings(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
) int {
	options, err := parseFindingsOptions(args)
	if err != nil {
		return usageError(stderr, err, printFindingsUsage)
	}
	if options.help {
		printFindingsUsage(stdout)
		return 0
	}

	filter := store.FindingFilter{Status: options.status, IncludeInactive: options.includeInactive}
	if options.reference != "" {
		filter.Product, filter.Release, err = splitReference(options.reference, "release")
		if err != nil {
			return usageError(stderr, err, printFindingsUsage)
		}
		if _, err := database.GetRelease(ctx, filter.Product, filter.Release); err != nil {
			return commandError(stderr, err)
		}
	}
	findings, err := database.ListFindings(ctx, filter)
	if err != nil {
		return commandError(stderr, err)
	}
	if options.jsonOutput {
		return printJSON(stdout, stderr, findings)
	}
	if len(findings) == 0 {
		if options.includeInactive {
			fmt.Fprintln(stdout, "No findings found.")
		} else {
			fmt.Fprintln(stdout, "No active findings found.")
		}
		return 0
	}

	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tPRODUCT RELEASE\tCOMPONENT\tASSESSMENT\tMATCH\tFIRST SEEN\tLAST SEEN")
	for _, item := range findings {
		fmt.Fprintf(table, "%s\t%s@%s\t%s:%s@%s\t%s\t%s\t%s\t%s\n",
			oneLine(item.VulnerabilityID), item.Product, item.Release,
			item.Ecosystem, item.Component, item.ComponentVersion, item.Status, item.MatchStatus,
			item.FirstSeenAt.Format("2006-01-02 15:04Z"),
			item.LastSeenAt.Format("2006-01-02 15:04Z"),
		)
	}
	if err := table.Flush(); err != nil {
		return commandError(stderr, fmt.Errorf("write finding list: %w", err))
	}
	return 0
}

func parseFindingsOptions(args []string) (findingsOptions, error) {
	var options findingsOptions
	var positional []string
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case isHelp(argument):
			options.help = true
		case argument == "--json":
			options.jsonOutput = true
		case argument == "--all":
			options.includeInactive = true
		case argument == "--status":
			if index+1 >= len(args) {
				return options, errors.New("--status requires a value")
			}
			index++
			options.status = args[index]
		case strings.HasPrefix(argument, "--status="):
			options.status = strings.TrimPrefix(argument, "--status=")
		case strings.HasPrefix(argument, "-"):
			return options, fmt.Errorf("unknown option %q", argument)
		default:
			positional = append(positional, argument)
		}
	}
	if options.help {
		return options, nil
	}
	if len(positional) > 1 {
		return options, errors.New("findings accepts at most one product@release reference")
	}
	if len(positional) == 1 {
		options.reference = positional[0]
	}
	return options, nil
}
