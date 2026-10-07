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
	severity        string
	kevOnly         bool
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
	if len(args) > 0 && args[0] == "show" {
		return runFindingShow(ctx, args[1:], stdout, stderr, database)
	}
	options, err := parseFindingsOptions(args)
	if err != nil {
		return usageError(stderr, err, printFindingsUsage)
	}
	if options.help {
		printFindingsUsage(stdout)
		return 0
	}

	filter := store.FindingFilter{
		Status: options.status, Severity: options.severity,
		KnownExploitedOnly: options.kevOnly, IncludeInactive: options.includeInactive,
	}
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
	fmt.Fprintln(table, "ID\tSEVERITY\tPRODUCT RELEASE\tCOMPONENT\tKEV\tASSESSMENT\tMATCH\tFIRST SEEN\tLAST SEEN")
	for _, item := range findings {
		kevStatus := "-"
		if item.KnownExploited {
			kevStatus = "YES"
		}
		fmt.Fprintf(table, "%s\t%s\t%s@%s\t%s:%s@%s\t%s\t%s\t%s\t%s\t%s\n",
			oneLine(item.VulnerabilityID), strings.ToUpper(item.Severity), item.Product, item.Release,
			item.Ecosystem, item.Component, item.ComponentVersion, kevStatus, item.Status, item.MatchStatus,
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
		case argument == "--kev":
			options.kevOnly = true
		case argument == "--status":
			if index+1 >= len(args) {
				return options, errors.New("--status requires a value")
			}
			index++
			options.status = args[index]
		case strings.HasPrefix(argument, "--status="):
			options.status = strings.TrimPrefix(argument, "--status=")
		case argument == "--severity":
			if index+1 >= len(args) {
				return options, errors.New("--severity requires a value")
			}
			index++
			options.severity = args[index]
		case strings.HasPrefix(argument, "--severity="):
			options.severity = strings.TrimPrefix(argument, "--severity=")
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

type findingShowOptions struct {
	reference       string
	vulnerabilityID string
	component       string
	jsonOutput      bool
	help            bool
}

func runFindingShow(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
) int {
	options, err := parseFindingShowOptions(args)
	if err != nil {
		return usageError(stderr, err, printFindingsUsage)
	}
	if options.help {
		printFindingsUsage(stdout)
		return 0
	}
	product, release, err := splitReference(options.reference, "release")
	if err != nil {
		return usageError(stderr, err, printFindingsUsage)
	}
	findings, err := database.ListFindings(ctx, store.FindingFilter{
		Product: product, Release: release, IncludeInactive: true,
	})
	if err != nil {
		return commandError(stderr, err)
	}
	var ecosystem, component, componentVersion string
	if options.component != "" {
		ecosystem, component, componentVersion, err = splitComponentSelector(options.component)
		if err != nil {
			return usageError(stderr, err, printFindingsUsage)
		}
	}
	matches := make([]store.Finding, 0, 1)
	for _, item := range findings {
		if !findingHasIdentifier(item, options.vulnerabilityID) {
			continue
		}
		if options.component != "" &&
			(!strings.EqualFold(item.Ecosystem, ecosystem) || item.Component != component || item.ComponentVersion != componentVersion) {
			continue
		}
		matches = append(matches, item)
	}
	if len(matches) == 0 {
		return commandError(stderr, fmt.Errorf("finding %s for %s@%s: %w", options.vulnerabilityID, product, release, store.ErrNotFound))
	}
	if len(matches) > 1 {
		return commandError(stderr, fmt.Errorf("finding %s matches %d components; use --component ecosystem:package@version: %w", options.vulnerabilityID, len(matches), store.ErrAmbiguousFinding))
	}
	if options.jsonOutput {
		return printJSON(stdout, stderr, matches[0])
	}
	printFindingDetail(stdout, matches[0])
	return 0
}

func parseFindingShowOptions(args []string) (findingShowOptions, error) {
	var options findingShowOptions
	positional := make([]string, 0, 2)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case isHelp(argument):
			options.help = true
		case argument == "--json":
			options.jsonOutput = true
		case argument == "--component":
			if index+1 >= len(args) {
				return options, errors.New("--component requires a value")
			}
			index++
			options.component = args[index]
		case strings.HasPrefix(argument, "--component="):
			options.component = strings.TrimPrefix(argument, "--component=")
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
		return options, errors.New("findings show requires a product@release and vulnerability ID")
	}
	options.reference = positional[0]
	options.vulnerabilityID = positional[1]
	return options, nil
}

func findingHasIdentifier(item store.Finding, identifier string) bool {
	if strings.EqualFold(item.VulnerabilityID, strings.TrimSpace(identifier)) {
		return true
	}
	for _, alias := range item.Aliases {
		if strings.EqualFold(alias, strings.TrimSpace(identifier)) {
			return true
		}
	}
	return false
}

func printFindingDetail(writer io.Writer, item store.Finding) {
	fmt.Fprintln(writer, "FINDING")
	fmt.Fprintf(writer, "ID:             %s\n", item.VulnerabilityID)
	if len(item.Aliases) > 0 {
		fmt.Fprintf(writer, "Aliases:        %s\n", strings.Join(item.Aliases, ", "))
	}
	severity := strings.ToUpper(item.Severity)
	if item.CVSSScore != nil {
		severity += fmt.Sprintf(" (%.1f, CVSS %s)", *item.CVSSScore, item.CVSSVersion)
	}
	fmt.Fprintf(writer, "Severity:       %s\n", severity)
	fmt.Fprintf(writer, "Known exploited:%s\n", map[bool]string{true: " YES — CISA KEV", false: " no"}[item.KnownExploited])
	fmt.Fprintf(writer, "Release:        %s@%s\n", item.Product, item.Release)
	fmt.Fprintf(writer, "Component:      %s:%s@%s\n", item.Ecosystem, item.Component, item.ComponentVersion)
	fmt.Fprintf(writer, "Assessment:     %s\n", item.Status)
	fmt.Fprintf(writer, "Match:          %s\n", item.MatchStatus)
	fmt.Fprintf(writer, "Source:         %s\n", item.Source)
	fmt.Fprintf(writer, "First seen:     %s\n", item.FirstSeenAt.Format("2006-01-02 15:04Z"))
	fmt.Fprintf(writer, "Last seen:      %s\n", item.LastSeenAt.Format("2006-01-02 15:04Z"))
	if item.NoLongerMatchedAt != nil {
		fmt.Fprintf(writer, "No longer match:%s\n", " "+item.NoLongerMatchedAt.Format("2006-01-02 15:04Z"))
	}
	if item.Published != "" {
		fmt.Fprintf(writer, "Published:      %s\n", item.Published)
	}
	if item.Modified != "" {
		fmt.Fprintf(writer, "Modified:       %s\n", item.Modified)
	}
	if item.Withdrawn != "" {
		fmt.Fprintf(writer, "Withdrawn:      %s\n", item.Withdrawn)
	}
	if len(item.FixedVersions) > 0 {
		fmt.Fprintf(writer, "Fixed boundary: %s\n", strings.Join(item.FixedVersions, ", "))
	}
	if item.CVSSVector != "" {
		fmt.Fprintf(writer, "CVSS vector:    %s\n", item.CVSSVector)
	}
	if item.Summary != "" {
		fmt.Fprintf(writer, "\nSUMMARY\n%s\n", oneLine(item.Summary))
	}
	if item.KnownExploited && item.KEV != nil {
		fmt.Fprintln(writer, "\nCISA KEV")
		fmt.Fprintf(writer, "Added:          %s\n", item.KEV.DateAdded)
		fmt.Fprintf(writer, "Due:            %s\n", item.KEV.DueDate)
		fmt.Fprintf(writer, "Required action:%s\n", " "+oneLine(item.KEV.RequiredAction))
	}
	if len(item.References) > 0 {
		fmt.Fprintln(writer, "\nREFERENCES")
		for _, reference := range item.References {
			label := reference.Type
			if label == "" {
				label = "WEB"
			}
			fmt.Fprintf(writer, "- %s: %s\n", label, reference.URL)
		}
	}
	fmt.Fprintln(writer, "\nPotential impact only — human review is required.")
}
