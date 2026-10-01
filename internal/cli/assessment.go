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

type assessOptions struct {
	reference       string
	vulnerabilityID string
	status          string
	reason          string
	reviewer        string
	evidence        string
	component       string
	jsonOutput      bool
	help            bool
}

func runAssess(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
) int {
	if len(args) > 0 && (args[0] == "history" || args[0] == "list") {
		return runAssessmentHistory(ctx, args[1:], stdout, stderr, database)
	}
	options, err := parseAssessOptions(args, true)
	if err != nil {
		return usageError(stderr, err, printAssessUsage)
	}
	if options.help {
		printAssessUsage(stdout)
		return 0
	}
	target, err := assessmentTarget(options)
	if err != nil {
		return usageError(stderr, err, printAssessUsage)
	}
	assessment, err := database.CreateAssessment(ctx, target, store.AssessmentInput{
		Status: options.status, Reason: options.reason, Reviewer: options.reviewer,
		Evidence: options.evidence,
	})
	if err != nil {
		return commandError(stderr, err)
	}
	if options.jsonOutput {
		return printJSON(stdout, stderr, assessment)
	}
	printAssessment(stdout, assessment)
	return 0
}

func runAssessmentHistory(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
) int {
	options, err := parseAssessOptions(args, false)
	if err != nil {
		return usageError(stderr, err, printAssessUsage)
	}
	if options.help {
		printAssessUsage(stdout)
		return 0
	}
	target, err := assessmentTarget(options)
	if err != nil {
		return usageError(stderr, err, printAssessUsage)
	}
	assessments, err := database.ListAssessments(ctx, store.AssessmentFilter{
		Product: target.Product, Release: target.Release,
		VulnerabilityID: target.VulnerabilityID, Ecosystem: target.Ecosystem,
		Component: target.Component, ComponentVersion: target.ComponentVersion,
	})
	if err != nil {
		return commandError(stderr, err)
	}
	if options.jsonOutput {
		return printJSON(stdout, stderr, assessments)
	}
	if len(assessments) == 0 {
		fmt.Fprintln(stdout, "No assessment history found.")
		return 0
	}
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "WHEN\tSTATUS\tREVIEWER\tCOMPONENT\tREASON\tEVIDENCE")
	for _, assessment := range assessments {
		fmt.Fprintf(table, "%s\t%s\t%s\t%s:%s@%s\t%s\t%s\n",
			assessment.AssessedAt.Format("2006-01-02 15:04Z"), assessment.Status,
			oneLine(assessment.Reviewer), assessment.Ecosystem, assessment.Component,
			assessment.ComponentVersion, oneLine(assessment.Reason),
			oneLine(assessment.Evidence),
		)
	}
	if err := table.Flush(); err != nil {
		return commandError(stderr, fmt.Errorf("write assessment history: %w", err))
	}
	return 0
}

func printAssessment(writer io.Writer, assessment store.Assessment) {
	fmt.Fprintln(writer, "ASSESSMENT RECORDED")
	fmt.Fprintf(writer, "Release:    %s@%s\n", assessment.Product, assessment.Release)
	fmt.Fprintf(writer, "Finding:    %s\n", assessment.VulnerabilityID)
	fmt.Fprintf(writer, "Component:  %s:%s@%s\n", assessment.Ecosystem, assessment.Component, assessment.ComponentVersion)
	fmt.Fprintf(writer, "Status:     %s\n", assessment.Status)
	fmt.Fprintf(writer, "Reviewer:   %s\n", oneLine(assessment.Reviewer))
	if assessment.Reason != "" {
		fmt.Fprintf(writer, "Reason:     %s\n", oneLine(assessment.Reason))
	}
	if assessment.Evidence != "" {
		fmt.Fprintf(writer, "Evidence:   %s\n", oneLine(assessment.Evidence))
	}
	fmt.Fprintf(writer, "Assessed:   %s\n", assessment.AssessedAt.Format("2006-01-02 15:04Z"))
}

func parseAssessOptions(args []string, write bool) (assessOptions, error) {
	var options assessOptions
	positional := make([]string, 0, 2)
	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case isHelp(argument):
			options.help = true
		case argument == "--json":
			options.jsonOutput = true
		case argument == "--status" || argument == "--reason" ||
			argument == "--reviewer" || argument == "--evidence" || argument == "--component":
			if index+1 >= len(args) {
				return options, fmt.Errorf("%s requires a value", argument)
			}
			index++
			setAssessOption(&options, argument, args[index])
		case strings.HasPrefix(argument, "--status="):
			options.status = strings.TrimPrefix(argument, "--status=")
		case strings.HasPrefix(argument, "--reason="):
			options.reason = strings.TrimPrefix(argument, "--reason=")
		case strings.HasPrefix(argument, "--reviewer="):
			options.reviewer = strings.TrimPrefix(argument, "--reviewer=")
		case strings.HasPrefix(argument, "--evidence="):
			options.evidence = strings.TrimPrefix(argument, "--evidence=")
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
		return options, errors.New("assess requires a product@release and vulnerability ID")
	}
	options.reference = positional[0]
	options.vulnerabilityID = positional[1]
	if write && strings.TrimSpace(options.status) == "" {
		return options, errors.New("--status is required")
	}
	if write && strings.TrimSpace(options.reviewer) == "" {
		return options, errors.New("--reviewer is required")
	}
	if !write && (options.status != "" || options.reason != "" || options.reviewer != "" || options.evidence != "") {
		return options, errors.New("assessment history accepts only --component and --json")
	}
	return options, nil
}

func setAssessOption(options *assessOptions, name, value string) {
	switch name {
	case "--status":
		options.status = value
	case "--reason":
		options.reason = value
	case "--reviewer":
		options.reviewer = value
	case "--evidence":
		options.evidence = value
	case "--component":
		options.component = value
	}
}

func assessmentTarget(options assessOptions) (store.AssessmentTarget, error) {
	product, release, err := splitReference(options.reference, "release")
	if err != nil {
		return store.AssessmentTarget{}, err
	}
	target := store.AssessmentTarget{
		Product: product, Release: release, VulnerabilityID: options.vulnerabilityID,
	}
	if strings.TrimSpace(options.component) == "" {
		return target, nil
	}
	target.Ecosystem, target.Component, target.ComponentVersion, err = splitComponentSelector(options.component)
	if err != nil {
		return store.AssessmentTarget{}, err
	}
	return target, nil
}

func splitComponentSelector(value string) (string, string, string, error) {
	value = strings.TrimSpace(value)
	colon := strings.Index(value, ":")
	if colon <= 0 || colon == len(value)-1 {
		return "", "", "", errors.New("component must use ecosystem:package@version")
	}
	ecosystem := value[:colon]
	packageReference := value[colon+1:]
	name, version, err := splitReference(packageReference, "component")
	if err != nil {
		return "", "", "", errors.New("component must use ecosystem:package@version")
	}
	return ecosystem, name, version, nil
}
