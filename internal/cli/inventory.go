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

func runInit(args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	if len(args) == 1 && isHelp(args[0]) {
		printInitUsage(stdout)
		return 0
	}
	if len(args) != 0 {
		return usageError(stderr, errors.New("init does not accept arguments"), printInitUsage)
	}
	fmt.Fprintf(stdout, "Initialized PSIRTMap database:\n%s\n", database.Path())
	return 0
}

func runProduct(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	if len(args) == 0 || (len(args) == 1 && (isHelp(args[0]) || args[0] == "help")) {
		printProductUsage(stdout)
		return 0
	}

	switch args[0] {
	case "add", "create":
		return runProductAdd(ctx, args[1:], stdout, stderr, database)
	case "list", "ls":
		return runProductList(ctx, args[1:], stdout, stderr, database)
	default:
		return usageError(stderr, fmt.Errorf("unknown product command %q", args[0]), printProductUsage)
	}
}

func runProductAdd(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	var description string
	var jsonOutput bool
	var positional []string

	for index := 0; index < len(args); index++ {
		switch argument := args[index]; {
		case isHelp(argument):
			printProductUsage(stdout)
			return 0
		case argument == "--json":
			jsonOutput = true
		case argument == "--description":
			if index+1 >= len(args) {
				return usageError(stderr, errors.New("--description requires a value"), printProductUsage)
			}
			index++
			description = args[index]
		case strings.HasPrefix(argument, "--description="):
			description = strings.TrimPrefix(argument, "--description=")
		case strings.HasPrefix(argument, "-"):
			return usageError(stderr, fmt.Errorf("unknown option %q", argument), printProductUsage)
		default:
			positional = append(positional, argument)
		}
	}
	if len(positional) != 1 {
		return usageError(stderr, errors.New("product add requires exactly one product name"), printProductUsage)
	}

	product, err := database.CreateProduct(ctx, positional[0], description)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, product)
	}
	fmt.Fprintf(stdout, "Created product:\n%s\n", product.Name)
	if product.Description != "" {
		fmt.Fprintf(stdout, "Description: %s\n", product.Description)
	}
	return 0
}

func runProductList(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	jsonOutput, help, err := parseListOptions(args)
	if err != nil {
		return usageError(stderr, err, printProductUsage)
	}
	if help {
		printProductUsage(stdout)
		return 0
	}
	products, err := database.ListProducts(ctx)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, products)
	}
	if len(products) == 0 {
		fmt.Fprintln(stdout, "No products found.")
		return 0
	}

	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "PRODUCT\tDESCRIPTION")
	for _, product := range products {
		fmt.Fprintf(table, "%s\t%s\n", product.Name, oneLine(product.Description))
	}
	if err := table.Flush(); err != nil {
		return commandError(stderr, fmt.Errorf("write product list: %w", err))
	}
	return 0
}

func runRelease(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	if len(args) == 0 || (len(args) == 1 && (isHelp(args[0]) || args[0] == "help")) {
		printReleaseUsage(stdout)
		return 0
	}
	switch args[0] {
	case "add", "create":
		return runReleaseAdd(ctx, args[1:], stdout, stderr, database)
	case "list", "ls":
		return runReleaseList(ctx, args[1:], stdout, stderr, database)
	default:
		return usageError(stderr, fmt.Errorf("unknown release command %q", args[0]), printReleaseUsage)
	}
}

func runReleaseAdd(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	positional, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printReleaseUsage)
	}
	if help {
		printReleaseUsage(stdout)
		return 0
	}
	if len(positional) != 2 {
		return usageError(stderr, errors.New("release add requires a product and version"), printReleaseUsage)
	}

	release, err := database.CreateRelease(ctx, positional[0], positional[1])
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, release)
	}
	fmt.Fprintf(stdout, "Created release:\n%s@%s\n", release.Product, release.Version)
	return 0
}

func runReleaseList(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	positional, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printReleaseUsage)
	}
	if help {
		printReleaseUsage(stdout)
		return 0
	}
	if len(positional) > 1 {
		return usageError(stderr, errors.New("release list accepts at most one product"), printReleaseUsage)
	}
	productName := ""
	if len(positional) == 1 {
		productName = positional[0]
	}
	releases, err := database.ListReleases(ctx, productName)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, releases)
	}
	if len(releases) == 0 {
		fmt.Fprintln(stdout, "No releases found.")
		return 0
	}

	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "PRODUCT\tRELEASE")
	for _, release := range releases {
		fmt.Fprintf(table, "%s\t%s\n", release.Product, release.Version)
	}
	if err := table.Flush(); err != nil {
		return commandError(stderr, fmt.Errorf("write release list: %w", err))
	}
	return 0
}

func runComponent(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	if len(args) == 0 || (len(args) == 1 && (isHelp(args[0]) || args[0] == "help")) {
		printComponentUsage(stdout)
		return 0
	}
	switch args[0] {
	case "add":
		return runComponentAdd(ctx, args[1:], stdout, stderr, database)
	case "list", "ls":
		return runComponentList(ctx, args[1:], stdout, stderr, database)
	default:
		return usageError(stderr, fmt.Errorf("unknown component command %q", args[0]), printComponentUsage)
	}
}

func runComponentAdd(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	var ecosystem string
	var jsonOutput bool
	var positional []string

	for index := 0; index < len(args); index++ {
		switch argument := args[index]; {
		case isHelp(argument):
			printComponentUsage(stdout)
			return 0
		case argument == "--json":
			jsonOutput = true
		case argument == "--ecosystem" || argument == "-e":
			if index+1 >= len(args) {
				return usageError(stderr, fmt.Errorf("%s requires a value", argument), printComponentUsage)
			}
			index++
			ecosystem = args[index]
		case strings.HasPrefix(argument, "--ecosystem="):
			ecosystem = strings.TrimPrefix(argument, "--ecosystem=")
		case strings.HasPrefix(argument, "-"):
			return usageError(stderr, fmt.Errorf("unknown option %q", argument), printComponentUsage)
		default:
			positional = append(positional, argument)
		}
	}
	if len(positional) != 2 {
		return usageError(stderr, errors.New("component add requires a release and package reference"), printComponentUsage)
	}
	if strings.TrimSpace(ecosystem) == "" {
		return usageError(stderr, errors.New("--ecosystem is required"), printComponentUsage)
	}

	productName, releaseVersion, err := splitReference(positional[0], "release")
	if err != nil {
		return usageError(stderr, err, printComponentUsage)
	}
	packageName, packageVersion, err := splitReference(positional[1], "package")
	if err != nil {
		return usageError(stderr, err, printComponentUsage)
	}
	component, err := database.CreateComponent(
		ctx, productName, releaseVersion, ecosystem, packageName, packageVersion,
	)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, component)
	}
	fmt.Fprintf(stdout, "Added component:\n%s@%s (%s) -> %s@%s\n",
		component.Name,
		component.Version,
		component.Ecosystem,
		component.Product,
		component.ReleaseVersion,
	)
	return 0
}

func runComponentList(ctx context.Context, args []string, stdout io.Writer, stderr io.Writer, database *store.DB) int {
	positional, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printComponentUsage)
	}
	if help {
		printComponentUsage(stdout)
		return 0
	}
	if len(positional) != 1 {
		return usageError(stderr, errors.New("component list requires one product@release reference"), printComponentUsage)
	}
	productName, releaseVersion, err := splitReference(positional[0], "release")
	if err != nil {
		return usageError(stderr, err, printComponentUsage)
	}
	components, err := database.ListComponents(ctx, productName, releaseVersion)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, components)
	}
	if len(components) == 0 {
		fmt.Fprintf(stdout, "No components found for %s@%s.\n", productName, releaseVersion)
		return 0
	}

	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "ECOSYSTEM\tCOMPONENT\tVERSION")
	for _, component := range components {
		fmt.Fprintf(table, "%s\t%s\t%s\n", component.Ecosystem, component.Name, component.Version)
	}
	if err := table.Flush(); err != nil {
		return commandError(stderr, fmt.Errorf("write component list: %w", err))
	}
	return 0
}

func parseListOptions(args []string) (jsonOutput bool, help bool, err error) {
	for _, argument := range args {
		switch {
		case argument == "--json":
			jsonOutput = true
		case isHelp(argument):
			help = true
		default:
			return false, false, fmt.Errorf("unknown option or argument %q", argument)
		}
	}
	return jsonOutput, help, nil
}

func parseJSONPositionals(args []string) (positional []string, jsonOutput bool, help bool, err error) {
	for _, argument := range args {
		switch {
		case argument == "--json":
			jsonOutput = true
		case isHelp(argument):
			help = true
		case strings.HasPrefix(argument, "-"):
			return nil, false, false, fmt.Errorf("unknown option %q", argument)
		default:
			positional = append(positional, argument)
		}
	}
	return positional, jsonOutput, help, nil
}

func splitReference(value, label string) (string, string, error) {
	value = strings.TrimSpace(value)
	separator := strings.LastIndex(value, "@")
	if separator <= 0 || separator == len(value)-1 {
		return "", "", fmt.Errorf("invalid %s reference %q; expected name@version", label, value)
	}
	name := strings.TrimSpace(value[:separator])
	version := strings.TrimSpace(value[separator+1:])
	if name == "" || version == "" {
		return "", "", fmt.Errorf("invalid %s reference %q; expected name@version", label, value)
	}
	return name, version, nil
}

func isHelp(argument string) bool {
	return argument == "--help" || argument == "-h"
}
