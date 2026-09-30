// Package cli implements the PSIRTMap command-line interface.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/solongate/psirtmap/internal/osv"
	"github.com/solongate/psirtmap/internal/store"
)

const version = "0.0.5"

// VulnerabilityQuerier is implemented by the OSV client.
type VulnerabilityQuerier interface {
	Query(context.Context, osv.Package, string) ([]osv.Vulnerability, error)
}

type globalOptions struct {
	databasePath string
}

// Run executes the CLI and returns a process exit code.
func Run(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	querier VulnerabilityQuerier,
) int {
	options, remaining, err := parseGlobalOptions(args)
	if err != nil {
		return usageError(stderr, err, printUsage)
	}
	if len(remaining) == 0 {
		printUsage(stdout)
		return 0
	}

	switch remaining[0] {
	case "check":
		return runCheck(ctx, remaining[1:], stdout, stderr, querier)
	case "init", "product", "release", "component", "sync", "scan", "dashboard", "ui":
		if printRequestedInventoryHelp(remaining, stdout) {
			return 0
		}
		return runInventoryCommand(ctx, remaining, stdout, stderr, querier, options.databasePath)
	case "help", "--help", "-h":
		printUsage(stdout)
		return 0
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return 0
	default:
		return usageError(stderr, fmt.Errorf("unknown command %q", remaining[0]), printUsage)
	}
}

func printRequestedInventoryHelp(args []string, stdout io.Writer) bool {
	command := args[0]
	commandArgs := args[1:]
	helpRequested := false
	for _, argument := range commandArgs {
		if isHelp(argument) {
			helpRequested = true
			break
		}
	}
	if len(commandArgs) == 1 && commandArgs[0] == "help" {
		helpRequested = true
	}
	if len(commandArgs) == 0 && command != "init" && command != "sync" && command != "dashboard" && command != "ui" {
		helpRequested = true
	}
	if !helpRequested {
		return false
	}

	switch command {
	case "init":
		printInitUsage(stdout)
	case "product":
		printProductUsage(stdout)
	case "release":
		printReleaseUsage(stdout)
	case "component":
		printComponentUsage(stdout)
	case "scan":
		printScanUsage(stdout)
	case "sync":
		printSyncUsage(stdout)
	case "dashboard", "ui":
		printDashboardUsage(stdout)
	}
	return true
}

func parseGlobalOptions(args []string) (globalOptions, []string, error) {
	defaultPath, err := defaultDatabasePath()
	if err != nil {
		return globalOptions{}, nil, err
	}
	options := globalOptions{databasePath: defaultPath}

	for index := 0; index < len(args); index++ {
		argument := args[index]
		switch {
		case argument == "--database" || argument == "-d":
			if index+1 >= len(args) {
				return options, nil, fmt.Errorf("%s requires a value", argument)
			}
			index++
			options.databasePath = strings.TrimSpace(args[index])
		case strings.HasPrefix(argument, "--database="):
			options.databasePath = strings.TrimSpace(strings.TrimPrefix(argument, "--database="))
		default:
			if options.databasePath == "" {
				return options, nil, errors.New("database path cannot be empty")
			}
			return options, args[index:], nil
		}
	}

	if options.databasePath == "" {
		return options, nil, errors.New("database path cannot be empty")
	}
	return options, nil, nil
}

func defaultDatabasePath() (string, error) {
	if configured := strings.TrimSpace(os.Getenv("PSIRTMAP_DB")); configured != "" {
		return configured, nil
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("determine home directory: %w", err)
	}
	return filepath.Join(home, ".psirtmap", "psirtmap.db"), nil
}

func runInventoryCommand(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	querier VulnerabilityQuerier,
	databasePath string,
) int {
	database, err := store.Open(ctx, databasePath)
	if err != nil {
		fmt.Fprintf(stderr, "Error: %v\n", err)
		return 1
	}
	defer database.Close()

	switch args[0] {
	case "init":
		return runInit(args[1:], stdout, stderr, database)
	case "product":
		return runProduct(ctx, args[1:], stdout, stderr, database)
	case "release":
		return runRelease(ctx, args[1:], stdout, stderr, database)
	case "component":
		return runComponent(ctx, args[1:], stdout, stderr, database)
	case "scan":
		return runScan(ctx, args[1:], stdout, stderr, database, querier)
	case "sync":
		return runSync(ctx, args[1:], stdout, stderr, database, querier)
	case "dashboard", "ui":
		return runDashboard(ctx, args[1:], stdout, stderr, database, querier)
	default:
		panic("unreachable inventory command")
	}
}

func usageError(stderr io.Writer, err error, usage func(io.Writer)) int {
	fmt.Fprintf(stderr, "Error: %v\n\n", err)
	usage(stderr)
	return 2
}

func commandError(stderr io.Writer, err error) int {
	if errors.Is(err, context.Canceled) {
		fmt.Fprintln(stderr, "Error: operation canceled")
	} else {
		fmt.Fprintf(stderr, "Error: %v\n", err)
	}
	return 1
}
