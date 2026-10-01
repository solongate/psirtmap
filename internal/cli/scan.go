package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"sync"
	"text/tabwriter"
	"time"

	"github.com/solongate/psirtmap/internal/osv"
	"github.com/solongate/psirtmap/internal/store"
)

const scanWorkers = 4

type finding struct {
	ID               string   `json:"id"`
	Aliases          []string `json:"aliases,omitempty"`
	Summary          string   `json:"summary,omitempty"`
	Ecosystem        string   `json:"ecosystem"`
	Component        string   `json:"component"`
	ComponentVersion string   `json:"component_version"`
	Status           string   `json:"status"`
}

type scanResult struct {
	Product         string    `json:"product"`
	Release         string    `json:"release"`
	Components      int       `json:"components"`
	DataSource      string    `json:"data_source"`
	SynchronizedAt  string    `json:"synchronized_at,omitempty"`
	Persisted       bool      `json:"persisted"`
	New             int       `json:"new"`
	Existing        int       `json:"existing"`
	Reopened        int       `json:"reopened"`
	NoLongerMatched int       `json:"no_longer_matched"`
	Findings        []finding `json:"findings"`
}

type scanOptions struct {
	reference  string
	jsonOutput bool
	live       bool
	help       bool
}

type scanJob struct {
	index     int
	component store.Component
}

type componentScanResult struct {
	index           int
	component       store.Component
	vulnerabilities []osv.Vulnerability
	err             error
}

func runScan(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
	querier VulnerabilityQuerier,
) int {
	options, err := parseScanOptions(args)
	if err != nil {
		return usageError(stderr, err, printScanUsage)
	}
	if options.help {
		printScanUsage(stdout)
		return 0
	}
	if options.live && querier == nil {
		return commandError(stderr, errors.New("vulnerability service is unavailable"))
	}

	productName, releaseVersion, err := splitReference(options.reference, "release")
	if err != nil {
		return usageError(stderr, err, printScanUsage)
	}
	release, err := database.GetRelease(ctx, productName, releaseVersion)
	if err != nil {
		return commandError(stderr, err)
	}
	components, err := database.ListComponents(ctx, productName, releaseVersion)
	if err != nil {
		return commandError(stderr, err)
	}

	result := scanResult{
		Product: release.Product, Release: release.Version,
		Components: len(components), Findings: []finding{},
	}
	if len(components) > 0 {
		if options.live {
			result.DataSource = "osv-live"
			result.Findings, err = scanComponentsLive(ctx, components, querier)
		} else {
			result.DataSource = "local-osv-snapshot"
			var synchronizedAt time.Time
			result.Findings, synchronizedAt, err = scanComponentsLocal(ctx, components, database)
			if !synchronizedAt.IsZero() {
				result.SynchronizedAt = synchronizedAt.Format(time.RFC3339)
			}
		}
	} else if options.live {
		result.DataSource = "osv-live"
	} else {
		result.DataSource = "local-osv-snapshot"
	}
	if err != nil {
		return commandError(stderr, err)
	}
	if !options.live {
		if err := persistScanResult(ctx, database, &result); err != nil {
			return commandError(stderr, err)
		}
	}

	if options.jsonOutput {
		return printJSON(stdout, stderr, result)
	}
	return printScanText(stdout, stderr, result)
}

func persistScanResult(ctx context.Context, database *store.DB, result *scanResult) error {
	matches := make([]store.FindingMatch, 0, len(result.Findings))
	for _, item := range result.Findings {
		matches = append(matches, store.FindingMatch{
			Ecosystem: item.Ecosystem, Component: item.Component,
			ComponentVersion: item.ComponentVersion, VulnerabilityID: item.ID,
			Aliases: item.Aliases, Summary: item.Summary,
		})
	}
	var synchronizedAt time.Time
	if result.SynchronizedAt != "" {
		parsed, err := time.Parse(time.RFC3339, result.SynchronizedAt)
		if err != nil {
			return fmt.Errorf("parse scan synchronization time: %w", err)
		}
		synchronizedAt = parsed
	}
	reconciled, err := database.ReconcileFindings(
		ctx, result.Product, result.Release, matches, result.DataSource,
		synchronizedAt, result.Components,
	)
	if err != nil {
		return err
	}
	result.Persisted = true
	result.New = reconciled.New
	result.Existing = reconciled.Existing
	result.Reopened = reconciled.Reopened
	result.NoLongerMatched = reconciled.NoLongerMatched
	saved, err := database.ListFindings(ctx, store.FindingFilter{
		Product: result.Product, Release: result.Release,
	})
	if err != nil {
		return fmt.Errorf("refresh persisted finding statuses: %w", err)
	}
	type findingIdentity struct {
		ecosystem string
		component string
		version   string
		id        string
	}
	statuses := make(map[findingIdentity]string, len(saved))
	for _, item := range saved {
		statuses[findingIdentity{
			ecosystem: item.Ecosystem, component: item.Component,
			version: item.ComponentVersion, id: item.VulnerabilityID,
		}] = item.Status
	}
	for index := range result.Findings {
		item := &result.Findings[index]
		if status, ok := statuses[findingIdentity{
			ecosystem: item.Ecosystem, component: item.Component,
			version: item.ComponentVersion, id: item.ID,
		}]; ok {
			item.Status = status
		}
	}
	return nil
}

func parseScanOptions(args []string) (scanOptions, error) {
	var options scanOptions
	var positional []string
	for _, argument := range args {
		switch argument {
		case "--help", "-h":
			options.help = true
		case "--json":
			options.jsonOutput = true
		case "--live":
			options.live = true
		default:
			if strings.HasPrefix(argument, "-") {
				return options, fmt.Errorf("unknown option %q", argument)
			}
			positional = append(positional, argument)
		}
	}
	if options.help {
		return options, nil
	}
	if len(positional) != 1 {
		return options, errors.New("scan requires one product@release reference")
	}
	options.reference = positional[0]
	return options, nil
}

func scanComponentsLive(
	ctx context.Context,
	components []store.Component,
	querier VulnerabilityQuerier,
) ([]finding, error) {
	workerCount := min(scanWorkers, len(components))
	jobs := make(chan scanJob)
	results := make(chan componentScanResult, len(components))
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				vulnerabilities, err := querier.Query(workerContext, osv.Package{
					Name:      job.component.Name,
					Ecosystem: job.component.Ecosystem,
				}, job.component.Version)
				results <- componentScanResult{
					index:           job.index,
					component:       job.component,
					vulnerabilities: vulnerabilities,
					err:             err,
				}
				if err != nil {
					cancel()
					return
				}
			}
		}()
	}

	go func() {
		defer close(jobs)
		for index, component := range components {
			select {
			case jobs <- scanJob{index: index, component: component}:
			case <-workerContext.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	findings := make([]finding, 0)
	var firstError error
	for result := range results {
		if result.err != nil {
			if firstError == nil {
				firstError = fmt.Errorf(
					"query %s package %s@%s: %w",
					result.component.Ecosystem,
					result.component.Name,
					result.component.Version,
					result.err,
				)
			}
			continue
		}
		for _, vulnerability := range result.vulnerabilities {
			findings = append(findings, finding{
				ID:               vulnerability.ID,
				Aliases:          vulnerability.Aliases,
				Summary:          vulnerability.Summary,
				Ecosystem:        result.component.Ecosystem,
				Component:        result.component.Name,
				ComponentVersion: result.component.Version,
				Status:           "needs-review",
			})
		}
	}
	if firstError != nil {
		return nil, firstError
	}

	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Ecosystem != findings[j].Ecosystem {
			return findings[i].Ecosystem < findings[j].Ecosystem
		}
		if findings[i].Component != findings[j].Component {
			return findings[i].Component < findings[j].Component
		}
		return findings[i].ComponentVersion < findings[j].ComponentVersion
	})
	return findings, nil
}

func scanComponentsLocal(
	ctx context.Context,
	components []store.Component,
	database *store.DB,
) ([]finding, time.Time, error) {
	findings := make([]finding, 0)
	var synchronizedAt time.Time
	for _, component := range components {
		vulnerabilities, packageSyncedAt, err := database.LookupOSVSnapshot(ctx, store.PackageVersion{
			Ecosystem: component.Ecosystem,
			Name:      component.Name,
			Version:   component.Version,
		})
		if err != nil {
			if errors.Is(err, store.ErrSnapshotNotFound) {
				return nil, time.Time{}, fmt.Errorf(
					"no local OSV data for %s:%s@%s; run \"psirtmap sync\" or use \"psirtmap scan --live %s@%s\"",
					component.Ecosystem, component.Name, component.Version,
					component.Product, component.ReleaseVersion,
				)
			}
			return nil, time.Time{}, err
		}
		if synchronizedAt.IsZero() || packageSyncedAt.Before(synchronizedAt) {
			synchronizedAt = packageSyncedAt
		}
		for _, vulnerability := range vulnerabilities {
			findings = append(findings, finding{
				ID: vulnerability.ID, Aliases: vulnerability.Aliases,
				Summary: vulnerability.Summary, Ecosystem: component.Ecosystem,
				Component: component.Name, ComponentVersion: component.Version,
				Status: "needs-review",
			})
		}
	}
	sortFindings(findings)
	return findings, synchronizedAt, nil
}

func sortFindings(findings []finding) {
	sort.Slice(findings, func(i, j int) bool {
		if findings[i].ID != findings[j].ID {
			return findings[i].ID < findings[j].ID
		}
		if findings[i].Ecosystem != findings[j].Ecosystem {
			return findings[i].Ecosystem < findings[j].Ecosystem
		}
		if findings[i].Component != findings[j].Component {
			return findings[i].Component < findings[j].Component
		}
		return findings[i].ComponentVersion < findings[j].ComponentVersion
	})
}

func printScanText(stdout io.Writer, stderr io.Writer, result scanResult) int {
	fmt.Fprintln(stdout, "PRODUCT RELEASE")
	fmt.Fprintf(stdout, "%s %s\n\n", result.Product, result.Release)
	fmt.Fprintln(stdout, "DATA SOURCE")
	if result.DataSource == "osv-live" {
		fmt.Fprintln(stdout, "OSV live query")
		fmt.Fprintln(stdout)
	} else if result.SynchronizedAt != "" {
		fmt.Fprintf(stdout, "Local OSV snapshot (%s)\n\n", result.SynchronizedAt)
	} else {
		fmt.Fprintln(stdout, "Local OSV snapshot")
		fmt.Fprintln(stdout)
	}
	fmt.Fprintf(stdout, "COMPONENTS\n%d\n\n", result.Components)
	fmt.Fprintf(stdout, "POTENTIAL FINDINGS\n%d\n", len(result.Findings))
	if result.Persisted {
		fmt.Fprintln(stdout, "\nFINDING CHANGES")
		fmt.Fprintf(stdout, "New %d  Existing %d  Reopened %d  No longer matched %d\n",
			result.New, result.Existing, result.Reopened, result.NoLongerMatched)
	} else {
		fmt.Fprintln(stdout, "\nLive results are diagnostic and were not saved.")
	}

	if len(result.Findings) == 0 {
		fmt.Fprintln(stdout, "\nNo known vulnerabilities found.")
		return 0
	}

	fmt.Fprintln(stdout)
	table := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(table, "ID\tECOSYSTEM\tCOMPONENT\tSTATUS")
	for _, item := range result.Findings {
		fmt.Fprintf(table, "%s\t%s\t%s@%s\t%s\n",
			oneLine(item.ID),
			item.Ecosystem,
			item.Component,
			item.ComponentVersion,
			item.Status,
		)
	}
	if err := table.Flush(); err != nil {
		return commandError(stderr, fmt.Errorf("write scan result: %w", err))
	}
	return 0
}
