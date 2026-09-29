package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"
	"text/tabwriter"

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
	Product    string    `json:"product"`
	Release    string    `json:"release"`
	Components int       `json:"components"`
	Findings   []finding `json:"findings"`
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
	positional, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printScanUsage)
	}
	if help {
		printScanUsage(stdout)
		return 0
	}
	if len(positional) != 1 {
		return usageError(stderr, errors.New("scan requires one product@release reference"), printScanUsage)
	}
	if querier == nil {
		return commandError(stderr, errors.New("vulnerability service is unavailable"))
	}

	productName, releaseVersion, err := splitReference(positional[0], "release")
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
		Product:    release.Product,
		Release:    release.Version,
		Components: len(components),
		Findings:   []finding{},
	}
	if len(components) > 0 {
		result.Findings, err = scanComponents(ctx, components, querier)
		if err != nil {
			return commandError(stderr, err)
		}
	}

	if jsonOutput {
		return printJSON(stdout, stderr, result)
	}
	return printScanText(stdout, stderr, result)
}

func scanComponents(
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

func printScanText(stdout io.Writer, stderr io.Writer, result scanResult) int {
	fmt.Fprintln(stdout, "PRODUCT RELEASE")
	fmt.Fprintf(stdout, "%s %s\n\n", result.Product, result.Release)
	fmt.Fprintf(stdout, "COMPONENTS\n%d\n\n", result.Components)
	fmt.Fprintf(stdout, "POTENTIAL FINDINGS\n%d\n", len(result.Findings))

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
