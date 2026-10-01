package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"sync"

	"github.com/solongate/psirtmap/internal/kev"
	"github.com/solongate/psirtmap/internal/osv"
	"github.com/solongate/psirtmap/internal/store"
)

type syncJob struct {
	index int
	pkg   store.PackageVersion
}

type syncQueryResult struct {
	index           int
	pkg             store.PackageVersion
	vulnerabilities []osv.Vulnerability
	err             error
}

type intelligenceSyncResult struct {
	OSV     store.VulnerabilitySync `json:"osv"`
	CISAKEV *store.KEVSync          `json:"cisa_kev,omitempty"`
}

func runSync(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
	querier VulnerabilityQuerier,
	kevFetcher KEVFetcher,
) int {
	positional, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printSyncUsage)
	}
	if help {
		printSyncUsage(stdout)
		return 0
	}
	if len(positional) != 0 {
		return usageError(stderr, errors.New("sync does not accept positional arguments"), printSyncUsage)
	}
	if querier == nil {
		return commandError(stderr, errors.New("vulnerability service is unavailable"))
	}

	packages, err := database.ListPackageVersions(ctx)
	if err != nil {
		return commandError(stderr, err)
	}
	if len(packages) == 0 {
		return commandError(stderr, errors.New("no components to synchronize; import an SBOM or add a component first"))
	}
	result, err := synchronizeIntelligence(ctx, database, packages, querier, kevFetcher)
	if err != nil {
		return commandError(stderr, err)
	}

	if jsonOutput {
		return printJSON(stdout, stderr, result)
	}
	fmt.Fprintln(stdout, "VULNERABILITY DATA UPDATED")
	fmt.Fprintln(stdout, "OSV              ready")
	if result.CISAKEV != nil {
		fmt.Fprintln(stdout, "CISA KEV         ready")
	}
	fmt.Fprintf(stdout, "Packages         %d\n", result.OSV.Packages)
	fmt.Fprintf(stdout, "Vulnerabilities  %d\n", result.OSV.Vulnerabilities)
	if result.CISAKEV != nil {
		fmt.Fprintf(stdout, "KEV entries      %d\n", result.CISAKEV.Entries)
		fmt.Fprintf(stdout, "KEV released     %s\n", result.CISAKEV.DateReleased.Format("2006-01-02 15:04:05 UTC"))
	}
	fmt.Fprintf(stdout, "Synchronized     %s\n", result.OSV.SynchronizedAt.Format("2006-01-02 15:04:05 UTC"))
	return 0
}

func synchronizeIntelligence(
	ctx context.Context,
	database *store.DB,
	packages []store.PackageVersion,
	querier VulnerabilityQuerier,
	kevFetcher KEVFetcher,
) (intelligenceSyncResult, error) {
	snapshots, err := queryPackageSnapshots(ctx, packages, querier)
	if err != nil {
		return intelligenceSyncResult{}, err
	}
	var catalog kev.Catalog
	var kevCatalogFetched bool
	var catalogResult *store.KEVSync
	if kevFetcher != nil {
		catalog, err = kevFetcher.Fetch(ctx)
		if err != nil {
			return intelligenceSyncResult{}, err
		}
		kevCatalogFetched = true
	}
	osvResult, err := database.SaveOSVSnapshot(ctx, snapshots)
	if err != nil {
		return intelligenceSyncResult{}, err
	}
	if kevCatalogFetched {
		kevResult, saveErr := database.SaveKEVCatalog(ctx, catalog)
		err = saveErr
		if err != nil {
			return intelligenceSyncResult{}, err
		}
		catalogResult = &kevResult
	}
	return intelligenceSyncResult{OSV: osvResult, CISAKEV: catalogResult}, nil
}

func queryPackageSnapshots(
	ctx context.Context,
	packages []store.PackageVersion,
	querier VulnerabilityQuerier,
) ([]store.PackageSnapshot, error) {
	if len(packages) == 0 {
		return []store.PackageSnapshot{}, nil
	}
	workerCount := min(scanWorkers, len(packages))
	jobs := make(chan syncJob)
	results := make(chan syncQueryResult, len(packages))
	workerContext, cancel := context.WithCancel(ctx)
	defer cancel()

	var workers sync.WaitGroup
	workers.Add(workerCount)
	for range workerCount {
		go func() {
			defer workers.Done()
			for job := range jobs {
				vulnerabilities, err := querier.Query(workerContext, osv.Package{
					Name: job.pkg.Name, Ecosystem: job.pkg.Ecosystem,
				}, job.pkg.Version)
				results <- syncQueryResult{
					index: job.index, pkg: job.pkg,
					vulnerabilities: vulnerabilities, err: err,
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
		for index, pkg := range packages {
			select {
			case jobs <- syncJob{index: index, pkg: pkg}:
			case <-workerContext.Done():
				return
			}
		}
	}()
	go func() {
		workers.Wait()
		close(results)
	}()

	snapshots := make([]store.PackageSnapshot, 0, len(packages))
	var firstError error
	for result := range results {
		if result.err != nil {
			if firstError == nil || (errors.Is(firstError, context.Canceled) && !errors.Is(result.err, context.Canceled)) {
				firstError = fmt.Errorf(
					"query %s package %s@%s: %w",
					result.pkg.Ecosystem, result.pkg.Name, result.pkg.Version, result.err,
				)
			}
			continue
		}
		snapshots = append(snapshots, store.PackageSnapshot{
			Package: result.pkg, Vulnerabilities: nonNilVulnerabilities(result.vulnerabilities),
		})
	}
	if firstError != nil {
		return nil, firstError
	}
	if len(snapshots) != len(packages) {
		return nil, errors.New("OSV synchronization ended before every package was queried")
	}
	sort.Slice(snapshots, func(i, j int) bool {
		left, right := snapshots[i].Package, snapshots[j].Package
		if left.Ecosystem != right.Ecosystem {
			return left.Ecosystem < right.Ecosystem
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.Version < right.Version
	})
	return snapshots, nil
}
