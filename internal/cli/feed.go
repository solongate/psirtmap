package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"time"

	"github.com/solongate/psirtmap/internal/feed"
	"github.com/solongate/psirtmap/internal/store"
)

type feedImportOutput struct {
	Bundle feed.Info        `json:"bundle"`
	Import store.FeedImport `json:"import"`
}

func runFeed(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
	querier VulnerabilityQuerier,
	kevFetcher KEVFetcher,
) int {
	if len(args) == 0 {
		return usageError(stderr, errors.New("feed requires pull, export, or import"), printFeedUsage)
	}
	switch args[0] {
	case "pull":
		return runSync(ctx, args[1:], stdout, stderr, database, querier, kevFetcher)
	case "export":
		return runFeedExport(ctx, args[1:], stdout, stderr, database)
	case "import":
		return runFeedImport(ctx, args[1:], stdout, stderr, database)
	case "help", "--help", "-h":
		printFeedUsage(stdout)
		return 0
	default:
		return usageError(stderr, fmt.Errorf("unknown feed action %q", args[0]), printFeedUsage)
	}
}

func runFeedExport(ctx context.Context, args []string, stdout, stderr io.Writer, database *store.DB) int {
	positional, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printFeedUsage)
	}
	if help {
		printFeedUsage(stdout)
		return 0
	}
	if len(positional) > 1 {
		return usageError(stderr, errors.New("feed export accepts at most one output path"), printFeedUsage)
	}
	createdAt := time.Now().UTC().Truncate(time.Second)
	path := fmt.Sprintf("psirtmap-feed-%s.bundle", createdAt.Format("20060102T150405Z"))
	if len(positional) == 1 {
		path = positional[0]
	}
	if err := validateCLIIdentifier("feed bundle path", path); err != nil {
		return usageError(stderr, err, printFeedUsage)
	}
	info, err := exportFeedBundle(ctx, database, path, createdAt)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, info)
	}
	fmt.Fprintln(stdout, "OFFLINE FEED EXPORTED")
	fmt.Fprintf(stdout, "Bundle           %s\n", info.Path)
	fmt.Fprintf(stdout, "Format           v%d\n", info.FormatVersion)
	fmt.Fprintf(stdout, "Packages         %d\n", info.Packages)
	fmt.Fprintf(stdout, "Vulnerabilities  %d\n", info.Vulnerabilities)
	fmt.Fprintf(stdout, "KEV entries      %d\n", info.KEVEntries)
	fmt.Fprintf(stdout, "Created          %s\n", info.CreatedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(stdout, "Manifest SHA256  %s\n", info.ManifestSHA256)
	return 0
}

func exportFeedBundle(
	ctx context.Context,
	database *store.DB,
	path string,
	createdAt time.Time,
) (feed.Info, error) {
	if err := validateCLIIdentifier("feed bundle path", path); err != nil {
		return feed.Info{}, err
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC().Truncate(time.Second)
	}
	intelligence, err := database.ExportIntelligence(ctx)
	if err != nil {
		if errors.Is(err, store.ErrSnapshotNotFound) {
			err = errors.New("local vulnerability data is incomplete; run \"psirtmap feed pull\" first")
		}
		return feed.Info{}, err
	}
	snapshot := feed.Snapshot{
		OSV: feed.OSVSnapshot{
			Source:         intelligence.OSVSync.Source,
			SynchronizedAt: intelligence.OSVSync.SynchronizedAt,
			Packages:       intelligence.Packages,
		},
		CISAKEV: feed.KEVSnapshot{
			Source:          intelligence.KEVSync.Source,
			CatalogVersion:  intelligence.KEVSync.CatalogVersion,
			DateReleased:    intelligence.KEVSync.DateReleased,
			SynchronizedAt:  intelligence.KEVSync.SynchronizedAt,
			Vulnerabilities: intelligence.KEVEntries,
		},
	}
	feed.Sort(&snapshot)
	info, err := feed.Write(path, "PSIRTMap "+version, snapshot, createdAt)
	if err != nil {
		return feed.Info{}, err
	}
	return info, nil
}

func runFeedImport(ctx context.Context, args []string, stdout, stderr io.Writer, database *store.DB) int {
	positional, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printFeedUsage)
	}
	if help {
		printFeedUsage(stdout)
		return 0
	}
	if len(positional) != 1 {
		return usageError(stderr, errors.New("feed import requires exactly one bundle path"), printFeedUsage)
	}
	path := positional[0]
	if err := validateCLIIdentifier("feed bundle path", path); err != nil {
		return usageError(stderr, err, printFeedUsage)
	}
	info, result, err := importFeedBundle(ctx, database, path)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, feedImportOutput{Bundle: info, Import: result})
	}
	fmt.Fprintln(stdout, "OFFLINE FEED IMPORTED")
	fmt.Fprintf(stdout, "Bundle           %s\n", oneLine(path))
	fmt.Fprintln(stdout, "Integrity        SHA-256 checksums verified")
	fmt.Fprintf(stdout, "Packages         %d\n", result.Packages)
	fmt.Fprintf(stdout, "Vulnerabilities  %d\n", result.Vulnerabilities)
	fmt.Fprintf(stdout, "KEV entries      %d\n", result.KEVEntries)
	fmt.Fprintf(stdout, "Feed created     %s\n", result.BundleCreatedAt.Format("2006-01-02 15:04:05 UTC"))
	fmt.Fprintf(stdout, "Imported         %s\n", result.ImportedAt.Format("2006-01-02 15:04:05 UTC"))
	return 0
}

func importFeedBundle(
	ctx context.Context,
	database *store.DB,
	path string,
) (feed.Info, store.FeedImport, error) {
	if err := validateCLIIdentifier("feed bundle path", path); err != nil {
		return feed.Info{}, store.FeedImport{}, err
	}
	snapshot, info, err := feed.Read(path)
	if err != nil {
		return feed.Info{}, store.FeedImport{}, err
	}
	result, err := database.ImportIntelligence(ctx, store.IntelligenceSnapshot{
		OSVSync: store.VulnerabilitySync{
			Source: snapshot.OSV.Source, SynchronizedAt: snapshot.OSV.SynchronizedAt,
			Packages: info.Packages, Vulnerabilities: info.Vulnerabilities,
		},
		Packages: snapshot.OSV.Packages,
		KEVSync: store.KEVSync{
			Source: snapshot.CISAKEV.Source, CatalogVersion: snapshot.CISAKEV.CatalogVersion,
			DateReleased:   snapshot.CISAKEV.DateReleased,
			SynchronizedAt: snapshot.CISAKEV.SynchronizedAt, Entries: info.KEVEntries,
		},
		KEVEntries: snapshot.CISAKEV.Vulnerabilities,
	}, store.FeedImportMetadata{
		FormatVersion: info.FormatVersion, BundleCreatedAt: info.CreatedAt,
		SourceName: filepath.Base(path), ManifestSHA256: info.ManifestSHA256,
	})
	if err != nil {
		return feed.Info{}, store.FeedImport{}, err
	}
	return info, result, nil
}
