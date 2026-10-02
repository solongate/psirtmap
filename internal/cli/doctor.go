package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/solongate/psirtmap/internal/store"
)

type doctorSnapshot struct {
	Version     string                   `json:"version"`
	Database    string                   `json:"database"`
	Products    int                      `json:"products"`
	Releases    int                      `json:"releases"`
	Components  int                      `json:"components"`
	Findings    int                      `json:"active_findings"`
	OSV         *store.VulnerabilitySync `json:"osv,omitempty"`
	CISAKEV     *store.KEVSync           `json:"cisa_kev,omitempty"`
	FeedImport  *store.FeedImport        `json:"feed_import,omitempty"`
	ReadyToScan bool                     `json:"ready_to_scan"`
	NextAction  string                   `json:"next_action"`
}

func runDoctor(
	ctx context.Context,
	args []string,
	stdout io.Writer,
	stderr io.Writer,
	database *store.DB,
) int {
	positional, jsonOutput, help, err := parseJSONPositionals(args)
	if err != nil {
		return usageError(stderr, err, printDoctorUsage)
	}
	if help {
		printDoctorUsage(stdout)
		return 0
	}
	if len(positional) != 0 {
		return usageError(stderr, errors.New("doctor does not accept positional arguments"), printDoctorUsage)
	}
	snapshot, err := inspectInstallation(ctx, database)
	if err != nil {
		return commandError(stderr, err)
	}
	if jsonOutput {
		return printJSON(stdout, stderr, snapshot)
	}
	fmt.Fprintln(stdout, "PSIRTMAP DOCTOR")
	fmt.Fprintf(stdout, "Version           %s\n", snapshot.Version)
	fmt.Fprintf(stdout, "Database          %s\n", snapshot.Database)
	fmt.Fprintln(stdout, "Database status   READY")
	fmt.Fprintf(stdout, "Inventory         %d products, %d releases, %d components\n",
		snapshot.Products, snapshot.Releases, snapshot.Components)
	fmt.Fprintf(stdout, "Active findings   %d\n", snapshot.Findings)
	printDoctorSource(stdout, "OSV snapshot", snapshot.OSV)
	printDoctorSource(stdout, "CISA KEV", snapshot.CISAKEV)
	if snapshot.FeedImport == nil {
		fmt.Fprintln(stdout, "Offline feed      No bundle imported (feature is available)")
	} else {
		fmt.Fprintf(stdout, "Offline feed      Imported %s from %s\n",
			snapshot.FeedImport.ImportedAt.Format("2006-01-02 15:04Z"), snapshot.FeedImport.SourceName)
	}
	if snapshot.ReadyToScan {
		fmt.Fprintln(stdout, "Scan readiness    READY")
	} else {
		fmt.Fprintln(stdout, "Scan readiness    NOT READY")
	}
	fmt.Fprintf(stdout, "Next action       %s\n", snapshot.NextAction)
	return 0
}

func inspectInstallation(ctx context.Context, database *store.DB) (doctorSnapshot, error) {
	products, err := database.ListProducts(ctx)
	if err != nil {
		return doctorSnapshot{}, err
	}
	releases, err := database.ListReleases(ctx, "")
	if err != nil {
		return doctorSnapshot{}, err
	}
	components, err := database.ListAllComponents(ctx)
	if err != nil {
		return doctorSnapshot{}, err
	}
	findings, err := database.ListFindings(ctx, store.FindingFilter{})
	if err != nil {
		return doctorSnapshot{}, err
	}
	result := doctorSnapshot{
		Version: version, Database: database.Path(), Products: len(products),
		Releases: len(releases), Components: len(components), Findings: len(findings),
	}
	if sync, syncErr := database.LatestVulnerabilitySync(ctx); syncErr == nil {
		result.OSV = &sync
	} else if !errors.Is(syncErr, store.ErrSnapshotNotFound) {
		return doctorSnapshot{}, syncErr
	}
	if sync, syncErr := database.LatestKEVSync(ctx); syncErr == nil {
		result.CISAKEV = &sync
	} else if !errors.Is(syncErr, store.ErrSnapshotNotFound) {
		return doctorSnapshot{}, syncErr
	}
	if imported, importErr := database.LatestFeedImport(ctx); importErr == nil {
		result.FeedImport = &imported
	} else if !errors.Is(importErr, store.ErrSnapshotNotFound) {
		return doctorSnapshot{}, importErr
	}
	result.ReadyToScan = len(components) > 0 && result.OSV != nil
	switch {
	case len(components) == 0:
		result.NextAction = "Import a CycloneDX product release with `psirtmap`"
	case result.OSV == nil:
		result.NextAction = "Update data from the Feeds screen or run `psirtmap sync`"
	case len(findings) > 0:
		result.NextAction = "Review active findings with `psirtmap findings` or the dashboard"
	default:
		result.NextAction = "Scan a shipped release from the dashboard or with `psirtmap scan`"
	}
	return result, nil
}

func printDoctorSource(writer io.Writer, label string, source any) {
	switch value := source.(type) {
	case *store.VulnerabilitySync:
		if value == nil {
			fmt.Fprintf(writer, "%-17s NOT SYNCED\n", label)
			return
		}
		fmt.Fprintf(writer, "%-17s %s (%d packages)\n", label,
			value.SynchronizedAt.Format(time.RFC3339), value.Packages)
	case *store.KEVSync:
		if value == nil {
			fmt.Fprintf(writer, "%-17s NOT SYNCED\n", label)
			return
		}
		fmt.Fprintf(writer, "%-17s %s (%d entries)\n", label,
			value.SynchronizedAt.Format(time.RFC3339), value.Entries)
	}
}
