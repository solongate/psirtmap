package store

import (
	"context"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/solongate/psirtmap/internal/kev"
)

// IntelligenceSnapshot is the active OSV and CISA KEV data needed by an
// offline PSIRTMap installation. Product inventory is deliberately excluded.
type IntelligenceSnapshot struct {
	OSVSync    VulnerabilitySync
	Packages   []PackageSnapshot
	KEVSync    KEVSync
	KEVEntries []kev.Vulnerability
}

// FeedImportMetadata records the provenance of one validated portable bundle.
type FeedImportMetadata struct {
	FormatVersion   int
	BundleCreatedAt time.Time
	SourceName      string
	ManifestSHA256  string
}

// FeedImport summarizes one atomically committed bundle import.
type FeedImport struct {
	FormatVersion     int       `json:"format_version"`
	BundleCreatedAt   time.Time `json:"bundle_created_at"`
	ImportedAt        time.Time `json:"imported_at"`
	SourceName        string    `json:"source_name"`
	ManifestSHA256    string    `json:"manifest_sha256"`
	OSVSynchronizedAt time.Time `json:"osv_synchronized_at"`
	KEVSynchronizedAt time.Time `json:"kev_synchronized_at"`
	Packages          int       `json:"packages"`
	Vulnerabilities   int       `json:"vulnerabilities"`
	KEVEntries        int       `json:"kev_entries"`
}

// LatestFeedImport returns the provenance of the most recently committed
// portable bundle.
func (d *DB) LatestFeedImport(ctx context.Context) (FeedImport, error) {
	var result FeedImport
	var bundleCreatedAt, importedAt, osvSynchronizedAt, kevSynchronizedAt string
	err := d.db.QueryRowContext(ctx, `SELECT format_version, bundle_created_at,
		imported_at, source_name, manifest_sha256, osv_synchronized_at,
		kev_synchronized_at, package_count, vulnerability_count, kev_entry_count
		FROM feed_imports ORDER BY id DESC LIMIT 1`).Scan(
		&result.FormatVersion, &bundleCreatedAt, &importedAt,
		&result.SourceName, &result.ManifestSHA256, &osvSynchronizedAt,
		&kevSynchronizedAt, &result.Packages, &result.Vulnerabilities,
		&result.KEVEntries,
	)
	if errors.Is(err, sql.ErrNoRows) {
		return FeedImport{}, ErrSnapshotNotFound
	}
	if err != nil {
		return FeedImport{}, fmt.Errorf("read latest feed import: %w", err)
	}
	for _, target := range []struct {
		value string
		into  *time.Time
	}{
		{bundleCreatedAt, &result.BundleCreatedAt},
		{importedAt, &result.ImportedAt},
		{osvSynchronizedAt, &result.OSVSynchronizedAt},
		{kevSynchronizedAt, &result.KEVSynchronizedAt},
	} {
		parsed, parseErr := parseTime(target.value)
		if parseErr != nil {
			return FeedImport{}, parseErr
		}
		*target.into = parsed
	}
	return result, nil
}

// ExportIntelligence returns a complete copy of the currently active local
// vulnerability data. It never includes products, releases, components,
// findings, or assessments.
func (d *DB) ExportIntelligence(ctx context.Context) (IntelligenceSnapshot, error) {
	osvSync, err := d.LatestVulnerabilitySync(ctx)
	if err != nil {
		return IntelligenceSnapshot{}, fmt.Errorf("export OSV snapshot: %w", err)
	}
	packages, err := d.listSnapshotPackages(ctx)
	if err != nil {
		return IntelligenceSnapshot{}, err
	}
	snapshots := make([]PackageSnapshot, 0, len(packages))
	for _, pkg := range packages {
		vulnerabilities, synchronizedAt, lookupErr := d.LookupOSVSnapshot(ctx, pkg)
		if lookupErr != nil {
			return IntelligenceSnapshot{}, fmt.Errorf("export OSV package %s:%s@%s: %w", pkg.Ecosystem, pkg.Name, pkg.Version, lookupErr)
		}
		if !synchronizedAt.Equal(osvSync.SynchronizedAt) {
			return IntelligenceSnapshot{}, errors.New("active OSV snapshot contains inconsistent synchronization times")
		}
		snapshots = append(snapshots, PackageSnapshot{Package: pkg, Vulnerabilities: vulnerabilities})
	}
	if len(snapshots) != osvSync.Packages {
		return IntelligenceSnapshot{}, fmt.Errorf("active OSV snapshot contains %d packages but metadata reports %d", len(snapshots), osvSync.Packages)
	}

	kevSync, err := d.LatestKEVSync(ctx)
	if err != nil {
		return IntelligenceSnapshot{}, fmt.Errorf("export CISA KEV snapshot: %w", err)
	}
	kevEntries, err := d.ListKEVEntries(ctx)
	if err != nil {
		return IntelligenceSnapshot{}, fmt.Errorf("export CISA KEV entries: %w", err)
	}
	if len(kevEntries) != kevSync.Entries {
		return IntelligenceSnapshot{}, fmt.Errorf("active CISA KEV snapshot contains %d entries but metadata reports %d", len(kevEntries), kevSync.Entries)
	}
	return IntelligenceSnapshot{
		OSVSync: osvSync, Packages: snapshots,
		KEVSync: kevSync, KEVEntries: kevEntries,
	}, nil
}

func (d *DB) listSnapshotPackages(ctx context.Context) ([]PackageVersion, error) {
	rows, err := d.db.QueryContext(ctx, `SELECT ecosystem, name, version
		FROM package_snapshots ORDER BY ecosystem, name, version`)
	if err != nil {
		return nil, fmt.Errorf("list active OSV package snapshots: %w", err)
	}
	defer rows.Close()
	packages := make([]PackageVersion, 0)
	for rows.Next() {
		var pkg PackageVersion
		if err := rows.Scan(&pkg.Ecosystem, &pkg.Name, &pkg.Version); err != nil {
			return nil, fmt.Errorf("read active OSV package snapshot: %w", err)
		}
		packages = append(packages, pkg)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("list active OSV package snapshots: %w", err)
	}
	return packages, nil
}

// ImportIntelligence atomically replaces both active source snapshots and
// records bundle provenance. Validation errors or database failures leave the
// previous local data untouched.
func (d *DB) ImportIntelligence(
	ctx context.Context,
	snapshot IntelligenceSnapshot,
	metadata FeedImportMetadata,
) (FeedImport, error) {
	result, catalog, err := validateIntelligenceImport(snapshot, metadata)
	if err != nil {
		return FeedImport{}, err
	}
	transaction, err := d.db.BeginTx(ctx, nil)
	if err != nil {
		return FeedImport{}, fmt.Errorf("begin feed import: %w", err)
	}
	defer transaction.Rollback()
	if err := replaceOSVSnapshot(ctx, transaction, snapshot.OSVSync, snapshot.Packages); err != nil {
		return FeedImport{}, err
	}
	if err := replaceKEVSnapshot(ctx, transaction, snapshot.KEVSync, catalog); err != nil {
		return FeedImport{}, err
	}
	_, err = transaction.ExecContext(ctx, `INSERT INTO feed_imports(
		format_version, bundle_created_at, imported_at, source_name,
		manifest_sha256, osv_synchronized_at, kev_synchronized_at,
		package_count, vulnerability_count, kev_entry_count
	) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		result.FormatVersion, formatTime(result.BundleCreatedAt), formatTime(result.ImportedAt),
		result.SourceName, result.ManifestSHA256, formatTime(result.OSVSynchronizedAt),
		formatTime(result.KEVSynchronizedAt), result.Packages,
		result.Vulnerabilities, result.KEVEntries,
	)
	if err != nil {
		return FeedImport{}, fmt.Errorf("record feed import: %w", err)
	}
	if err := transaction.Commit(); err != nil {
		return FeedImport{}, fmt.Errorf("commit feed import: %w", err)
	}
	return result, nil
}

func validateIntelligenceImport(snapshot IntelligenceSnapshot, metadata FeedImportMetadata) (FeedImport, kev.Catalog, error) {
	metadata.SourceName = strings.TrimSpace(metadata.SourceName)
	metadata.ManifestSHA256 = strings.ToLower(strings.TrimSpace(metadata.ManifestSHA256))
	if metadata.FormatVersion <= 0 || metadata.BundleCreatedAt.IsZero() || metadata.SourceName == "" {
		return FeedImport{}, kev.Catalog{}, errors.New("complete feed bundle provenance is required")
	}
	if _, err := cleanIdentifier("feed source name", metadata.SourceName); err != nil {
		return FeedImport{}, kev.Catalog{}, err
	}
	if len(metadata.ManifestSHA256) != 64 {
		return FeedImport{}, kev.Catalog{}, errors.New("feed manifest SHA-256 is invalid")
	}
	if _, err := hex.DecodeString(metadata.ManifestSHA256); err != nil {
		return FeedImport{}, kev.Catalog{}, errors.New("feed manifest SHA-256 is invalid")
	}
	metadata.BundleCreatedAt = metadata.BundleCreatedAt.UTC()
	if metadata.BundleCreatedAt.After(time.Now().UTC().Add(5 * time.Minute)) {
		return FeedImport{}, kev.Catalog{}, errors.New("feed bundle creation time is in the future")
	}
	if strings.TrimSpace(snapshot.OSVSync.Source) == "" || strings.TrimSpace(snapshot.OSVSync.Source) != snapshot.OSVSync.Source || snapshot.OSVSync.SynchronizedAt.IsZero() {
		return FeedImport{}, kev.Catalog{}, errors.New("complete OSV snapshot metadata is required")
	}
	if len(snapshot.Packages) == 0 {
		return FeedImport{}, kev.Catalog{}, errors.New("OSV snapshot contains no packages")
	}
	seenPackages := make(map[PackageVersion]struct{}, len(snapshot.Packages))
	seenVulnerabilities := make(map[string]struct{})
	for _, packageSnapshot := range snapshot.Packages {
		pkg := packageSnapshot.Package
		for _, target := range []struct{ label, value string }{
			{"ecosystem", pkg.Ecosystem}, {"package name", pkg.Name}, {"package version", pkg.Version},
		} {
			cleaned, err := cleanIdentifier(target.label, target.value)
			if err != nil || cleaned != target.value {
				if err != nil {
					return FeedImport{}, kev.Catalog{}, err
				}
				return FeedImport{}, kev.Catalog{}, fmt.Errorf("%s is not normalized", target.label)
			}
		}
		if _, duplicate := seenPackages[pkg]; duplicate {
			return FeedImport{}, kev.Catalog{}, fmt.Errorf("duplicate package snapshot %s:%s@%s", pkg.Ecosystem, pkg.Name, pkg.Version)
		}
		seenPackages[pkg] = struct{}{}
		seenForPackage := make(map[string]struct{}, len(packageSnapshot.Vulnerabilities))
		for _, vulnerability := range packageSnapshot.Vulnerabilities {
			identifier := strings.TrimSpace(vulnerability.ID)
			if identifier == "" || identifier != vulnerability.ID {
				return FeedImport{}, kev.Catalog{}, errors.New("OSV vulnerability ID is required and must be normalized")
			}
			if _, duplicate := seenForPackage[identifier]; duplicate {
				return FeedImport{}, kev.Catalog{}, fmt.Errorf("duplicate OSV match %s for %s:%s@%s", identifier, pkg.Ecosystem, pkg.Name, pkg.Version)
			}
			seenForPackage[identifier] = struct{}{}
			seenVulnerabilities[identifier] = struct{}{}
		}
	}
	if snapshot.OSVSync.Packages != len(snapshot.Packages) || snapshot.OSVSync.Vulnerabilities != len(seenVulnerabilities) {
		return FeedImport{}, kev.Catalog{}, errors.New("OSV snapshot counts do not match its contents")
	}
	if strings.TrimSpace(snapshot.KEVSync.Source) == "" || strings.TrimSpace(snapshot.KEVSync.Source) != snapshot.KEVSync.Source || snapshot.KEVSync.SynchronizedAt.IsZero() || snapshot.KEVSync.DateReleased.IsZero() {
		return FeedImport{}, kev.Catalog{}, errors.New("complete CISA KEV snapshot metadata is required")
	}
	catalog := kev.Catalog{
		CatalogVersion: snapshot.KEVSync.CatalogVersion,
		DateReleased:   snapshot.KEVSync.DateReleased.UTC().Format(time.RFC3339),
		Count:          len(snapshot.KEVEntries), Vulnerabilities: append([]kev.Vulnerability(nil), snapshot.KEVEntries...),
		SourceURL: snapshot.KEVSync.Source,
	}
	if err := kev.ValidateCatalog(&catalog); err != nil {
		return FeedImport{}, kev.Catalog{}, err
	}
	if catalog.CatalogVersion != snapshot.KEVSync.CatalogVersion {
		return FeedImport{}, kev.Catalog{}, errors.New("CISA KEV catalog version is not normalized")
	}
	if snapshot.KEVSync.Entries != len(catalog.Vulnerabilities) {
		return FeedImport{}, kev.Catalog{}, errors.New("CISA KEV snapshot count does not match its contents")
	}
	latestSource := snapshot.OSVSync.SynchronizedAt
	if snapshot.KEVSync.SynchronizedAt.After(latestSource) {
		latestSource = snapshot.KEVSync.SynchronizedAt
	}
	if latestSource.After(metadata.BundleCreatedAt.Add(time.Minute)) {
		return FeedImport{}, kev.Catalog{}, errors.New("feed source timestamp is later than bundle creation time")
	}
	return FeedImport{
		FormatVersion:   metadata.FormatVersion,
		BundleCreatedAt: metadata.BundleCreatedAt.UTC(),
		ImportedAt:      time.Now().UTC().Truncate(time.Second),
		SourceName:      metadata.SourceName, ManifestSHA256: metadata.ManifestSHA256,
		OSVSynchronizedAt: snapshot.OSVSync.SynchronizedAt.UTC(),
		KEVSynchronizedAt: snapshot.KEVSync.SynchronizedAt.UTC(),
		Packages:          len(snapshot.Packages), Vulnerabilities: len(seenVulnerabilities),
		KEVEntries: len(catalog.Vulnerabilities),
	}, catalog, nil
}

func replaceOSVSnapshot(ctx context.Context, transaction *sql.Tx, syncResult VulnerabilitySync, snapshots []PackageSnapshot) error {
	insert, err := transaction.ExecContext(ctx, `INSERT INTO vulnerability_syncs(
		source, synchronized_at, package_count, vulnerability_count
	) VALUES (?, ?, ?, ?)`, syncResult.Source, formatTime(syncResult.SynchronizedAt), syncResult.Packages, syncResult.Vulnerabilities)
	if err != nil {
		return fmt.Errorf("record imported OSV sync: %w", err)
	}
	syncID, err := insert.LastInsertId()
	if err != nil {
		return fmt.Errorf("read imported OSV sync ID: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM package_snapshots"); err != nil {
		return fmt.Errorf("replace imported package snapshots: %w", err)
	}
	for _, snapshot := range snapshots {
		packageInsert, err := transaction.ExecContext(ctx, `INSERT INTO package_snapshots(
			sync_id, ecosystem, name, version
		) VALUES (?, ?, ?, ?)`, syncID, snapshot.Package.Ecosystem, snapshot.Package.Name, snapshot.Package.Version)
		if err != nil {
			return fmt.Errorf("store imported package snapshot %s@%s: %w", snapshot.Package.Name, snapshot.Package.Version, err)
		}
		packageID, err := packageInsert.LastInsertId()
		if err != nil {
			return fmt.Errorf("read imported package snapshot ID: %w", err)
		}
		for _, vulnerability := range snapshot.Vulnerabilities {
			aliasesJSON, err := json.Marshal(nonNilStrings(vulnerability.Aliases))
			if err != nil {
				return fmt.Errorf("encode imported aliases for %s: %w", vulnerability.ID, err)
			}
			severityJSON, err := json.Marshal(nonNilSeverities(vulnerability.Severity))
			if err != nil {
				return fmt.Errorf("encode imported severity for %s: %w", vulnerability.ID, err)
			}
			affectedJSON, err := json.Marshal(nonNilAffected(vulnerability.Affected))
			if err != nil {
				return fmt.Errorf("encode imported affected data for %s: %w", vulnerability.ID, err)
			}
			_, err = transaction.ExecContext(ctx, `INSERT INTO vulnerabilities(
				source, source_id, summary, details, published, modified, withdrawn,
				aliases_json, severity_json, affected_json, updated_at
			) VALUES ('OSV', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
			ON CONFLICT(source, source_id) DO UPDATE SET
				summary = excluded.summary, details = excluded.details,
				published = excluded.published, modified = excluded.modified,
				withdrawn = excluded.withdrawn, aliases_json = excluded.aliases_json,
				severity_json = excluded.severity_json, affected_json = excluded.affected_json,
				updated_at = excluded.updated_at`,
				vulnerability.ID, vulnerability.Summary, vulnerability.Details,
				vulnerability.Published, vulnerability.Modified, vulnerability.Withdrawn,
				string(aliasesJSON), string(severityJSON), string(affectedJSON), formatTime(syncResult.SynchronizedAt))
			if err != nil {
				return fmt.Errorf("store imported vulnerability %s: %w", vulnerability.ID, err)
			}
			var vulnerabilityID int64
			if err := transaction.QueryRowContext(ctx,
				"SELECT id FROM vulnerabilities WHERE source = 'OSV' AND source_id = ?", vulnerability.ID,
			).Scan(&vulnerabilityID); err != nil {
				return fmt.Errorf("read imported vulnerability %s: %w", vulnerability.ID, err)
			}
			if _, err := transaction.ExecContext(ctx, "DELETE FROM vulnerability_aliases WHERE vulnerability_id = ?", vulnerabilityID); err != nil {
				return fmt.Errorf("replace imported aliases for %s: %w", vulnerability.ID, err)
			}
			for _, alias := range vulnerability.Aliases {
				if _, err := transaction.ExecContext(ctx,
					"INSERT OR IGNORE INTO vulnerability_aliases(vulnerability_id, alias) VALUES (?, ?)", vulnerabilityID, alias,
				); err != nil {
					return fmt.Errorf("store imported alias for %s: %w", vulnerability.ID, err)
				}
			}
			if _, err := transaction.ExecContext(ctx, `INSERT INTO package_vulnerability_matches(
				package_snapshot_id, vulnerability_id
			) VALUES (?, ?)`, packageID, vulnerabilityID); err != nil {
				return fmt.Errorf("store imported match for %s: %w", vulnerability.ID, err)
			}
		}
	}
	if _, err := transaction.ExecContext(ctx, `DELETE FROM vulnerabilities
		WHERE id NOT IN (SELECT vulnerability_id FROM package_vulnerability_matches)`); err != nil {
		return fmt.Errorf("remove stale imported vulnerabilities: %w", err)
	}
	return nil
}

func replaceKEVSnapshot(ctx context.Context, transaction *sql.Tx, syncResult KEVSync, catalog kev.Catalog) error {
	insert, err := transaction.ExecContext(ctx, `INSERT INTO kev_syncs(
		source, catalog_version, date_released, synchronized_at, entry_count
	) VALUES (?, ?, ?, ?, ?)`, syncResult.Source, syncResult.CatalogVersion,
		formatTime(syncResult.DateReleased), formatTime(syncResult.SynchronizedAt), syncResult.Entries)
	if err != nil {
		return fmt.Errorf("record imported CISA KEV sync: %w", err)
	}
	syncID, err := insert.LastInsertId()
	if err != nil {
		return fmt.Errorf("read imported CISA KEV sync ID: %w", err)
	}
	if _, err := transaction.ExecContext(ctx, "DELETE FROM kev_syncs WHERE id <> ?", syncID); err != nil {
		return fmt.Errorf("replace imported CISA KEV snapshot: %w", err)
	}
	for _, entry := range catalog.Vulnerabilities {
		cwesJSON, err := json.Marshal(nonNilStrings(entry.CWEs))
		if err != nil {
			return fmt.Errorf("encode imported CWEs for %s: %w", entry.CVEID, err)
		}
		if _, err := transaction.ExecContext(ctx, `INSERT INTO kev_entries(
			cve_id, sync_id, vendor_project, product, vulnerability_name,
			date_added, short_description, required_action, due_date,
			known_ransomware_campaign_use, forensic_triage, notes, cwes_json
		) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			entry.CVEID, syncID, entry.VendorProject, entry.Product,
			entry.VulnerabilityName, entry.DateAdded, entry.ShortDescription,
			entry.RequiredAction, entry.DueDate, entry.KnownRansomwareCampaignUse,
			entry.ForensicTriage, entry.Notes, string(cwesJSON),
		); err != nil {
			return fmt.Errorf("store imported CISA KEV entry %s: %w", entry.CVEID, err)
		}
	}
	return nil
}
