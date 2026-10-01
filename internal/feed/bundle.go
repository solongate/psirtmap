// Package feed creates and validates portable PSIRTMap vulnerability-data
// bundles for controlled transfer into disconnected environments.
package feed

import (
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/solongate/psirtmap/internal/kev"
	"github.com/solongate/psirtmap/internal/store"
)

const (
	Format        = "psirtmap-offline-feed"
	FormatVersion = 1

	manifestName = "manifest.json"
	osvName      = "osv.json"
	kevName      = "cisa-kev.json"

	maxBundleSize   = 256 << 20
	maxManifestSize = 1 << 20
	maxOSVSize      = 192 << 20
	maxKEVSize      = 48 << 20
	maxPackages     = 1_000_000
	maxKEVEntries   = 100_000
)

// Snapshot contains the intelligence copied into a portable bundle.
type Snapshot struct {
	OSV     OSVSnapshot
	CISAKEV KEVSnapshot
}

// OSVSnapshot is one complete inventory-scoped OSV snapshot.
type OSVSnapshot struct {
	Source         string                  `json:"source"`
	SynchronizedAt time.Time               `json:"synchronized_at"`
	Packages       []store.PackageSnapshot `json:"packages"`
}

// KEVSnapshot is one complete CISA Known Exploited Vulnerabilities catalog.
type KEVSnapshot struct {
	Source          string              `json:"source"`
	CatalogVersion  string              `json:"catalog_version"`
	DateReleased    time.Time           `json:"date_released"`
	SynchronizedAt  time.Time           `json:"synchronized_at"`
	Vulnerabilities []kev.Vulnerability `json:"vulnerabilities"`
}

// Info describes a validated bundle without exposing its complete payload.
type Info struct {
	Path            string    `json:"path"`
	Format          string    `json:"format"`
	FormatVersion   int       `json:"format_version"`
	CreatedAt       time.Time `json:"created_at"`
	ManifestSHA256  string    `json:"manifest_sha256"`
	Packages        int       `json:"packages"`
	Vulnerabilities int       `json:"vulnerabilities"`
	KEVEntries      int       `json:"kev_entries"`
}

type manifest struct {
	Format        string           `json:"format"`
	FormatVersion int              `json:"format_version"`
	CreatedAt     time.Time        `json:"created_at"`
	Generator     string           `json:"generator"`
	Contents      manifestContents `json:"contents"`
	Files         []manifestFile   `json:"files"`
}

type manifestContents struct {
	Packages        int `json:"packages"`
	Vulnerabilities int `json:"vulnerabilities"`
	KEVEntries      int `json:"kev_entries"`
}

type manifestFile struct {
	Name   string `json:"name"`
	Size   int64  `json:"size"`
	SHA256 string `json:"sha256"`
}

// Write creates a new bundle atomically. Existing files are never replaced.
func Write(path, generator string, snapshot Snapshot, createdAt time.Time) (Info, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Info{}, errors.New("feed bundle path is required")
	}
	if createdAt.IsZero() {
		createdAt = time.Now().UTC()
	}
	createdAt = createdAt.UTC().Truncate(time.Second)
	if err := validateSnapshot(snapshot, createdAt); err != nil {
		return Info{}, err
	}

	osvBytes, err := marshalDocument(snapshot.OSV)
	if err != nil {
		return Info{}, fmt.Errorf("encode OSV feed data: %w", err)
	}
	kevBytes, err := marshalDocument(snapshot.CISAKEV)
	if err != nil {
		return Info{}, fmt.Errorf("encode CISA KEV feed data: %w", err)
	}
	if len(osvBytes) > maxOSVSize || len(kevBytes) > maxKEVSize {
		return Info{}, errors.New("feed data exceeds the supported bundle size")
	}

	contents := countContents(snapshot)
	manifestValue := manifest{
		Format: Format, FormatVersion: FormatVersion, CreatedAt: createdAt,
		Generator: strings.TrimSpace(generator), Contents: contents,
		Files: []manifestFile{
			{Name: osvName, Size: int64(len(osvBytes)), SHA256: digest(osvBytes)},
			{Name: kevName, Size: int64(len(kevBytes)), SHA256: digest(kevBytes)},
		},
	}
	manifestBytes, err := marshalDocument(manifestValue)
	if err != nil {
		return Info{}, fmt.Errorf("encode feed manifest: %w", err)
	}

	parent := filepath.Dir(path)
	if _, err := os.Stat(path); err == nil {
		return Info{}, fmt.Errorf("feed bundle %q already exists", path)
	} else if !errors.Is(err, os.ErrNotExist) {
		return Info{}, fmt.Errorf("inspect feed bundle target: %w", err)
	}
	temporary, err := os.CreateTemp(parent, ".psirtmap-feed-*.tmp")
	if err != nil {
		return Info{}, fmt.Errorf("create temporary feed bundle: %w", err)
	}
	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)
	if err := temporary.Chmod(0o600); err != nil {
		temporary.Close()
		return Info{}, fmt.Errorf("secure temporary feed bundle: %w", err)
	}

	zipWriter := zip.NewWriter(temporary)
	for _, file := range []struct {
		name string
		data []byte
	}{{manifestName, manifestBytes}, {osvName, osvBytes}, {kevName, kevBytes}} {
		header := &zip.FileHeader{Name: file.name, Method: zip.Deflate}
		header.SetModTime(createdAt)
		header.SetMode(0o600)
		entry, createErr := zipWriter.CreateHeader(header)
		if createErr != nil {
			zipWriter.Close()
			temporary.Close()
			return Info{}, fmt.Errorf("create %s in feed bundle: %w", file.name, createErr)
		}
		if _, writeErr := entry.Write(file.data); writeErr != nil {
			zipWriter.Close()
			temporary.Close()
			return Info{}, fmt.Errorf("write %s to feed bundle: %w", file.name, writeErr)
		}
	}
	if err := zipWriter.Close(); err != nil {
		temporary.Close()
		return Info{}, fmt.Errorf("finalize feed bundle: %w", err)
	}
	if err := temporary.Sync(); err != nil {
		temporary.Close()
		return Info{}, fmt.Errorf("flush feed bundle: %w", err)
	}
	if err := temporary.Close(); err != nil {
		return Info{}, fmt.Errorf("close feed bundle: %w", err)
	}
	if err := publishNoReplace(temporaryPath, path); err != nil {
		return Info{}, err
	}
	return newInfo(path, manifestValue, manifestBytes), nil
}

// Read validates a bundle's structure, checksums, counts, and source payloads.
func Read(path string) (Snapshot, Info, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Snapshot{}, Info{}, errors.New("feed bundle path is required")
	}
	stat, err := os.Stat(path)
	if err != nil {
		return Snapshot{}, Info{}, fmt.Errorf("open feed bundle: %w", err)
	}
	if !stat.Mode().IsRegular() {
		return Snapshot{}, Info{}, errors.New("feed bundle must be a regular file")
	}
	if stat.Size() > maxBundleSize {
		return Snapshot{}, Info{}, fmt.Errorf("feed bundle exceeds %d bytes", maxBundleSize)
	}

	reader, err := zip.OpenReader(path)
	if err != nil {
		return Snapshot{}, Info{}, fmt.Errorf("open feed bundle ZIP: %w", err)
	}
	defer reader.Close()
	if len(reader.File) != 3 {
		return Snapshot{}, Info{}, fmt.Errorf("feed bundle contains %d files; want exactly 3", len(reader.File))
	}
	limits := map[string]int64{manifestName: maxManifestSize, osvName: maxOSVSize, kevName: maxKEVSize}
	files := make(map[string][]byte, len(limits))
	for _, file := range reader.File {
		limit, expected := limits[file.Name]
		if !expected || strings.Contains(file.Name, "/") || file.FileInfo().IsDir() {
			return Snapshot{}, Info{}, fmt.Errorf("unexpected feed bundle entry %q", file.Name)
		}
		if _, duplicate := files[file.Name]; duplicate {
			return Snapshot{}, Info{}, fmt.Errorf("duplicate feed bundle entry %q", file.Name)
		}
		if file.UncompressedSize64 > uint64(limit) {
			return Snapshot{}, Info{}, fmt.Errorf("feed bundle entry %q exceeds %d bytes", file.Name, limit)
		}
		content, readErr := readZipFile(file, limit)
		if readErr != nil {
			return Snapshot{}, Info{}, readErr
		}
		files[file.Name] = content
	}

	var manifestValue manifest
	if err := decodeStrict(files[manifestName], &manifestValue); err != nil {
		return Snapshot{}, Info{}, fmt.Errorf("decode feed manifest: %w", err)
	}
	if err := validateManifest(manifestValue, files); err != nil {
		return Snapshot{}, Info{}, err
	}
	var snapshot Snapshot
	if err := decodeStrict(files[osvName], &snapshot.OSV); err != nil {
		return Snapshot{}, Info{}, fmt.Errorf("decode OSV feed data: %w", err)
	}
	if err := decodeStrict(files[kevName], &snapshot.CISAKEV); err != nil {
		return Snapshot{}, Info{}, fmt.Errorf("decode CISA KEV feed data: %w", err)
	}
	if err := validateSnapshot(snapshot, manifestValue.CreatedAt); err != nil {
		return Snapshot{}, Info{}, err
	}
	if actual := countContents(snapshot); actual != manifestValue.Contents {
		return Snapshot{}, Info{}, fmt.Errorf("feed content counts do not match manifest: got %+v, want %+v", actual, manifestValue.Contents)
	}
	return snapshot, newInfo(path, manifestValue, files[manifestName]), nil
}

func validateSnapshot(snapshot Snapshot, createdAt time.Time) error {
	if strings.TrimSpace(snapshot.OSV.Source) == "" {
		return errors.New("OSV feed source is required")
	}
	if snapshot.OSV.SynchronizedAt.IsZero() {
		return errors.New("OSV synchronization time is required")
	}
	if len(snapshot.OSV.Packages) == 0 {
		return errors.New("OSV feed contains no package snapshots")
	}
	if len(snapshot.OSV.Packages) > maxPackages {
		return fmt.Errorf("OSV feed contains more than %d package snapshots", maxPackages)
	}
	seenPackages := make(map[store.PackageVersion]struct{}, len(snapshot.OSV.Packages))
	for _, packageSnapshot := range snapshot.OSV.Packages {
		pkg := packageSnapshot.Package
		if strings.TrimSpace(pkg.Ecosystem) == "" || strings.TrimSpace(pkg.Name) == "" || strings.TrimSpace(pkg.Version) == "" {
			return errors.New("OSV feed contains an incomplete package identity")
		}
		if _, exists := seenPackages[pkg]; exists {
			return fmt.Errorf("OSV feed contains duplicate package %s:%s@%s", pkg.Ecosystem, pkg.Name, pkg.Version)
		}
		seenPackages[pkg] = struct{}{}
		seenVulnerabilities := make(map[string]struct{}, len(packageSnapshot.Vulnerabilities))
		for _, vulnerability := range packageSnapshot.Vulnerabilities {
			identifier := strings.TrimSpace(vulnerability.ID)
			if identifier == "" {
				return errors.New("OSV feed contains a vulnerability without an ID")
			}
			if _, exists := seenVulnerabilities[identifier]; exists {
				return fmt.Errorf("OSV feed contains duplicate vulnerability %s for %s:%s@%s", identifier, pkg.Ecosystem, pkg.Name, pkg.Version)
			}
			seenVulnerabilities[identifier] = struct{}{}
		}
	}
	if strings.TrimSpace(snapshot.CISAKEV.Source) == "" {
		return errors.New("CISA KEV feed source is required")
	}
	if snapshot.CISAKEV.SynchronizedAt.IsZero() || snapshot.CISAKEV.DateReleased.IsZero() {
		return errors.New("CISA KEV feed timestamps are required")
	}
	if len(snapshot.CISAKEV.Vulnerabilities) > maxKEVEntries {
		return fmt.Errorf("CISA KEV feed contains more than %d entries", maxKEVEntries)
	}
	catalog := kev.Catalog{
		CatalogVersion:  snapshot.CISAKEV.CatalogVersion,
		DateReleased:    snapshot.CISAKEV.DateReleased.UTC().Format(time.RFC3339),
		Count:           len(snapshot.CISAKEV.Vulnerabilities),
		Vulnerabilities: append([]kev.Vulnerability(nil), snapshot.CISAKEV.Vulnerabilities...),
	}
	if err := kev.ValidateCatalog(&catalog); err != nil {
		return fmt.Errorf("validate CISA KEV feed data: %w", err)
	}
	if !createdAt.IsZero() {
		latestSource := snapshot.OSV.SynchronizedAt
		if snapshot.CISAKEV.SynchronizedAt.After(latestSource) {
			latestSource = snapshot.CISAKEV.SynchronizedAt
		}
		if latestSource.After(createdAt.Add(time.Minute)) {
			return errors.New("feed source timestamp is later than bundle creation time")
		}
	}
	return nil
}

func validateManifest(value manifest, files map[string][]byte) error {
	if value.Format != Format {
		return fmt.Errorf("unsupported feed format %q", value.Format)
	}
	if value.FormatVersion != FormatVersion {
		return fmt.Errorf("unsupported feed format version %d", value.FormatVersion)
	}
	if value.CreatedAt.IsZero() {
		return errors.New("feed manifest creation time is required")
	}
	if value.CreatedAt.After(time.Now().UTC().Add(5 * time.Minute)) {
		return errors.New("feed manifest creation time is in the future")
	}
	if len(value.Files) != 2 {
		return fmt.Errorf("feed manifest describes %d data files; want 2", len(value.Files))
	}
	seen := make(map[string]struct{}, 2)
	for _, entry := range value.Files {
		if entry.Name != osvName && entry.Name != kevName {
			return fmt.Errorf("feed manifest contains unexpected file %q", entry.Name)
		}
		if _, duplicate := seen[entry.Name]; duplicate {
			return fmt.Errorf("feed manifest contains duplicate file %q", entry.Name)
		}
		seen[entry.Name] = struct{}{}
		data := files[entry.Name]
		if entry.Size != int64(len(data)) {
			return fmt.Errorf("feed file %q size mismatch", entry.Name)
		}
		if entry.SHA256 != digest(data) {
			return fmt.Errorf("feed file %q checksum mismatch", entry.Name)
		}
	}
	return nil
}

func countContents(snapshot Snapshot) manifestContents {
	identifiers := make(map[string]struct{})
	for _, packageSnapshot := range snapshot.OSV.Packages {
		for _, vulnerability := range packageSnapshot.Vulnerabilities {
			identifiers[vulnerability.ID] = struct{}{}
		}
	}
	return manifestContents{
		Packages: len(snapshot.OSV.Packages), Vulnerabilities: len(identifiers),
		KEVEntries: len(snapshot.CISAKEV.Vulnerabilities),
	}
}

func newInfo(path string, value manifest, manifestBytes []byte) Info {
	return Info{
		Path: path, Format: value.Format, FormatVersion: value.FormatVersion,
		CreatedAt: value.CreatedAt, ManifestSHA256: digest(manifestBytes),
		Packages: value.Contents.Packages, Vulnerabilities: value.Contents.Vulnerabilities,
		KEVEntries: value.Contents.KEVEntries,
	}
}

func marshalDocument(value any) ([]byte, error) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return nil, err
	}
	return append(data, '\n'), nil
}

func decodeStrict(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("unexpected trailing JSON value")
		}
		return err
	}
	return nil
}

func readZipFile(file *zip.File, limit int64) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, fmt.Errorf("open feed bundle entry %q: %w", file.Name, err)
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, fmt.Errorf("read feed bundle entry %q: %w", file.Name, err)
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("feed bundle entry %q exceeds %d bytes", file.Name, limit)
	}
	return data, nil
}

func digest(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func publishNoReplace(temporaryPath, targetPath string) error {
	// Hard-linking is atomic and cannot replace an existing destination. Some
	// removable filesystems do not support links, so fall back to an exclusive
	// copy while retaining the no-overwrite guarantee.
	if err := os.Link(temporaryPath, targetPath); err == nil {
		_ = os.Remove(temporaryPath)
		return nil
	}
	source, err := os.Open(temporaryPath)
	if err != nil {
		return fmt.Errorf("reopen temporary feed bundle: %w", err)
	}
	defer source.Close()
	target, err := os.OpenFile(targetPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("publish feed bundle: %w", err)
	}
	complete := false
	defer func() {
		target.Close()
		if !complete {
			_ = os.Remove(targetPath)
		}
	}()
	if _, err := io.Copy(target, source); err != nil {
		return fmt.Errorf("copy feed bundle to destination: %w", err)
	}
	if err := target.Sync(); err != nil {
		return fmt.Errorf("flush published feed bundle: %w", err)
	}
	if err := target.Close(); err != nil {
		return fmt.Errorf("close published feed bundle: %w", err)
	}
	complete = true
	_ = os.Remove(temporaryPath)
	return nil
}

// Sort makes exported snapshots deterministic before they are serialized.
func Sort(snapshot *Snapshot) {
	if snapshot == nil {
		return
	}
	sort.Slice(snapshot.OSV.Packages, func(i, j int) bool {
		left, right := snapshot.OSV.Packages[i].Package, snapshot.OSV.Packages[j].Package
		if left.Ecosystem != right.Ecosystem {
			return left.Ecosystem < right.Ecosystem
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		return left.Version < right.Version
	})
	for index := range snapshot.OSV.Packages {
		sort.Slice(snapshot.OSV.Packages[index].Vulnerabilities, func(i, j int) bool {
			return snapshot.OSV.Packages[index].Vulnerabilities[i].ID < snapshot.OSV.Packages[index].Vulnerabilities[j].ID
		})
	}
	sort.Slice(snapshot.CISAKEV.Vulnerabilities, func(i, j int) bool {
		return snapshot.CISAKEV.Vulnerabilities[i].CVEID < snapshot.CISAKEV.Vulnerabilities[j].CVEID
	})
}
