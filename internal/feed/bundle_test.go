package feed

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/solongate/psirtmap/internal/kev"
	"github.com/solongate/psirtmap/internal/osv"
	"github.com/solongate/psirtmap/internal/store"
)

func TestBundleRoundTripAndNoOverwrite(t *testing.T) {
	t.Parallel()
	createdAt := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	path := filepath.Join(t.TempDir(), "feed.bundle")
	snapshot := testSnapshot(createdAt)
	info, err := Write(path, "PSIRTMap test", snapshot, createdAt)
	if err != nil {
		t.Fatalf("Write() error = %v", err)
	}
	if info.Packages != 1 || info.Vulnerabilities != 1 || info.KEVEntries != 1 || len(info.ManifestSHA256) != 64 {
		t.Fatalf("Write() info = %+v", info)
	}
	stat, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat() error = %v", err)
	}
	if stat.Mode().Perm() != 0o600 {
		t.Fatalf("bundle permissions = %o, want 600", stat.Mode().Perm())
	}
	got, readInfo, err := Read(path)
	if err != nil {
		t.Fatalf("Read() error = %v", err)
	}
	if got.OSV.Packages[0].Vulnerabilities[0].ID != "OSV-2026-1" ||
		got.CISAKEV.Vulnerabilities[0].CVEID != "CVE-2026-12345" ||
		readInfo.ManifestSHA256 != info.ManifestSHA256 {
		t.Fatalf("Read() snapshot = %+v, info = %+v", got, readInfo)
	}
	if _, err := Write(path, "PSIRTMap test", snapshot, createdAt); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second Write() error = %v", err)
	}
}

func TestBundleRejectsTamperedAndUnexpectedFiles(t *testing.T) {
	t.Parallel()
	createdAt := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	directory := t.TempDir()
	validPath := filepath.Join(directory, "valid.bundle")
	if _, err := Write(validPath, "PSIRTMap test", testSnapshot(createdAt), createdAt); err != nil {
		t.Fatalf("Write() error = %v", err)
	}

	tamperedPath := filepath.Join(directory, "tampered.bundle")
	rewriteBundle(t, validPath, tamperedPath, func(name string, data []byte) []byte {
		if name == osvName {
			return bytes.Replace(data, []byte("OSV-2026-1"), []byte("OSV-2026-X"), 1)
		}
		return data
	}, "")
	if _, _, err := Read(tamperedPath); err == nil || !strings.Contains(err.Error(), "checksum mismatch") {
		t.Fatalf("Read(tampered) error = %v", err)
	}

	extraPath := filepath.Join(directory, "extra.bundle")
	rewriteBundle(t, validPath, extraPath, func(_ string, data []byte) []byte { return data }, "../unexpected.json")
	if _, _, err := Read(extraPath); err == nil || !strings.Contains(err.Error(), "want exactly 3") {
		t.Fatalf("Read(extra) error = %v", err)
	}
}

func TestBundleRejectsInvalidSourceData(t *testing.T) {
	t.Parallel()
	createdAt := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name   string
		mutate func(*Snapshot)
		want   string
	}{
		{name: "no packages", mutate: func(value *Snapshot) { value.OSV.Packages = nil }, want: "no package snapshots"},
		{name: "duplicate package", mutate: func(value *Snapshot) { value.OSV.Packages = append(value.OSV.Packages, value.OSV.Packages[0]) }, want: "duplicate package"},
		{name: "invalid KEV", mutate: func(value *Snapshot) { value.CISAKEV.Vulnerabilities[0].CVEID = "not-a-cve" }, want: "invalid CISA KEV"},
		{name: "future source", mutate: func(value *Snapshot) { value.OSV.SynchronizedAt = createdAt.Add(2 * time.Minute) }, want: "later than bundle"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			value := testSnapshot(createdAt)
			test.mutate(&value)
			_, err := Write(filepath.Join(t.TempDir(), "feed.bundle"), "test", value, createdAt)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Write() error = %v, want %q", err, test.want)
			}
		})
	}
}

func testSnapshot(createdAt time.Time) Snapshot {
	synchronizedAt := createdAt.Add(-time.Hour)
	return Snapshot{
		OSV: OSVSnapshot{
			Source: "OSV", SynchronizedAt: synchronizedAt,
			Packages: []store.PackageSnapshot{{
				Package:         store.PackageVersion{Ecosystem: "npm", Name: "demo", Version: "1.0.0"},
				Vulnerabilities: []osv.Vulnerability{{ID: "OSV-2026-1", Aliases: []string{"CVE-2026-12345"}}},
			}},
		},
		CISAKEV: KEVSnapshot{
			Source: "https://example.test/kev.json", CatalogVersion: "2026.10.01",
			DateReleased: synchronizedAt, SynchronizedAt: synchronizedAt,
			Vulnerabilities: []kev.Vulnerability{{
				CVEID: "CVE-2026-12345", VendorProject: "Example", Product: "Demo",
				VulnerabilityName: "Demo issue", DateAdded: "2026-09-01",
				ShortDescription: "Example description", RequiredAction: "Apply update",
				DueDate: "2026-10-01", CWEs: []string{"CWE-79"},
			}},
		},
	}
}

func rewriteBundle(
	t *testing.T,
	sourcePath, targetPath string,
	transform func(string, []byte) []byte,
	extraName string,
) {
	t.Helper()
	reader, err := zip.OpenReader(sourcePath)
	if err != nil {
		t.Fatalf("open source ZIP: %v", err)
	}
	defer reader.Close()
	target, err := os.Create(targetPath)
	if err != nil {
		t.Fatalf("create target ZIP: %v", err)
	}
	writer := zip.NewWriter(target)
	for _, file := range reader.File {
		opened, err := file.Open()
		if err != nil {
			t.Fatalf("open ZIP entry: %v", err)
		}
		data, err := io.ReadAll(opened)
		opened.Close()
		if err != nil {
			t.Fatalf("read ZIP entry: %v", err)
		}
		entry, err := writer.Create(file.Name)
		if err != nil {
			t.Fatalf("create ZIP entry: %v", err)
		}
		if _, err := entry.Write(transform(file.Name, data)); err != nil {
			t.Fatalf("write ZIP entry: %v", err)
		}
	}
	if extraName != "" {
		entry, err := writer.Create(extraName)
		if err != nil {
			t.Fatalf("create extra ZIP entry: %v", err)
		}
		if _, err := entry.Write([]byte("{}")); err != nil {
			t.Fatalf("write extra ZIP entry: %v", err)
		}
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("close target ZIP: %v", err)
	}
	if err := target.Close(); err != nil {
		t.Fatalf("close target file: %v", err)
	}
}
