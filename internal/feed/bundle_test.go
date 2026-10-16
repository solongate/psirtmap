package feed

import (
	"archive/zip"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/solongate/psirtmap/internal/kev"
	"github.com/solongate/psirtmap/internal/osv"
	"github.com/solongate/psirtmap/internal/store"
)

func FuzzReadBundle(f *testing.F) {
	createdAt := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	seedPath := filepath.Join(f.TempDir(), "valid.bundle")
	if _, err := Write(seedPath, "PSIRTMap fuzz seed", testSnapshot(createdAt), createdAt); err != nil {
		f.Fatalf("create valid fuzz seed: %v", err)
	}
	valid, err := os.ReadFile(seedPath)
	if err != nil {
		f.Fatalf("read valid fuzz seed: %v", err)
	}
	f.Add(valid)
	privatePath := filepath.Join(f.TempDir(), "fuzz-signing-key.pem")
	publicPath := filepath.Join(f.TempDir(), "fuzz-signing-key.pub.pem")
	if _, err := GenerateKeyPair(privatePath, publicPath); err != nil {
		f.Fatalf("create fuzz signing key: %v", err)
	}
	signingKey, err := LoadSigningKey(privatePath)
	if err != nil {
		f.Fatalf("load fuzz signing key: %v", err)
	}
	signedPath := filepath.Join(f.TempDir(), "signed.bundle")
	if _, err := WriteWithOptions(
		signedPath, "PSIRTMap signed fuzz seed", testSnapshot(createdAt), createdAt,
		WriteOptions{SigningKey: &signingKey},
	); err != nil {
		f.Fatalf("create signed fuzz seed: %v", err)
	}
	signed, err := os.ReadFile(signedPath)
	if err != nil {
		f.Fatalf("read signed fuzz seed: %v", err)
	}
	f.Add(signed)
	f.Add([]byte("not-a-zip"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		path := filepath.Join(t.TempDir(), "input.bundle")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatalf("write fuzz bundle: %v", err)
		}
		_, _, _ = Read(path)
	})
}

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
	if _, _, err := Read(extraPath); err == nil || !strings.Contains(err.Error(), "unexpected feed bundle entry") {
		t.Fatalf("Read(extra) error = %v", err)
	}
}

func TestSignedBundleRequiresAndVerifiesTrustedKey(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "feed-signing.pem")
	publicPath := filepath.Join(directory, "feed-signing.pub.pem")
	keyID, err := GenerateKeyPair(privatePath, publicPath)
	if err != nil {
		t.Fatalf("GenerateKeyPair() error = %v", err)
	}
	if !strings.HasPrefix(keyID, "sha256:") || len(keyID) != len("sha256:")+64 {
		t.Fatalf("GenerateKeyPair() key ID = %q", keyID)
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(privatePath)
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("private key mode = %v, %v; want 0600", info.Mode().Perm(), err)
		}
	}
	signingKey, err := LoadSigningKey(privatePath)
	if err != nil {
		t.Fatalf("LoadSigningKey() error = %v", err)
	}
	trustedKey, err := LoadTrustedKey(publicPath)
	if err != nil {
		t.Fatalf("LoadTrustedKey() error = %v", err)
	}
	if signingKey.KeyID() != keyID || trustedKey.KeyID() != keyID {
		t.Fatalf("loaded key IDs = %q/%q, want %q", signingKey.KeyID(), trustedKey.KeyID(), keyID)
	}

	createdAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	bundlePath := filepath.Join(directory, "signed.bundle")
	writeInfo, err := WriteWithOptions(
		bundlePath, "PSIRTMap signed test", testSnapshot(createdAt), createdAt,
		WriteOptions{SigningKey: &signingKey},
	)
	if err != nil {
		t.Fatalf("WriteWithOptions() error = %v", err)
	}
	if writeInfo.FormatVersion != SignedFormatVersion || !writeInfo.Signed ||
		writeInfo.SignatureVerified || writeInfo.SignerKeyID != keyID {
		t.Fatalf("WriteWithOptions() info = %+v", writeInfo)
	}

	_, unverifiedInfo, err := Read(bundlePath)
	if err != nil {
		t.Fatalf("Read(signed) error = %v", err)
	}
	if !unverifiedInfo.Signed || unverifiedInfo.SignatureVerified || unverifiedInfo.SignerKeyID != keyID {
		t.Fatalf("Read(signed) info = %+v", unverifiedInfo)
	}
	_, verifiedInfo, err := ReadWithPolicy(bundlePath, VerificationPolicy{
		TrustedKeys: []TrustedKey{trustedKey}, RequireSignature: true,
	})
	if err != nil {
		t.Fatalf("ReadWithPolicy() error = %v", err)
	}
	if !verifiedInfo.Signed || !verifiedInfo.SignatureVerified || verifiedInfo.SignerKeyID != keyID {
		t.Fatalf("ReadWithPolicy() info = %+v", verifiedInfo)
	}
	if _, err := GenerateKeyPair(privatePath, publicPath); err == nil || !strings.Contains(err.Error(), "already exists") {
		t.Fatalf("second GenerateKeyPair() error = %v", err)
	}
}

func TestSignedBundleRejectsWrongKeyTamperingAndUnsignedPolicy(t *testing.T) {
	t.Parallel()
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "signing.pem")
	publicPath := filepath.Join(directory, "signing.pub.pem")
	if _, err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	signingKey, err := LoadSigningKey(privatePath)
	if err != nil {
		t.Fatal(err)
	}
	createdAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Second)
	signedPath := filepath.Join(directory, "signed.bundle")
	if _, err := WriteWithOptions(signedPath, "PSIRTMap test", testSnapshot(createdAt), createdAt, WriteOptions{SigningKey: &signingKey}); err != nil {
		t.Fatal(err)
	}

	otherPrivate := filepath.Join(directory, "other.pem")
	otherPublic := filepath.Join(directory, "other.pub.pem")
	if _, err := GenerateKeyPair(otherPrivate, otherPublic); err != nil {
		t.Fatal(err)
	}
	otherTrusted, err := LoadTrustedKey(otherPublic)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadWithPolicy(signedPath, VerificationPolicy{
		TrustedKeys: []TrustedKey{otherTrusted}, RequireSignature: true,
	}); err == nil || !strings.Contains(err.Error(), "is not trusted") {
		t.Fatalf("ReadWithPolicy(wrong key) error = %v", err)
	}

	tamperedPath := filepath.Join(directory, "tampered-signature.bundle")
	rewriteBundle(t, signedPath, tamperedPath, func(name string, data []byte) []byte {
		if name == signatureName {
			return bytes.Replace(data, []byte(`"signature": "`), []byte(`"signature": "A`), 1)
		}
		return data
	}, "")
	trustedKey, err := LoadTrustedKey(publicPath)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadWithPolicy(tamperedPath, VerificationPolicy{
		TrustedKeys: []TrustedKey{trustedKey}, RequireSignature: true,
	}); err == nil || !strings.Contains(err.Error(), "signature value is invalid") {
		t.Fatalf("ReadWithPolicy(tampered) error = %v", err)
	}

	unsignedPath := filepath.Join(directory, "unsigned.bundle")
	if _, err := Write(unsignedPath, "PSIRTMap test", testSnapshot(createdAt), createdAt); err != nil {
		t.Fatal(err)
	}
	if _, _, err := ReadWithPolicy(unsignedPath, VerificationPolicy{
		TrustedKeys: []TrustedKey{trustedKey}, RequireSignature: true,
	}); err == nil || !strings.Contains(err.Error(), "unsigned") {
		t.Fatalf("ReadWithPolicy(unsigned) error = %v", err)
	}
}

func TestSigningKeyRejectsBroadPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows does not enforce Unix file permission bits")
	}
	directory := t.TempDir()
	privatePath := filepath.Join(directory, "signing.pem")
	publicPath := filepath.Join(directory, "signing.pub.pem")
	if _, err := GenerateKeyPair(privatePath, publicPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(privatePath, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadSigningKey(privatePath); err == nil || !strings.Contains(err.Error(), "too broad") {
		t.Fatalf("LoadSigningKey() error = %v", err)
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
