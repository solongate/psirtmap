// SPDX-License-Identifier: Apache-2.0
// Copyright (c) PSIRTMap contributors

package sbom

import (
	"bytes"
	"strings"
	"testing"

	packageurl "github.com/package-url/packageurl-go"
)

func FuzzParseCycloneDX(f *testing.F) {
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.6","version":1,"components":[{"type":"library","name":"demo","version":"1.0.0","purl":"pkg:npm/demo@1.0.0"}]}`))
	f.Add([]byte(`{"bomFormat":"CycloneDX","specVersion":"1.2","version":1}`))
	f.Add([]byte("not-json"))
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = Parse(bytes.NewReader(data))
	})
}

func TestParseCycloneDXMapsPURLsAndNestedComponents(t *testing.T) {
	t.Parallel()

	document := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "serialNumber": "urn:uuid:12345678-1234-1234-1234-123456789abc",
  "version": 1,
  "components": [
    {
      "type": "library",
      "bom-ref": "openssl",
      "name": "openssl",
      "version": "3.0.8-r0",
      "purl": "pkg:apk/alpine/openssl@3.0.8-r0?arch=aarch64&distro=alpine-3.17.2"
    },
    {
      "type": "application",
      "name": "web",
      "version": "1.0.0",
      "purl": "pkg:npm/%40solongate/web@1.0.0",
      "components": [
        {
          "type": "library",
          "name": "jinja2",
          "version": "2.4.1",
          "purl": "pkg:pypi/Jinja2@2.4.1"
        }
      ]
    }
  ]
}`

	report, err := Parse(strings.NewReader(document))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if report.Format != "CycloneDX JSON" || report.SpecVersion != "1.6" || report.Discovered != 3 {
		t.Fatalf("report metadata = %+v", report)
	}
	if len(report.Components) != 3 || len(report.Skipped) != 0 || report.Duplicates != 0 {
		t.Fatalf("report counts = %+v", report)
	}
	want := map[string]string{
		"Alpine:v3.17:openssl": "3.0.8-r0",
		"PyPI:jinja2":          "2.4.1",
		"npm:@solongate/web":   "1.0.0",
	}
	for _, component := range report.Components {
		key := component.Ecosystem + ":" + component.Name
		if want[key] != component.Version {
			t.Errorf("component = %+v; expected version map = %v", component, want)
		}
		delete(want, key)
	}
	if len(want) != 0 {
		t.Fatalf("missing components = %v", want)
	}
	if len(report.DocumentSHA256) != 64 {
		t.Fatalf("SHA-256 = %q", report.DocumentSHA256)
	}
}

func TestParseCycloneDXClassifiesSkippedAndDuplicateComponents(t *testing.T) {
	t.Parallel()

	document := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {"type":"library","name":"openssl","version":"3.0.8","purl":"pkg:apk/alpine/openssl@3.0.8?distro=alpine-3.17.2"},
    {"type":"library","name":"openssl copy","version":"3.0.8","purl":"pkg:apk/alpine/openssl@3.0.8?arch=x86_64&distro=alpine-3.17.2"},
    {"type":"library","name":"sqlite","version":"3.42.0"},
    {"type":"library","name":"image","version":"1","purl":"pkg:docker/example/image@1"},
    {"type":"library","name":"bad","version":"2","purl":"not-a-purl"}
  ]
}`
	report, err := Parse(strings.NewReader(document))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if report.Discovered != 5 || len(report.Components) != 1 || report.Duplicates != 1 || len(report.Skipped) != 3 {
		t.Fatalf("report = %+v", report)
	}
	reasons := make([]string, 0, len(report.Skipped))
	for _, skipped := range report.Skipped {
		reasons = append(reasons, skipped.Reason)
	}
	joined := strings.Join(reasons, "\n")
	for _, expected := range []string{"package URL is required", "not mapped", "invalid package URL"} {
		if !strings.Contains(joined, expected) {
			t.Errorf("skip reasons = %q, want %q", joined, expected)
		}
	}
}

func TestParseCycloneDXMapsAlpineSubpackagesAndSkipsUnknownRelease(t *testing.T) {
	t.Parallel()

	document := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {"type":"library","name":"libcrypto3","version":"3.0.8-r0","purl":"pkg:apk/alpine/libcrypto3@3.0.8-r0?arch=x86_64&distro=alpine-3.17.2&upstream=openssl"},
    {"type":"library","name":"libssl3","version":"3.0.8-r0","purl":"pkg:apk/alpine/libssl3@3.0.8-r0?arch=x86_64&distro=alpine-3.17.2&upstream=openssl"},
    {"type":"library","name":"busybox","version":"1.35.0-r29","purl":"pkg:apk/alpine/busybox@1.35.0-r29?arch=x86_64"}
  ]
}`
	report, err := Parse(strings.NewReader(document))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(report.Components) != 1 || report.Duplicates != 1 || len(report.Skipped) != 1 {
		t.Fatalf("report = %+v", report)
	}
	component := report.Components[0]
	if component.Ecosystem != "Alpine:v3.17" || component.Name != "openssl" || component.Version != "3.0.8-r0" {
		t.Fatalf("component = %+v", component)
	}
	if skipped := report.Skipped[0]; skipped.Name != "busybox" || !strings.Contains(skipped.Reason, "distro qualifier") {
		t.Fatalf("skipped = %+v", skipped)
	}
}

func TestParseCycloneDXMapsDebianSourcePackagesAndSkipsUnknownRelease(t *testing.T) {
	t.Parallel()

	document := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.6",
  "version": 1,
  "components": [
    {"type":"library","name":"bsdutils","version":"1:2.38.1-5+deb12u3","purl":"pkg:deb/debian/bsdutils@1%3A2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12.15&upstream=util-linux%402.38.1-5%2Bdeb12u3"},
    {"type":"library","name":"libmount1","version":"2.38.1-5+deb12u3","purl":"pkg:deb/debian/libmount1@2.38.1-5%2Bdeb12u3?arch=amd64&distro=debian-12.15&upstream=util-linux"},
    {"type":"library","name":"curl","version":"7.88.1-10","purl":"pkg:deb/debian/curl@7.88.1-10?arch=amd64"}
  ]
}`
	report, err := Parse(strings.NewReader(document))
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if len(report.Components) != 1 || report.Duplicates != 1 || len(report.Skipped) != 1 {
		t.Fatalf("report = %+v", report)
	}
	component := report.Components[0]
	if component.Ecosystem != "Debian:12" || component.Name != "util-linux" || component.Version != "2.38.1-5+deb12u3" {
		t.Fatalf("component = %+v", component)
	}
	if !strings.HasPrefix(component.PURL, "pkg:deb/debian/bsdutils@1:2.38.1-5%2Bdeb12u3") {
		t.Fatalf("component PURL = %q, want the installed package preserved", component.PURL)
	}
	if skipped := report.Skipped[0]; skipped.Name != "curl" || !strings.Contains(skipped.Reason, "distro qualifier") {
		t.Fatalf("skipped = %+v", skipped)
	}
}

func TestParseCycloneDXRejectsInvalidDocuments(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		document string
		want     string
	}{
		{name: "empty", document: "", want: "empty"},
		{name: "invalid JSON", document: "{", want: "decode"},
		{name: "wrong format", document: `{"bomFormat":"SPDX","specVersion":"1.6","version":1}`, want: "expected CycloneDX"},
		{name: "unsupported version", document: `{"bomFormat":"CycloneDX","specVersion":"2.0","version":1}`, want: "unsupported CycloneDX"},
		{name: "invalid document version", document: `{"bomFormat":"CycloneDX","specVersion":"1.6","version":0}`, want: "at least 1"},
		{name: "trailing JSON", document: `{"bomFormat":"CycloneDX","specVersion":"1.6","version":1}{}`, want: "multiple JSON"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			_, err := Parse(strings.NewReader(test.document))
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Parse() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestParseCycloneDXRejectsConflictingVersions(t *testing.T) {
	t.Parallel()
	document := `{
  "bomFormat":"CycloneDX","specVersion":"1.7","version":1,
  "components":[{"type":"library","name":"jinja2","version":"2.4.1","purl":"pkg:pypi/jinja2@3.0.0"}]
}`
	report, err := Parse(strings.NewReader(document))
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Components) != 0 || len(report.Skipped) != 1 || !strings.Contains(report.Skipped[0].Reason, "conflicts") {
		t.Fatalf("report = %+v", report)
	}
}

func TestOSVIdentityMappings(t *testing.T) {
	t.Parallel()

	tests := []struct {
		purl      string
		ecosystem string
		name      string
		mapped    bool
	}{
		{purl: "pkg:pypi/Jinja2@2.4.1", ecosystem: "PyPI", name: "jinja2", mapped: true},
		{purl: "pkg:npm/%40babel/core@7.0.0", ecosystem: "npm", name: "@babel/core", mapped: true},
		{purl: "pkg:golang/github.com/gin-gonic/gin@v1.9.0", ecosystem: "Go", name: "github.com/gin-gonic/gin", mapped: true},
		{purl: "pkg:maven/org.apache.logging.log4j/log4j-core@2.14.0", ecosystem: "Maven", name: "org.apache.logging.log4j:log4j-core", mapped: true},
		{purl: "pkg:deb/debian/curl@7.88.1?distro=debian-12.15", ecosystem: "Debian:12", name: "curl", mapped: true},
		{purl: "pkg:deb/debian/libc6@2.36-9?distro=debian-12&upstream=glibc", ecosystem: "Debian:12", name: "glibc", mapped: true},
		{purl: "pkg:deb/debian/bash@5.2.15-2%2Bb13?distro=debian-12.15&upstream=bash%405.2.15-2", ecosystem: "Debian:12", name: "bash", mapped: true},
		{purl: "pkg:deb/ubuntu/libssl3@3.0.2-0ubuntu1.30?distro=ubuntu-22.04&upstream=openssl", ecosystem: "Ubuntu:22.04:LTS", name: "openssl", mapped: true},
		{purl: "pkg:deb/ubuntu/curl@8.9.1-2ubuntu2?distro=ubuntu-24.10", ecosystem: "Ubuntu:24.10", name: "curl", mapped: true},
		{purl: "pkg:deb/debian/curl@7.88.1", mapped: false},
		{purl: "pkg:deb/ubuntu/curl@7.81.0-1ubuntu1?distro=ubuntu-jammy", mapped: false},
		{purl: "pkg:apk/alpine/openssl@3.0.8-r0?distro=alpine-3.17.2", ecosystem: "Alpine:v3.17", name: "openssl", mapped: true},
		{purl: "pkg:apk/alpine/musl@1.2.4-r2?distro=3.18.4", ecosystem: "Alpine:v3.18", name: "musl", mapped: true},
		{purl: "pkg:apk/alpine/libcrypto3@3.0.8-r0?distro=alpine-3.17.2&upstream=openssl", ecosystem: "Alpine:v3.17", name: "openssl", mapped: true},
		{purl: "pkg:apk/alpine/openssl@3.0.8-r0?arch=x86_64", mapped: false},
		{purl: "pkg:apk/alpine/openssl@3.0.8-r0?distro=alpine-edge", mapped: false},
		{purl: "pkg:docker/library/nginx@1.27", mapped: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.purl, func(t *testing.T) {
			t.Parallel()
			parsed, err := packageurl.FromString(test.purl)
			if err != nil {
				t.Fatal(err)
			}
			ecosystem, name, mapped := osvIdentity(parsed)
			if ecosystem != test.ecosystem || name != test.name || mapped != test.mapped {
				t.Fatalf("osvIdentity(%q) = %q, %q, %v", test.purl, ecosystem, name, mapped)
			}
		})
	}
}
