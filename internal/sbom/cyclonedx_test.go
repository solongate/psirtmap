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
      "purl": "pkg:apk/alpine/openssl@3.0.8-r0?arch=aarch64"
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
		"Alpine:openssl":     "3.0.8-r0",
		"PyPI:jinja2":        "2.4.1",
		"npm:@solongate/web": "1.0.0",
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
    {"type":"library","name":"openssl","version":"3.0.8","purl":"pkg:apk/alpine/openssl@3.0.8"},
    {"type":"library","name":"openssl copy","version":"3.0.8","purl":"pkg:apk/alpine/openssl@3.0.8?arch=x86_64"},
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
		{purl: "pkg:deb/debian/curl@7.88.1", ecosystem: "Debian", name: "curl", mapped: true},
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
