// Package sbom reads software bills of materials into PSIRTMap's component
// identity model.
package sbom

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"unicode"

	packageurl "github.com/package-url/packageurl-go"
)

const (
	maxDocumentBytes  = 128 << 20
	maxComponentDepth = 128
)

// Component is a package identity that can be queried through OSV.
type Component struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	PURL      string `json:"purl"`
	BOMRef    string `json:"bom_ref,omitempty"`
}

// SkippedComponent describes a CycloneDX component that cannot be represented
// as a safe OSV package-version query.
type SkippedComponent struct {
	BOMRef  string `json:"bom_ref,omitempty"`
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
	Reason  string `json:"reason"`
}

// Report is the fully validated, deterministic result of parsing one
// CycloneDX JSON document.
type Report struct {
	Format         string             `json:"format"`
	SpecVersion    string             `json:"spec_version"`
	SerialNumber   string             `json:"serial_number,omitempty"`
	DocumentSHA256 string             `json:"document_sha256"`
	Discovered     int                `json:"components_discovered"`
	Duplicates     int                `json:"duplicates_in_sbom"`
	Components     []Component        `json:"components"`
	Skipped        []SkippedComponent `json:"skipped_components"`
}

type cycloneDXBOM struct {
	BOMFormat    string               `json:"bomFormat"`
	SpecVersion  string               `json:"specVersion"`
	SerialNumber string               `json:"serialNumber"`
	Version      int                  `json:"version"`
	Components   []cycloneDXComponent `json:"components"`
}

type cycloneDXComponent struct {
	BOMRef     string               `json:"bom-ref"`
	Type       string               `json:"type"`
	Group      string               `json:"group"`
	Name       string               `json:"name"`
	Version    string               `json:"version"`
	PURL       string               `json:"purl"`
	Components []cycloneDXComponent `json:"components"`
}

// ParseFile reads and validates a CycloneDX JSON document. No persistent state
// is changed by this operation.
func ParseFile(path string) (Report, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return Report{}, errors.New("SBOM path is required")
	}
	file, err := os.Open(path)
	if err != nil {
		return Report{}, fmt.Errorf("open SBOM: %w", err)
	}
	defer file.Close()
	return Parse(file)
}

// Parse validates and converts a CycloneDX JSON stream.
func Parse(reader io.Reader) (Report, error) {
	if reader == nil {
		return Report{}, errors.New("SBOM input is required")
	}
	data, err := io.ReadAll(io.LimitReader(reader, maxDocumentBytes+1))
	if err != nil {
		return Report{}, fmt.Errorf("read SBOM: %w", err)
	}
	if len(data) == 0 {
		return Report{}, errors.New("SBOM is empty")
	}
	if len(data) > maxDocumentBytes {
		return Report{}, fmt.Errorf("SBOM exceeds the %d MiB size limit", maxDocumentBytes>>20)
	}

	var bom cycloneDXBOM
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&bom); err != nil {
		return Report{}, fmt.Errorf("decode CycloneDX JSON: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return Report{}, errors.New("decode CycloneDX JSON: multiple JSON values are not allowed")
		}
		return Report{}, fmt.Errorf("decode CycloneDX JSON: %w", err)
	}
	if bom.BOMFormat != "CycloneDX" {
		return Report{}, fmt.Errorf("unsupported SBOM format %q; expected CycloneDX", bom.BOMFormat)
	}
	if !supportedSpecVersion(bom.SpecVersion) {
		return Report{}, fmt.Errorf("unsupported CycloneDX spec version %q; supported versions are 1.2 through 1.7", bom.SpecVersion)
	}
	if bom.Version < 1 {
		return Report{}, errors.New("CycloneDX document version must be at least 1")
	}
	if containsControl(bom.SerialNumber) {
		return Report{}, errors.New("CycloneDX serial number cannot contain control characters")
	}

	digest := sha256.Sum256(data)
	report := Report{
		Format:         "CycloneDX JSON",
		SpecVersion:    bom.SpecVersion,
		SerialNumber:   strings.TrimSpace(bom.SerialNumber),
		DocumentSHA256: hex.EncodeToString(digest[:]),
		Components:     make([]Component, 0),
		Skipped:        make([]SkippedComponent, 0),
	}
	seen := make(map[string]struct{})
	if err := collectComponents(bom.Components, 0, &report, seen); err != nil {
		return Report{}, err
	}
	sort.Slice(report.Components, func(i, j int) bool {
		left := report.Components[i]
		right := report.Components[j]
		if left.Ecosystem != right.Ecosystem {
			return left.Ecosystem < right.Ecosystem
		}
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.PURL < right.PURL
	})
	sort.SliceStable(report.Skipped, func(i, j int) bool {
		left := report.Skipped[i]
		right := report.Skipped[j]
		if left.Name != right.Name {
			return left.Name < right.Name
		}
		if left.Version != right.Version {
			return left.Version < right.Version
		}
		return left.Reason < right.Reason
	})
	return report, nil
}

func supportedSpecVersion(value string) bool {
	majorText, minorText, found := strings.Cut(strings.TrimSpace(value), ".")
	if !found || majorText != "1" {
		return false
	}
	minor, err := strconv.Atoi(minorText)
	return err == nil && minor >= 2 && minor <= 7
}

func collectComponents(
	components []cycloneDXComponent,
	depth int,
	report *Report,
	seen map[string]struct{},
) error {
	if depth > maxComponentDepth {
		return fmt.Errorf("CycloneDX component nesting exceeds %d levels", maxComponentDepth)
	}
	for _, raw := range components {
		report.Discovered++
		component, skip := convertComponent(raw)
		if skip != nil {
			report.Skipped = append(report.Skipped, *skip)
		} else {
			key := component.Ecosystem + "\x00" + component.Name + "\x00" + component.Version
			if _, exists := seen[key]; exists {
				report.Duplicates++
			} else {
				seen[key] = struct{}{}
				report.Components = append(report.Components, component)
			}
		}
		if err := collectComponents(raw.Components, depth+1, report, seen); err != nil {
			return err
		}
	}
	return nil
}

func convertComponent(raw cycloneDXComponent) (Component, *SkippedComponent) {
	skipped := func(reason string) (Component, *SkippedComponent) {
		return Component{}, &SkippedComponent{
			BOMRef: strings.TrimSpace(raw.BOMRef), Name: strings.TrimSpace(raw.Name),
			Version: strings.TrimSpace(raw.Version), Reason: reason,
		}
	}
	if containsControl(raw.BOMRef) || containsControl(raw.Name) || containsControl(raw.Version) || containsControl(raw.PURL) {
		return skipped("identity contains control characters")
	}
	purlText := strings.TrimSpace(raw.PURL)
	if purlText == "" {
		return skipped("package URL is required to determine the OSV ecosystem")
	}
	purl, err := packageurl.FromString(purlText)
	if err != nil {
		return skipped("invalid package URL: " + err.Error())
	}
	version := strings.TrimSpace(purl.Version)
	componentVersion := strings.TrimSpace(raw.Version)
	if version == "" {
		version = componentVersion
	}
	if version == "" {
		return skipped("component version is required")
	}
	if componentVersion != "" && purl.Version != "" && componentVersion != purl.Version {
		return skipped(fmt.Sprintf("component version %q conflicts with package URL version %q", componentVersion, purl.Version))
	}

	ecosystem, name, ok := osvIdentity(purl)
	if !ok {
		return skipped(fmt.Sprintf("package URL type %q is not mapped to an OSV ecosystem", purl.Type))
	}
	if name == "" {
		return skipped("package URL does not contain an OSV package name")
	}
	purl.Version = version
	return Component{
		Ecosystem: ecosystem,
		Name:      name,
		Version:   version,
		PURL:      purl.ToString(),
		BOMRef:    strings.TrimSpace(raw.BOMRef),
	}, nil
}

func osvIdentity(purl packageurl.PackageURL) (string, string, bool) {
	joined := func(separator string) string {
		if purl.Namespace == "" {
			return purl.Name
		}
		return purl.Namespace + separator + purl.Name
	}
	switch purl.Type {
	case packageurl.TypePyPi:
		return "PyPI", purl.Name, true
	case packageurl.TypeNPM:
		if purl.Namespace == "" {
			return "npm", purl.Name, true
		}
		return "npm", "@" + strings.TrimPrefix(joined("/"), "@"), true
	case packageurl.TypeGolang:
		return "Go", joined("/"), true
	case packageurl.TypeMaven:
		return "Maven", joined(":"), true
	case packageurl.TypeCargo:
		return "crates.io", purl.Name, true
	case packageurl.TypeNuget:
		return "NuGet", purl.Name, true
	case packageurl.TypeGem:
		return "RubyGems", purl.Name, true
	case packageurl.TypeComposer:
		return "Packagist", joined("/"), true
	case packageurl.TypeHex:
		return "Hex", purl.Name, true
	case packageurl.TypePub:
		return "Pub", purl.Name, true
	case packageurl.TypeHackage:
		return "Haskell", purl.Name, true
	case packageurl.TypeOpam:
		return "opam", purl.Name, true
	case packageurl.TypeBitnami:
		return "Bitnami", purl.Name, true
	case packageurl.TypeSwift:
		return "SwiftURL", joined("/"), true
	case packageurl.TypeApk:
		if firstNamespaceSegment(purl.Namespace) == "alpine" {
			return "Alpine", purl.Name, true
		}
	case packageurl.TypeDebian:
		switch firstNamespaceSegment(purl.Namespace) {
		case "debian":
			return "Debian", purl.Name, true
		case "ubuntu":
			return "Ubuntu", purl.Name, true
		}
	case packageurl.TypeRPM:
		switch firstNamespaceSegment(purl.Namespace) {
		case "almalinux":
			return "AlmaLinux", purl.Name, true
		case "rockylinux":
			return "Rocky Linux", purl.Name, true
		}
	}
	return "", "", false
}

func firstNamespaceSegment(namespace string) string {
	segment, _, _ := strings.Cut(strings.ToLower(namespace), "/")
	return segment
}

func containsControl(value string) bool {
	return strings.IndexFunc(value, unicode.IsControl) >= 0
}
