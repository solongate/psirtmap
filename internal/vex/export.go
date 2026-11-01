// SPDX-License-Identifier: Apache-2.0
// Copyright (c) PSIRTMap contributors

// Package vex creates CycloneDX VEX documents from PSIRTMap assessments.
package vex

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"github.com/solongate/psirtmap/internal/store"
)

const (
	SpecVersion = "1.6"
	schemaURL   = "https://cyclonedx.org/schema/bom-1.6.schema.json"
)

var referenceNamespace = uuid.MustParse("b9dabb95-b0a9-57ec-a28c-f2b96b55a94f")

// Summary describes one generated VEX document.
type Summary struct {
	Format                   string    `json:"format"`
	SpecVersion              string    `json:"spec_version"`
	Product                  string    `json:"product"`
	Release                  string    `json:"release"`
	Path                     string    `json:"path"`
	Components               int       `json:"components"`
	Vulnerabilities          int       `json:"vulnerabilities"`
	AssessmentsExported      int       `json:"assessments_exported"`
	AssessmentHistoryEntries int       `json:"assessment_history_entries"`
	GeneratedAt              time.Time `json:"generated_at"`
}

// Document contains a generated BOM and the counts used to report the export.
type Document struct {
	BOM                      *cdx.BOM
	Components               int
	Vulnerabilities          int
	AssessmentsExported      int
	AssessmentHistoryEntries int
}

type assessmentHistory struct {
	latest store.Assessment
	first  time.Time
	count  int
}

// Build creates a standalone CycloneDX 1.6 VEX document. Only findings with a
// human assessment are exported, and the latest decision is authoritative.
func Build(
	release store.Release,
	components []store.Component,
	findings []store.Finding,
	assessments []store.Assessment,
	toolVersion string,
	generatedAt time.Time,
	serialNumber string,
) (Document, error) {
	if strings.TrimSpace(release.Product) == "" || strings.TrimSpace(release.Version) == "" {
		return Document{}, errors.New("product release is required for VEX export")
	}
	if generatedAt.IsZero() {
		generatedAt = time.Now().UTC()
	}
	generatedAt = generatedAt.UTC().Truncate(time.Second)
	if strings.TrimSpace(serialNumber) == "" {
		serialNumber = "urn:uuid:" + uuid.NewString()
	}
	if !strings.HasPrefix(serialNumber, "urn:uuid:") {
		return Document{}, errors.New("VEX serial number must use urn:uuid format")
	}
	parsedSerial, err := uuid.Parse(strings.TrimPrefix(serialNumber, "urn:uuid:"))
	if err != nil {
		return Document{}, errors.New("VEX serial number must contain a valid UUID")
	}
	serialNumber = "urn:uuid:" + parsedSerial.String()

	histories := assessmentHistories(assessments)
	if len(histories) == 0 {
		return Document{}, fmt.Errorf("%s@%s has no human assessments to export", release.Product, release.Version)
	}

	componentInventory := make(map[string]store.Component, len(components))
	for _, component := range components {
		componentInventory[componentKey(component.Ecosystem, component.Name, component.Version)] = component
	}

	orderedFindings := append([]store.Finding(nil), findings...)
	sort.Slice(orderedFindings, func(i, j int) bool {
		left, right := orderedFindings[i], orderedFindings[j]
		if left.VulnerabilityID != right.VulnerabilityID {
			return left.VulnerabilityID < right.VulnerabilityID
		}
		if left.Ecosystem != right.Ecosystem {
			return left.Ecosystem < right.Ecosystem
		}
		if left.Component != right.Component {
			return left.Component < right.Component
		}
		if left.ComponentVersion != right.ComponentVersion {
			return left.ComponentVersion < right.ComponentVersion
		}
		return left.FindingID < right.FindingID
	})

	componentDocuments := make([]cdx.Component, 0)
	vulnerabilities := make([]cdx.Vulnerability, 0)
	exportedComponents := make(map[string]struct{})
	historyEntries := 0
	for _, finding := range orderedFindings {
		history, ok := histories[finding.FindingID]
		if !ok {
			continue
		}
		if history.first.IsZero() || history.latest.AssessedAt.IsZero() {
			return Document{}, fmt.Errorf("finding %s has an invalid assessment timestamp", finding.VulnerabilityID)
		}
		state, err := analysisState(history.latest.Status)
		if err != nil {
			return Document{}, fmt.Errorf("finding %s: %w", finding.VulnerabilityID, err)
		}

		inventoryComponent, exists := componentInventory[componentKey(
			finding.Ecosystem, finding.Component, finding.ComponentVersion,
		)]
		if !exists {
			inventoryComponent = store.Component{
				Ecosystem: finding.Ecosystem, Name: finding.Component,
				Version: finding.ComponentVersion,
			}
		}
		componentRef := componentReference(inventoryComponent)
		if _, exists := exportedComponents[componentRef]; !exists {
			componentDocuments = append(componentDocuments, cycloneDXComponent(inventoryComponent, componentRef))
			exportedComponents[componentRef] = struct{}{}
		}

		properties := []cdx.Property{
			{Name: "psirtmap:assessment:status", Value: history.latest.Status},
			{Name: "psirtmap:assessment:reviewer", Value: history.latest.Reviewer},
			{Name: "psirtmap:finding:match-status", Value: finding.MatchStatus},
			{Name: "psirtmap:finding:active", Value: fmt.Sprintf("%t", finding.Active)},
		}
		if history.latest.Evidence != "" {
			properties = append(properties, cdx.Property{Name: "psirtmap:assessment:evidence", Value: history.latest.Evidence})
		}
		if finding.KnownExploited {
			properties = append(properties, cdx.Property{Name: "psirtmap:cisa-kev:known-exploited", Value: "true"})
		}
		for _, alias := range sortedUnique(finding.Aliases) {
			if strings.EqualFold(alias, finding.VulnerabilityID) {
				continue
			}
			properties = append(properties, cdx.Property{Name: "psirtmap:vulnerability:alias", Value: alias})
		}

		vulnerability := cdx.Vulnerability{
			BOMRef:      vulnerabilityReference(finding),
			ID:          finding.VulnerabilityID,
			Source:      &cdx.Source{Name: sourceName(finding.Source)},
			Description: finding.Summary,
			Analysis: &cdx.VulnerabilityAnalysis{
				State:       state,
				Detail:      history.latest.Reason,
				FirstIssued: history.first.UTC().Format(time.RFC3339),
				LastUpdated: history.latest.AssessedAt.UTC().Format(time.RFC3339),
			},
			Affects:    &[]cdx.Affects{{Ref: componentRef}},
			Properties: &properties,
		}
		if published := validTimestamp(finding.Published); published != "" {
			vulnerability.Published = published
		}
		if modified := validTimestamp(finding.Modified); modified != "" {
			vulnerability.Updated = modified
		}
		if ratings := vulnerabilityRatings(finding); len(ratings) > 0 {
			vulnerability.Ratings = &ratings
		}
		if advisories := vulnerabilityAdvisories(finding); len(advisories) > 0 {
			vulnerability.Advisories = &advisories
		}
		vulnerabilities = append(vulnerabilities, vulnerability)
		historyEntries += history.count
	}

	if len(vulnerabilities) == 0 {
		return Document{}, fmt.Errorf("%s@%s has no assessed findings to export", release.Product, release.Version)
	}
	sort.Slice(componentDocuments, func(i, j int) bool {
		return componentDocuments[i].BOMRef < componentDocuments[j].BOMRef
	})

	productRef := stableReference("product", release.Product, release.Version)
	toolComponents := []cdx.Component{{
		Type: cdx.ComponentTypeApplication, Name: "PSIRTMap", Version: strings.TrimSpace(toolVersion),
	}}
	bom := cdx.NewBOM()
	bom.SpecVersion = cdx.SpecVersion1_6
	bom.JSONSchema = schemaURL
	bom.SerialNumber = serialNumber
	bom.Metadata = &cdx.Metadata{
		Timestamp: generatedAt.Format(time.RFC3339),
		Tools:     &cdx.ToolsChoice{Components: &toolComponents},
		Component: &cdx.Component{
			BOMRef: productRef, Type: cdx.ComponentTypeApplication,
			Name: release.Product, Version: release.Version,
		},
	}
	bom.Components = &componentDocuments
	bom.Vulnerabilities = &vulnerabilities
	bom.Properties = &[]cdx.Property{
		{Name: "psirtmap:document:type", Value: "vex"},
		{Name: "psirtmap:product", Value: release.Product},
		{Name: "psirtmap:release", Value: release.Version},
	}

	return Document{
		BOM: bom, Components: len(componentDocuments), Vulnerabilities: len(vulnerabilities),
		AssessmentsExported: len(vulnerabilities), AssessmentHistoryEntries: historyEntries,
	}, nil
}

// Write creates a private CycloneDX JSON file without replacing an existing
// destination.
func Write(path string, bom *cdx.BOM) error {
	path = strings.TrimSpace(path)
	if path == "" {
		return errors.New("VEX output path is required")
	}
	if bom == nil {
		return errors.New("VEX document is required")
	}
	output, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		if errors.Is(err, os.ErrExist) {
			return fmt.Errorf("VEX output %q already exists", path)
		}
		return fmt.Errorf("create VEX output: %w", err)
	}
	complete := false
	defer func() {
		_ = output.Close()
		if !complete {
			_ = os.Remove(path)
		}
	}()
	encoder := cdx.NewBOMEncoder(output, cdx.BOMFileFormatJSON).SetPretty(true).SetEscapeHTML(false)
	if err := encoder.EncodeVersion(bom, cdx.SpecVersion1_6); err != nil {
		return fmt.Errorf("encode CycloneDX VEX: %w", err)
	}
	if err := output.Sync(); err != nil {
		return fmt.Errorf("flush CycloneDX VEX: %w", err)
	}
	if err := output.Close(); err != nil {
		return fmt.Errorf("close CycloneDX VEX: %w", err)
	}
	complete = true
	return nil
}

// DefaultFilename returns a portable filename for one release VEX document.
func DefaultFilename(product, release string) string {
	return safeFilenamePart(product) + "-" + safeFilenamePart(release) + ".vex.cdx.json"
}

func assessmentHistories(assessments []store.Assessment) map[int64]assessmentHistory {
	histories := make(map[int64]assessmentHistory)
	for _, assessment := range assessments {
		history, exists := histories[assessment.FindingID]
		if !exists {
			history = assessmentHistory{latest: assessment, first: assessment.AssessedAt}
		}
		history.count++
		if assessment.AssessedAt.Before(history.first) {
			history.first = assessment.AssessedAt
		}
		if assessment.AssessedAt.After(history.latest.AssessedAt) ||
			(assessment.AssessedAt.Equal(history.latest.AssessedAt) && assessment.AssessmentID > history.latest.AssessmentID) {
			history.latest = assessment
		}
		histories[assessment.FindingID] = history
	}
	return histories
}

func analysisState(status string) (cdx.ImpactAnalysisState, error) {
	switch status {
	case store.AssessmentInvestigating:
		return cdx.IASInTriage, nil
	case store.AssessmentAffected:
		return cdx.IASExploitable, nil
	case store.AssessmentNotAffected:
		return cdx.IASNotAffected, nil
	case store.AssessmentFixed:
		return cdx.IASResolved, nil
	default:
		return "", fmt.Errorf("unsupported assessment status %q", status)
	}
}

func cycloneDXComponent(component store.Component, reference string) cdx.Component {
	properties := []cdx.Property{{Name: "psirtmap:component:ecosystem", Value: component.Ecosystem}}
	return cdx.Component{
		BOMRef: reference, Type: cdx.ComponentTypeLibrary, Name: component.Name,
		Version: component.Version, PackageURL: component.PURL, Properties: &properties,
	}
}

func componentReference(component store.Component) string {
	if value := strings.TrimSpace(component.PURL); value != "" {
		return value
	}
	return stableReference("component", component.Ecosystem, component.Name, component.Version)
}

func vulnerabilityReference(finding store.Finding) string {
	return stableReference(
		"vulnerability", finding.Product, finding.Release, finding.Ecosystem,
		finding.Component, finding.ComponentVersion, finding.VulnerabilityID,
	)
}

func stableReference(parts ...string) string {
	joined := strings.Join(parts, "\x00")
	return "urn:uuid:" + uuid.NewSHA1(referenceNamespace, []byte(joined)).String()
}

func componentKey(ecosystem, name, version string) string {
	return strings.ToLower(strings.TrimSpace(ecosystem)) + "\x00" +
		strings.ToLower(strings.TrimSpace(name)) + "\x00" + strings.TrimSpace(version)
}

func sourceName(source string) string {
	if value := strings.TrimSpace(source); value != "" {
		return value
	}
	return "OSV"
}

func vulnerabilityRatings(finding store.Finding) []cdx.VulnerabilityRating {
	if finding.CVSSScore == nil && strings.TrimSpace(finding.CVSSVector) == "" {
		return nil
	}
	rating := cdx.VulnerabilityRating{
		Source: &cdx.Source{Name: sourceName(finding.Source)}, Score: finding.CVSSScore,
		Severity: cdx.Severity(strings.ToLower(strings.TrimSpace(finding.Severity))),
		Vector:   strings.TrimSpace(finding.CVSSVector),
	}
	switch finding.CVSSVersion {
	case "2.0":
		rating.Method = cdx.ScoringMethodCVSSv2
	case "3.0":
		rating.Method = cdx.ScoringMethodCVSSv3
	case "3.1":
		rating.Method = cdx.ScoringMethodCVSSv31
	case "4.0":
		rating.Method = cdx.ScoringMethodCVSSv4
	}
	return []cdx.VulnerabilityRating{rating}
}

func vulnerabilityAdvisories(finding store.Finding) []cdx.Advisory {
	advisories := make([]cdx.Advisory, 0, len(finding.References))
	seen := make(map[string]struct{}, len(finding.References))
	for _, reference := range finding.References {
		url := strings.TrimSpace(reference.URL)
		if url == "" {
			continue
		}
		if _, exists := seen[url]; exists {
			continue
		}
		seen[url] = struct{}{}
		advisories = append(advisories, cdx.Advisory{Title: strings.TrimSpace(reference.Type), URL: url})
	}
	sort.Slice(advisories, func(i, j int) bool { return advisories[i].URL < advisories[j].URL })
	return advisories
}

func validTimestamp(value string) string {
	parsed, err := time.Parse(time.RFC3339, strings.TrimSpace(value))
	if err != nil {
		return ""
	}
	return parsed.UTC().Format(time.RFC3339)
}

func sortedUnique(values []string) []string {
	seen := make(map[string]struct{}, len(values))
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		if _, exists := seen[value]; exists {
			continue
		}
		seen[value] = struct{}{}
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}

func safeFilenamePart(value string) string {
	value = strings.TrimSpace(value)
	var builder strings.Builder
	lastDash := false
	for _, character := range value {
		safe := (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
			(character >= '0' && character <= '9') || character == '-' || character == '_' || character == '.'
		if safe {
			builder.WriteRune(character)
			lastDash = character == '-'
		} else if builder.Len() > 0 && !lastDash {
			builder.WriteByte('-')
			lastDash = true
		}
		if builder.Len() >= 100 {
			break
		}
	}
	result := strings.Trim(builder.String(), ".-_")
	if result == "" {
		return "release"
	}
	return result
}
