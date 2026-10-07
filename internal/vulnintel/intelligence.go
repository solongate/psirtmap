// Package vulnintel derives review-friendly intelligence from source records.
package vulnintel

import (
	"net/url"
	"sort"
	"strings"

	"github.com/secengcommons/cvss/cvss20"
	"github.com/secengcommons/cvss/cvss30"
	"github.com/secengcommons/cvss/cvss31"
	"github.com/secengcommons/cvss/cvss40"
	"github.com/solongate/psirtmap/internal/osv"
)

const (
	SeverityUnknown  = "unknown"
	SeverityNone     = "none"
	SeverityLow      = "low"
	SeverityMedium   = "medium"
	SeverityHigh     = "high"
	SeverityCritical = "critical"
)

// Intelligence is deterministic context derived from one OSV record for one
// package match. It is prioritization context, not an exploitability decision.
type Intelligence struct {
	Severity      string
	CVSSScore     *float64
	CVSSVersion   string
	CVSSVector    string
	Published     string
	Modified      string
	Withdrawn     string
	FixedVersions []string
	References    []osv.Reference
}

// Analyze extracts the strongest supported CVSS score, matching fixed-version
// boundaries, timestamps, and safe web references from an OSV record.
func Analyze(record osv.Vulnerability, ecosystem, component string) Intelligence {
	result := Intelligence{
		Severity:  SeverityUnknown,
		Published: strings.TrimSpace(record.Published),
		Modified:  strings.TrimSpace(record.Modified),
		Withdrawn: strings.TrimSpace(record.Withdrawn),
	}
	for _, candidate := range record.Severity {
		score, version, vector, ok := parseSeverity(candidate)
		if !ok || (result.CVSSScore != nil && (score < *result.CVSSScore ||
			(score == *result.CVSSScore && cvssVersionRank(version) <= cvssVersionRank(result.CVSSVersion)))) {
			continue
		}
		scoreCopy := score
		result.CVSSScore = &scoreCopy
		result.CVSSVersion = version
		result.CVSSVector = vector
		result.Severity = severityFromScore(score)
	}

	fixed := make(map[string]struct{})
	for _, affected := range record.Affected {
		if !strings.EqualFold(strings.TrimSpace(affected.Package.Ecosystem), strings.TrimSpace(ecosystem)) ||
			!strings.EqualFold(strings.TrimSpace(affected.Package.Name), strings.TrimSpace(component)) {
			continue
		}
		for _, affectedRange := range affected.Ranges {
			for _, event := range affectedRange.Events {
				version := strings.TrimSpace(event.Fixed)
				if version != "" {
					fixed[version] = struct{}{}
				}
			}
		}
	}
	result.FixedVersions = make([]string, 0, len(fixed))
	for version := range fixed {
		result.FixedVersions = append(result.FixedVersions, version)
	}
	sort.Strings(result.FixedVersions)

	seenReferences := make(map[string]struct{})
	for _, reference := range record.References {
		reference.Type = strings.TrimSpace(reference.Type)
		reference.URL = strings.TrimSpace(reference.URL)
		parsed, err := url.Parse(reference.URL)
		if err != nil || (parsed.Scheme != "https" && parsed.Scheme != "http") || parsed.Host == "" {
			continue
		}
		key := reference.Type + "\x00" + reference.URL
		if _, exists := seenReferences[key]; exists {
			continue
		}
		seenReferences[key] = struct{}{}
		result.References = append(result.References, reference)
	}
	sort.Slice(result.References, func(i, j int) bool {
		if result.References[i].Type != result.References[j].Type {
			return result.References[i].Type < result.References[j].Type
		}
		return result.References[i].URL < result.References[j].URL
	})
	return result
}

// ValidSeverity reports whether a value is a supported normalized label.
func ValidSeverity(value string) bool {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SeverityUnknown, SeverityNone, SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical:
		return true
	default:
		return false
	}
}

// SeverityRank returns a stable ordering value for prioritization.
func SeverityRank(value string) int {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case SeverityCritical:
		return 5
	case SeverityHigh:
		return 4
	case SeverityMedium:
		return 3
	case SeverityLow:
		return 2
	case SeverityNone:
		return 1
	default:
		return 0
	}
}

func parseSeverity(value osv.Severity) (float64, string, string, bool) {
	vector := strings.TrimSpace(value.Score)
	typ := strings.ToUpper(strings.TrimSpace(value.Type))
	switch {
	case strings.HasPrefix(vector, "CVSS:4.0/") || typ == "CVSS_V4":
		parsed, err := cvss40.Parse(vector)
		if err != nil {
			return 0, "", "", false
		}
		score, err := parsed.Score()
		return score.Float64(), "4.0", vector, err == nil
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		parsed, err := cvss31.Parse(vector)
		if err != nil {
			return 0, "", "", false
		}
		score, err := parsed.BaseScore()
		return score.Float64(), "3.1", vector, err == nil
	case strings.HasPrefix(vector, "CVSS:3.0/") || typ == "CVSS_V3":
		parsed, err := cvss30.Parse(vector)
		if err != nil {
			return 0, "", "", false
		}
		score, err := parsed.BaseScore()
		return score.Float64(), "3.0", vector, err == nil
	case typ == "CVSS_V2":
		parsed, err := cvss20.Parse(vector)
		if err != nil {
			return 0, "", "", false
		}
		score, err := parsed.BaseScore()
		return score.Float64(), "2.0", vector, err == nil
	default:
		return 0, "", "", false
	}
}

func severityFromScore(score float64) string {
	if score == 0 {
		return SeverityNone
	}
	if score < 4 {
		return SeverityLow
	}
	if score < 7 {
		return SeverityMedium
	}
	if score < 9 {
		return SeverityHigh
	}
	return SeverityCritical
}

func cvssVersionRank(version string) int {
	switch version {
	case "4.0":
		return 4
	case "3.1":
		return 3
	case "3.0":
		return 2
	case "2.0":
		return 1
	default:
		return 0
	}
}
