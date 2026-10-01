// Package kev downloads and validates CISA's Known Exploited Vulnerabilities
// catalog for local prioritization.
package kev

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	// CatalogURL is CISA's canonical machine-readable KEV feed.
	CatalogURL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	// MirrorURL is CISA's official GitHub mirror. It is used when the canonical
	// endpoint is temporarily unavailable or rejects automated clients.
	MirrorURL           = "https://raw.githubusercontent.com/cisagov/kev-data/develop/known_exploited_vulnerabilities.json"
	defaultTimeout      = 20 * time.Second
	maxResponseBodySize = 32 << 20 // 32 MiB
)

var cvePattern = regexp.MustCompile(`^CVE-[0-9]{4}-[0-9]{4,19}$`)

// Catalog is one complete CISA KEV snapshot.
type Catalog struct {
	CatalogVersion  string          `json:"catalogVersion"`
	DateReleased    string          `json:"dateReleased"`
	Count           int             `json:"count"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
	SourceURL       string          `json:"-"`
}

// Vulnerability is one known-exploited CVE and its CISA prioritization
// metadata.
type Vulnerability struct {
	CVEID                      string   `json:"cveID"`
	VendorProject              string   `json:"vendorProject"`
	Product                    string   `json:"product"`
	VulnerabilityName          string   `json:"vulnerabilityName"`
	DateAdded                  string   `json:"dateAdded"`
	ShortDescription           string   `json:"shortDescription"`
	RequiredAction             string   `json:"requiredAction"`
	DueDate                    string   `json:"dueDate"`
	KnownRansomwareCampaignUse string   `json:"knownRansomwareCampaignUse,omitempty"`
	ForensicTriage             string   `json:"forensicTriage,omitempty"`
	Notes                      string   `json:"notes,omitempty"`
	CWEs                       []string `json:"cwes,omitempty"`
}

// HTTPError describes a non-successful KEV feed response.
type HTTPError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *HTTPError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("CISA KEV feed returned %s", e.Status)
	}
	return fmt.Sprintf("CISA KEV feed returned %s: %s", e.Status, e.Body)
}

// Client fetches the complete KEV catalog.
type Client struct {
	urls       []string
	httpClient *http.Client
}

// NewClient creates a client that prefers CISA's canonical feed and falls back
// to CISA's official GitHub mirror.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}
	return &Client{urls: []string{CatalogURL, MirrorURL}, httpClient: httpClient}
}

// NewClientWithURL creates a single-endpoint client for tests and compatible
// mirrors.
func NewClientWithURL(url string, httpClient *http.Client) *Client {
	client := NewClient(httpClient)
	client.urls = []string{strings.TrimSpace(url)}
	return client
}

// Fetch downloads, validates, normalizes, and deterministically sorts one
// complete catalog.
func (c *Client) Fetch(ctx context.Context) (Catalog, error) {
	if len(c.urls) == 0 {
		return Catalog{}, errors.New("CISA KEV feed URL is required")
	}
	var failures []error
	for _, endpoint := range c.urls {
		catalog, err := c.fetchEndpoint(ctx, endpoint)
		if err == nil {
			return catalog, nil
		}
		// Stop only when the caller's context ended. An individual HTTP client
		// timeout is an endpoint failure and should still allow the official
		// mirror to serve as a fallback.
		if contextErr := ctx.Err(); contextErr != nil {
			return Catalog{}, contextErr
		}
		failures = append(failures, err)
	}
	return Catalog{}, fmt.Errorf("download CISA KEV catalog: %w", errors.Join(failures...))
}

func (c *Client) fetchEndpoint(ctx context.Context, endpoint string) (Catalog, error) {
	endpoint = strings.TrimSpace(endpoint)
	if endpoint == "" {
		return Catalog{}, errors.New("CISA KEV feed URL is required")
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return Catalog{}, fmt.Errorf("create CISA KEV request: %w", err)
	}
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "psirtmap/0.0.8")

	response, err := c.httpClient.Do(request)
	if err != nil {
		return Catalog{}, fmt.Errorf("request CISA KEV feed: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 4096))
		return Catalog{}, &HTTPError{
			StatusCode: response.StatusCode,
			Status:     response.Status,
			Body:       strings.TrimSpace(string(body)),
		}
	}

	limited := io.LimitReader(response.Body, maxResponseBodySize+1)
	body, err := io.ReadAll(limited)
	if err != nil {
		return Catalog{}, fmt.Errorf("read CISA KEV response: %w", err)
	}
	if len(body) > maxResponseBodySize {
		return Catalog{}, fmt.Errorf("CISA KEV response exceeds %d bytes", maxResponseBodySize)
	}
	var catalog Catalog
	if err := json.Unmarshal(body, &catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode CISA KEV response: %w", err)
	}
	catalog.SourceURL = endpoint
	if err := ValidateCatalog(&catalog); err != nil {
		return Catalog{}, err
	}
	return catalog, nil
}

// ValidateCatalog validates required metadata and normalizes all entries.
func ValidateCatalog(catalog *Catalog) error {
	if catalog == nil {
		return errors.New("CISA KEV catalog is required")
	}
	catalog.CatalogVersion = strings.TrimSpace(catalog.CatalogVersion)
	catalog.DateReleased = strings.TrimSpace(catalog.DateReleased)
	if catalog.CatalogVersion == "" {
		return errors.New("CISA KEV catalog version is required")
	}
	if _, err := time.Parse(time.RFC3339, catalog.DateReleased); err != nil {
		return fmt.Errorf("invalid CISA KEV release time %q: %w", catalog.DateReleased, err)
	}
	if catalog.Count != len(catalog.Vulnerabilities) {
		return fmt.Errorf("CISA KEV count is %d but catalog contains %d entries", catalog.Count, len(catalog.Vulnerabilities))
	}
	seen := make(map[string]struct{}, len(catalog.Vulnerabilities))
	for index := range catalog.Vulnerabilities {
		entry := &catalog.Vulnerabilities[index]
		entry.CVEID = strings.ToUpper(strings.TrimSpace(entry.CVEID))
		entry.VendorProject = strings.TrimSpace(entry.VendorProject)
		entry.Product = strings.TrimSpace(entry.Product)
		entry.VulnerabilityName = strings.TrimSpace(entry.VulnerabilityName)
		entry.DateAdded = strings.TrimSpace(entry.DateAdded)
		entry.ShortDescription = strings.TrimSpace(entry.ShortDescription)
		entry.RequiredAction = strings.TrimSpace(entry.RequiredAction)
		entry.DueDate = strings.TrimSpace(entry.DueDate)
		entry.KnownRansomwareCampaignUse = strings.TrimSpace(entry.KnownRansomwareCampaignUse)
		entry.ForensicTriage = strings.TrimSpace(entry.ForensicTriage)
		entry.Notes = strings.TrimSpace(entry.Notes)
		if !cvePattern.MatchString(entry.CVEID) {
			return fmt.Errorf("invalid CISA KEV CVE ID %q", entry.CVEID)
		}
		if _, exists := seen[entry.CVEID]; exists {
			return fmt.Errorf("duplicate CISA KEV entry %s", entry.CVEID)
		}
		seen[entry.CVEID] = struct{}{}
		for label, value := range map[string]string{
			"vendor project":     entry.VendorProject,
			"product":            entry.Product,
			"vulnerability name": entry.VulnerabilityName,
			"short description":  entry.ShortDescription,
			"required action":    entry.RequiredAction,
		} {
			if value == "" {
				return fmt.Errorf("CISA KEV %s %s is required", entry.CVEID, label)
			}
		}
		for label, value := range map[string]string{"date added": entry.DateAdded, "due date": entry.DueDate} {
			if _, err := time.Parse("2006-01-02", value); err != nil {
				return fmt.Errorf("invalid CISA KEV %s %s %q: %w", entry.CVEID, label, value, err)
			}
		}
		entry.CWEs = cleanStrings(entry.CWEs)
	}
	sort.Slice(catalog.Vulnerabilities, func(i, j int) bool {
		return catalog.Vulnerabilities[i].CVEID < catalog.Vulnerabilities[j].CVEID
	})
	return nil
}

func cleanStrings(values []string) []string {
	if len(values) == 0 {
		return []string{}
	}
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
