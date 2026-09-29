// Package osv provides a small client for the OSV.dev API.
package osv

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	defaultBaseURL      = "https://api.osv.dev"
	defaultTimeout      = 20 * time.Second
	maxResponseBodySize = 64 << 20 // 64 MiB
)

// Client queries vulnerabilities from OSV.dev.
type Client struct {
	baseURL    string
	httpClient *http.Client
}

// Package identifies a package in an OSV ecosystem.
type Package struct {
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
}

// Vulnerability is the subset of an OSV record needed by the first PSIRTMap
// command. More fields can be added as the product model grows.
type Vulnerability struct {
	ID        string     `json:"id"`
	Summary   string     `json:"summary,omitempty"`
	Details   string     `json:"details,omitempty"`
	Aliases   []string   `json:"aliases,omitempty"`
	Published string     `json:"published,omitempty"`
	Modified  string     `json:"modified,omitempty"`
	Severity  []Severity `json:"severity,omitempty"`
}

// Severity contains an OSV severity type and its score or vector.
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type queryRequest struct {
	Version   string  `json:"version"`
	Package   Package `json:"package"`
	PageToken string  `json:"page_token,omitempty"`
}

type queryResponse struct {
	Vulnerabilities []Vulnerability `json:"vulns"`
	NextPageToken   string          `json:"next_page_token"`
}

// APIError describes a non-successful response returned by OSV.dev.
type APIError struct {
	StatusCode int
	Status     string
	Body       string
}

func (e *APIError) Error() string {
	if e.Body == "" {
		return fmt.Sprintf("OSV API returned %s", e.Status)
	}
	return fmt.Sprintf("OSV API returned %s: %s", e.Status, e.Body)
}

// NewClient creates an OSV client. A nil HTTP client uses a client with a
// finite timeout so a network problem cannot hang the CLI indefinitely.
func NewClient(httpClient *http.Client) *Client {
	if httpClient == nil {
		httpClient = &http.Client{Timeout: defaultTimeout}
	}

	return &Client{
		baseURL:    defaultBaseURL,
		httpClient: httpClient,
	}
}

// NewClientWithBaseURL creates a client pointed at another API endpoint. It is
// primarily useful for tests and compatible OSV deployments.
func NewClientWithBaseURL(baseURL string, httpClient *http.Client) *Client {
	client := NewClient(httpClient)
	client.baseURL = strings.TrimRight(baseURL, "/")
	return client
}

// Query returns every OSV record matching a package version. OSV can paginate
// large result sets, so Query follows page tokens until the result is complete.
func (c *Client) Query(ctx context.Context, pkg Package, version string) ([]Vulnerability, error) {
	pkg.Name = strings.TrimSpace(pkg.Name)
	pkg.Ecosystem = strings.TrimSpace(pkg.Ecosystem)
	version = strings.TrimSpace(version)

	if pkg.Name == "" {
		return nil, errors.New("package name is required")
	}
	if pkg.Ecosystem == "" {
		return nil, errors.New("package ecosystem is required")
	}
	if version == "" {
		return nil, errors.New("package version is required")
	}

	var vulnerabilities []Vulnerability
	seenIDs := make(map[string]struct{})
	seenTokens := make(map[string]struct{})
	pageToken := ""

	for {
		response, err := c.queryPage(ctx, queryRequest{
			Version:   version,
			Package:   pkg,
			PageToken: pageToken,
		})
		if err != nil {
			return nil, err
		}

		for _, vulnerability := range response.Vulnerabilities {
			if _, exists := seenIDs[vulnerability.ID]; exists {
				continue
			}
			seenIDs[vulnerability.ID] = struct{}{}
			vulnerabilities = append(vulnerabilities, vulnerability)
		}

		if response.NextPageToken == "" {
			break
		}
		if _, exists := seenTokens[response.NextPageToken]; exists {
			return nil, errors.New("OSV API returned a repeated page token")
		}
		seenTokens[response.NextPageToken] = struct{}{}
		pageToken = response.NextPageToken
	}

	vulnerabilities = canonicalizeVulnerabilities(vulnerabilities)
	sort.Slice(vulnerabilities, func(i, j int) bool {
		return vulnerabilities[i].ID < vulnerabilities[j].ID
	})

	return vulnerabilities, nil
}

func canonicalizeVulnerabilities(records []Vulnerability) []Vulnerability {
	if len(records) < 2 {
		return records
	}

	parents := make([]int, len(records))
	for index := range parents {
		parents[index] = index
	}
	var find func(int) int
	find = func(index int) int {
		if parents[index] != index {
			parents[index] = find(parents[index])
		}
		return parents[index]
	}
	union := func(left, right int) {
		leftRoot := find(left)
		rightRoot := find(right)
		if leftRoot != rightRoot {
			parents[rightRoot] = leftRoot
		}
	}

	identifierOwner := make(map[string]int)
	for index, record := range records {
		identifiers := append([]string{record.ID}, record.Aliases...)
		for _, identifier := range identifiers {
			identifier = strings.TrimSpace(identifier)
			if identifier == "" {
				continue
			}
			if owner, exists := identifierOwner[identifier]; exists {
				union(index, owner)
			} else {
				identifierOwner[identifier] = index
			}
		}
	}

	groups := make(map[int][]Vulnerability)
	for index, record := range records {
		root := find(index)
		groups[root] = append(groups[root], record)
	}

	merged := make([]Vulnerability, 0, len(groups))
	for _, group := range groups {
		merged = append(merged, mergeVulnerabilityGroup(group))
	}
	return merged
}

func mergeVulnerabilityGroup(records []Vulnerability) Vulnerability {
	identifiers := make(map[string]struct{})
	severitySet := make(map[Severity]struct{})
	var merged Vulnerability
	for _, record := range records {
		if record.ID != "" {
			identifiers[record.ID] = struct{}{}
		}
		for _, alias := range record.Aliases {
			if alias != "" {
				identifiers[alias] = struct{}{}
			}
		}
		merged.Summary = preferredText(merged.Summary, record.Summary)
		merged.Details = preferredText(merged.Details, record.Details)
		if merged.Published == "" || (record.Published != "" && record.Published < merged.Published) {
			merged.Published = record.Published
		}
		if record.Modified > merged.Modified {
			merged.Modified = record.Modified
		}
		for _, severity := range record.Severity {
			severitySet[severity] = struct{}{}
		}
	}

	allIdentifiers := make([]string, 0, len(identifiers))
	for identifier := range identifiers {
		allIdentifiers = append(allIdentifiers, identifier)
	}
	sort.Slice(allIdentifiers, func(i, j int) bool {
		leftRank := identifierRank(allIdentifiers[i])
		rightRank := identifierRank(allIdentifiers[j])
		if leftRank != rightRank {
			return leftRank < rightRank
		}
		return allIdentifiers[i] < allIdentifiers[j]
	})
	if len(allIdentifiers) > 0 {
		merged.ID = allIdentifiers[0]
		merged.Aliases = append([]string(nil), allIdentifiers[1:]...)
		sort.Strings(merged.Aliases)
	}

	merged.Severity = make([]Severity, 0, len(severitySet))
	for severity := range severitySet {
		merged.Severity = append(merged.Severity, severity)
	}
	sort.Slice(merged.Severity, func(i, j int) bool {
		if merged.Severity[i].Type != merged.Severity[j].Type {
			return merged.Severity[i].Type < merged.Severity[j].Type
		}
		return merged.Severity[i].Score < merged.Severity[j].Score
	})
	if len(merged.Severity) == 0 {
		merged.Severity = nil
	}
	return merged
}

func identifierRank(identifier string) int {
	switch {
	case strings.HasPrefix(identifier, "CVE-"):
		return 0
	case strings.HasPrefix(identifier, "GHSA-"):
		return 1
	case strings.HasPrefix(identifier, "OSV-"):
		return 2
	default:
		return 3
	}
}

func preferredText(current, candidate string) string {
	if len(candidate) > len(current) || (len(candidate) == len(current) && candidate < current) {
		return candidate
	}
	return current
}

func (c *Client) queryPage(ctx context.Context, query queryRequest) (queryResponse, error) {
	var response queryResponse

	body, err := json.Marshal(query)
	if err != nil {
		return response, fmt.Errorf("encode OSV query: %w", err)
	}

	request, err := http.NewRequestWithContext(
		ctx,
		http.MethodPost,
		c.baseURL+"/v1/query",
		bytes.NewReader(body),
	)
	if err != nil {
		return response, fmt.Errorf("create OSV request: %w", err)
	}
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Accept", "application/json")
	request.Header.Set("User-Agent", "psirtmap/dev")

	httpResponse, err := c.httpClient.Do(request)
	if err != nil {
		return response, fmt.Errorf("query OSV API: %w", err)
	}
	defer httpResponse.Body.Close()

	limitedBody := io.LimitReader(httpResponse.Body, maxResponseBodySize+1)
	responseBody, err := io.ReadAll(limitedBody)
	if err != nil {
		return response, fmt.Errorf("read OSV response: %w", err)
	}
	if len(responseBody) > maxResponseBodySize {
		return response, fmt.Errorf("OSV response exceeded %d bytes", maxResponseBodySize)
	}

	if httpResponse.StatusCode < http.StatusOK || httpResponse.StatusCode >= http.StatusMultipleChoices {
		return response, &APIError{
			StatusCode: httpResponse.StatusCode,
			Status:     httpResponse.Status,
			Body:       strings.TrimSpace(string(responseBody)),
		}
	}

	if err := json.Unmarshal(responseBody, &response); err != nil {
		return response, fmt.Errorf("decode OSV response: %w", err)
	}

	return response, nil
}
