package osv_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/solongate/psirtmap/internal/osv"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func jsonResponse(statusCode int, body string) *http.Response {
	return &http.Response{
		StatusCode: statusCode,
		Status:     http.StatusText(statusCode),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

func TestQueryFollowsPaginationAndSortsResults(t *testing.T) {
	t.Parallel()

	var calls int
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		calls++
		if request.Method != http.MethodPost {
			t.Fatalf("method = %s, want POST", request.Method)
		}
		if request.URL.Path != "/v1/query" {
			t.Fatalf("path = %s, want /v1/query", request.URL.Path)
		}

		var body struct {
			Version string      `json:"version"`
			Package osv.Package `json:"package"`
			Token   string      `json:"page_token"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body.Version != "2.4.1" || body.Package.Name != "jinja2" || body.Package.Ecosystem != "PyPI" {
			t.Fatalf("unexpected query: %+v", body)
		}

		if body.Token == "" {
			return jsonResponse(http.StatusOK, `{
				"vulns":[{"id":"PYSEC-2","summary":"second"}],
				"next_page_token":"page-2"
			}`), nil
		}
		if body.Token != "page-2" {
			t.Fatalf("page token = %q, want page-2", body.Token)
		}
		return jsonResponse(http.StatusOK, `{
			"vulns":[
				{"id":"PYSEC-1","summary":"first"},
				{"id":"PYSEC-2","summary":"duplicate"}
			]
		}`), nil
	})}

	client := osv.NewClientWithBaseURL("https://api.test", httpClient)
	vulnerabilities, err := client.Query(context.Background(), osv.Package{
		Name:      "jinja2",
		Ecosystem: "PyPI",
	}, "2.4.1")
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if len(vulnerabilities) != 2 {
		t.Fatalf("len(vulnerabilities) = %d, want 2", len(vulnerabilities))
	}
	if vulnerabilities[0].ID != "PYSEC-1" || vulnerabilities[1].ID != "PYSEC-2" {
		t.Fatalf("vulnerabilities = %+v, want sorted unique records", vulnerabilities)
	}
}

func TestQueryReturnsAPIError(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadRequest, "invalid ecosystem"), nil
	})}

	client := osv.NewClientWithBaseURL("https://api.test", httpClient)
	_, err := client.Query(context.Background(), osv.Package{
		Name:      "jinja2",
		Ecosystem: "not-an-ecosystem",
	}, "2.4.1")
	if err == nil {
		t.Fatal("Query() error = nil, want API error")
	}

	var apiError *osv.APIError
	if !errors.As(err, &apiError) {
		t.Fatalf("error type = %T, want *osv.APIError", err)
	}
	if apiError.StatusCode != http.StatusBadRequest {
		t.Fatalf("status code = %d, want 400", apiError.StatusCode)
	}
}

func TestQueryValidatesInputBeforeRequest(t *testing.T) {
	t.Parallel()

	client := osv.NewClient(nil)
	_, err := client.Query(context.Background(), osv.Package{Name: "jinja2"}, "2.4.1")
	if err == nil {
		t.Fatal("Query() error = nil, want validation error")
	}
}

func TestQueryRejectsEveryBlankRequiredField(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		pkg     osv.Package
		version string
		want    string
	}{
		{name: "name", pkg: osv.Package{Ecosystem: "npm"}, version: "1.0", want: "name"},
		{name: "ecosystem", pkg: osv.Package{Name: "pkg"}, version: "1.0", want: "ecosystem"},
		{name: "version", pkg: osv.Package{Name: "pkg", Ecosystem: "npm"}, want: "version"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := osv.NewClient(nil)
			_, err := client.Query(context.Background(), test.pkg, test.version)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Query() error = %v, want %q validation", err, test.want)
			}
		})
	}
}

func TestQueryTrimsInputAndSetsHeaders(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("Content-Type = %q", request.Header.Get("Content-Type"))
		}
		if request.Header.Get("Accept") != "application/json" {
			t.Fatalf("Accept = %q", request.Header.Get("Accept"))
		}
		if !strings.HasPrefix(request.Header.Get("User-Agent"), "psirtmap/") {
			t.Fatalf("User-Agent = %q", request.Header.Get("User-Agent"))
		}
		var body struct {
			Version string      `json:"version"`
			Package osv.Package `json:"package"`
		}
		if err := json.NewDecoder(request.Body).Decode(&body); err != nil {
			t.Fatalf("decode request: %v", err)
		}
		if body.Package.Name != "pkg" || body.Package.Ecosystem != "npm" || body.Version != "1.0" {
			t.Fatalf("request body = %+v", body)
		}
		return jsonResponse(http.StatusOK, `{}`), nil
	})}

	client := osv.NewClientWithBaseURL("https://api.test/", httpClient)
	if _, err := client.Query(context.Background(), osv.Package{
		Name: " pkg ", Ecosystem: " npm ",
	}, " 1.0 "); err != nil {
		t.Fatalf("Query() error = %v", err)
	}
}

func TestQueryRejectsRepeatedPageToken(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{"next_page_token":"again"}`), nil
	})}
	client := osv.NewClientWithBaseURL("https://api.test", httpClient)
	_, err := client.Query(context.Background(), osv.Package{Name: "pkg", Ecosystem: "npm"}, "1.0")
	if err == nil || !strings.Contains(err.Error(), "repeated page token") {
		t.Fatalf("Query() error = %v", err)
	}
}

func TestQueryMergesAliasRecordsIntoCanonicalVulnerability(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusOK, `{
			"vulns": [
				{
					"id": "PYSEC-2021-66",
					"aliases": ["CVE-2020-28493", "GHSA-g3rq-g295-4j3m"],
					"published": "2021-02-01T00:00:00Z",
					"modified": "2022-01-01T00:00:00Z",
					"severity": [{"type":"CVSS_V3","score":"score-a"}],
					"references": [{"type":"ADVISORY","url":"https://example.test/advisory"}]
				},
				{
					"id": "GHSA-g3rq-g295-4j3m",
					"aliases": ["CVE-2020-28493", "PYSEC-2021-66"],
					"summary": "Jinja2 ReDoS vulnerability",
					"published": "2021-01-01T00:00:00Z",
					"modified": "2023-01-01T00:00:00Z",
					"severity": [
						{"type":"CVSS_V3","score":"score-a"},
						{"type":"CVSS_V4","score":"score-b"}
					],
					"references": [
						{"type":"ADVISORY","url":"https://example.test/advisory"},
						{"type":"WEB","url":"https://example.test/report"}
					]
				}
			]
		}`), nil
	})}
	client := osv.NewClientWithBaseURL("https://api.test", httpClient)
	vulnerabilities, err := client.Query(
		context.Background(),
		osv.Package{Name: "jinja2", Ecosystem: "PyPI"},
		"2.4.1",
	)
	if err != nil {
		t.Fatalf("Query() error = %v", err)
	}
	if len(vulnerabilities) != 1 {
		t.Fatalf("vulnerabilities = %+v, want one merged record", vulnerabilities)
	}
	vulnerability := vulnerabilities[0]
	if vulnerability.ID != "CVE-2020-28493" {
		t.Fatalf("ID = %q, want CVE", vulnerability.ID)
	}
	if strings.Join(vulnerability.Aliases, ",") != "GHSA-g3rq-g295-4j3m,PYSEC-2021-66" {
		t.Fatalf("aliases = %v", vulnerability.Aliases)
	}
	if vulnerability.Summary != "Jinja2 ReDoS vulnerability" {
		t.Fatalf("summary = %q", vulnerability.Summary)
	}
	if vulnerability.Published != "2021-01-01T00:00:00Z" || vulnerability.Modified != "2023-01-01T00:00:00Z" {
		t.Fatalf("dates = published %q, modified %q", vulnerability.Published, vulnerability.Modified)
	}
	if len(vulnerability.Severity) != 2 {
		t.Fatalf("severity = %+v", vulnerability.Severity)
	}
	if len(vulnerability.References) != 2 || vulnerability.References[1].URL != "https://example.test/report" {
		t.Fatalf("references = %+v", vulnerability.References)
	}
}

func TestQueryReportsMalformedResponseAndTransportFailure(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name      string
		transport roundTripFunc
		want      string
	}{
		{
			name: "malformed JSON",
			transport: func(_ *http.Request) (*http.Response, error) {
				return jsonResponse(http.StatusOK, `{not-json`), nil
			},
			want: "decode OSV response",
		},
		{
			name: "transport failure",
			transport: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("connection refused")
			},
			want: "query OSV API",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := osv.NewClientWithBaseURL("https://api.test", &http.Client{Transport: test.transport})
			_, err := client.Query(context.Background(), osv.Package{Name: "pkg", Ecosystem: "npm"}, "1.0")
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Query() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestQueryHonorsCanceledContext(t *testing.T) {
	t.Parallel()

	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, request.Context().Err()
	})}
	client := osv.NewClientWithBaseURL("https://api.test", httpClient)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Query(ctx, osv.Package{Name: "pkg", Ecosystem: "npm"}, "1.0")
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Query() error = %v, want context.Canceled", err)
	}
}

func TestAPIErrorFormatting(t *testing.T) {
	t.Parallel()

	tests := []struct {
		body string
		want string
	}{
		{body: "", want: "OSV API returned 503 Service Unavailable"},
		{body: "maintenance", want: "OSV API returned 503 Service Unavailable: maintenance"},
	}
	for _, test := range tests {
		test := test
		t.Run(fmt.Sprintf("body=%q", test.body), func(t *testing.T) {
			t.Parallel()
			err := (&osv.APIError{
				StatusCode: http.StatusServiceUnavailable,
				Status:     "503 Service Unavailable",
				Body:       test.body,
			}).Error()
			if err != test.want {
				t.Fatalf("Error() = %q, want %q", err, test.want)
			}
		})
	}
}
