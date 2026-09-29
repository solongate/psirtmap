package osv_test

import (
	"context"
	"encoding/json"
	"errors"
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
