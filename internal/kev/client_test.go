package kev_test

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/solongate/psirtmap/internal/kev"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func response(status int, body string) *http.Response {
	return &http.Response{
		StatusCode: status,
		Status:     fmt.Sprintf("%d %s", status, http.StatusText(status)),
		Header:     make(http.Header),
		Body:       io.NopCloser(strings.NewReader(body)),
	}
}

const validCatalog = `{
  "catalogVersion":"2026.10.01",
  "dateReleased":"2026-10-01T12:00:00.000Z",
  "count":2,
  "vulnerabilities":[
    {
      "cveID":"CVE-2026-99999",
      "vendorProject":"Vendor B",
      "product":"Product B",
      "vulnerabilityName":"Second vulnerability",
      "dateAdded":"2026-10-01",
      "shortDescription":"Second description",
      "requiredAction":"Apply mitigations",
      "dueDate":"2026-10-22",
      "knownRansomwareCampaignUse":"Unknown",
      "cwes":["CWE-79","CWE-79"]
    },
    {
      "cveID":" cve-2026-12345 ",
      "vendorProject":" Vendor A ",
      "product":" Product A ",
      "vulnerabilityName":" First vulnerability ",
      "dateAdded":"2026-09-30",
      "shortDescription":" First description ",
      "requiredAction":" Update product ",
      "dueDate":"2026-10-21",
      "knownRansomwareCampaignUse":"Known",
      "notes":" Advisory "
    }
  ]
}`

func TestFetchValidatesNormalizesAndSortsCatalog(t *testing.T) {
	t.Parallel()
	httpClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodGet || request.URL.String() != "https://kev.test/catalog.json" {
			t.Fatalf("request = %s %s", request.Method, request.URL)
		}
		if request.Header.Get("Accept") != "application/json" || !strings.HasPrefix(request.Header.Get("User-Agent"), "psirtmap/") {
			t.Fatalf("headers = %#v", request.Header)
		}
		return response(http.StatusOK, validCatalog), nil
	})}
	catalog, err := kev.NewClientWithURL("https://kev.test/catalog.json", httpClient).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if catalog.SourceURL != "https://kev.test/catalog.json" || catalog.Count != 2 {
		t.Fatalf("catalog = %+v", catalog)
	}
	if catalog.Vulnerabilities[0].CVEID != "CVE-2026-12345" || catalog.Vulnerabilities[0].VendorProject != "Vendor A" {
		t.Fatalf("first entry = %+v", catalog.Vulnerabilities[0])
	}
	if len(catalog.Vulnerabilities[1].CWEs) != 1 {
		t.Fatalf("CWEs = %v", catalog.Vulnerabilities[1].CWEs)
	}
}

func TestFetchRejectsHTTPAndTransportErrors(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		transport roundTripFunc
		want      string
	}{
		{
			name: "HTTP",
			transport: func(_ *http.Request) (*http.Response, error) {
				return response(http.StatusServiceUnavailable, "maintenance"), nil
			},
			want: "503 Service Unavailable",
		},
		{
			name: "transport",
			transport: func(_ *http.Request) (*http.Response, error) {
				return nil, errors.New("connection refused")
			},
			want: "connection refused",
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := kev.NewClientWithURL("https://kev.test/catalog.json", &http.Client{Transport: test.transport})
			_, err := client.Fetch(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Fetch() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFetchFallsBackAfterEndpointTimeout(t *testing.T) {
	t.Parallel()
	requests := 0
	httpClient := &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
		requests++
		if requests == 1 {
			return nil, context.DeadlineExceeded
		}
		return response(http.StatusOK, validCatalog), nil
	})}
	catalog, err := kev.NewClient(httpClient).Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch() error = %v", err)
	}
	if requests != 2 || catalog.SourceURL != kev.MirrorURL {
		t.Fatalf("requests = %d, source = %q", requests, catalog.SourceURL)
	}
}

func TestFetchRejectsMalformedAndInvalidCatalogs(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		body string
		want string
	}{
		{name: "malformed", body: `{not-json`, want: "decode CISA KEV response"},
		{name: "count", body: strings.Replace(validCatalog, `"count":2`, `"count":1`, 1), want: "count is 1"},
		{name: "release time", body: strings.Replace(validCatalog, `2026-10-01T12:00:00.000Z`, `yesterday`, 1), want: "release time"},
		{name: "CVE", body: strings.Replace(validCatalog, `CVE-2026-99999`, `NOT-A-CVE`, 1), want: "CVE ID"},
		{name: "date", body: strings.Replace(validCatalog, `2026-10-22`, `22 October`, 1), want: "due date"},
		{name: "duplicate", body: strings.Replace(validCatalog, `cve-2026-12345`, `CVE-2026-99999`, 1), want: "duplicate"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			client := kev.NewClientWithURL("https://kev.test/catalog.json", &http.Client{Transport: roundTripFunc(func(_ *http.Request) (*http.Response, error) {
				return response(http.StatusOK, test.body), nil
			})})
			_, err := client.Fetch(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("Fetch() error = %v, want %q", err, test.want)
			}
		})
	}
}

func TestFetchHonorsCanceledContext(t *testing.T) {
	t.Parallel()
	client := kev.NewClientWithURL("https://kev.test/catalog.json", &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		return nil, request.Context().Err()
	})})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := client.Fetch(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Fetch() error = %v, want context.Canceled", err)
	}
}

func TestValidateCatalogRejectsMissingFields(t *testing.T) {
	t.Parallel()
	catalog := kev.Catalog{
		CatalogVersion: "1", DateReleased: "2026-10-01T00:00:00Z", Count: 1,
		Vulnerabilities: []kev.Vulnerability{{CVEID: "CVE-2026-12345"}},
	}
	if err := kev.ValidateCatalog(&catalog); err == nil || !strings.Contains(err.Error(), "is required") {
		t.Fatalf("ValidateCatalog() error = %v", err)
	}
}
