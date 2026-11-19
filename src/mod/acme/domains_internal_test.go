package acme

import (
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
)

// An empty entry (trailing comma, empty alias) used to fail the whole request
// with "domain is empty"
func TestParseDomainList(t *testing.T) {
	for input, want := range map[string][]string{
		"a.com,b.com,":    {"a.com", "b.com"},
		"a.com,,b.com":    {"a.com", "b.com"},
		" a.com , b.com ": {"a.com", "b.com"},
		",a.com":          {"a.com"},
		"a.com":           {"a.com"},
	} {
		got, err := parseDomainList(input)
		if err != nil {
			t.Errorf("%q: %v", input, err)
			continue
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%q: got %v, want %v", input, got, want)
		}
	}

	for _, input := range []string{",", " , ", ""} {
		if _, err := parseDomainList(input); err == nil {
			t.Errorf("%q: expected an error", input)
		}
	}
}

// An explicit challenge type (e.g. DNS-01 for a wildcard in the ACME tool)
// must win over the one stored for the certificate, a request without one
// keeps the stored type
func TestRequestUsesDNSChallenge(t *testing.T) {
	workdir := t.TempDir()
	previous, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(workdir); err != nil {
		t.Fatal(err)
	}
	defer os.Chdir(previous)
	os.MkdirAll("conf/certs", 0o755)
	os.WriteFile("conf/certs/dns.example.com.json", []byte(`{"dns":true}`), 0o644)
	os.WriteFile("conf/certs/http.example.com.json", []byte(`{"dns":false}`), 0o644)

	for query, want := range map[string]bool{
		"filename=dns.example.com":              true,
		"filename=dns.example.com&dns=":         true,
		"filename=dns.example.com&dns=false":    false,
		"filename=http.example.com":             false,
		"filename=http.example.com&dns=true":    true,
		"filename=_.http.example.com&dns=true":  true,
		"filename=missing.example.com":          false,
		"filename=missing.example.com&dns=true": true,
		"domains=a.com":                         false,
	} {
		r := httptest.NewRequest("GET", "/api/acme/obtainCert?"+query, nil)
		if got := RequestUsesDNSChallenge(r); got != want {
			t.Errorf("%s: got %v, want %v", query, got, want)
		}
	}
}
