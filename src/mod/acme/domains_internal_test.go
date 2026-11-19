package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"reflect"
	"testing"
	"time"
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

// writeDomainsTestCert writes a self-signed certificate for dnsNames to path
func writeDomainsTestCert(t *testing.T, path string, dnsNames []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
}

// Requesting a certificate for a host must not drop other domains of the
// certificate it replaces (e.g. a wildcard added in the ACME tool), and the
// requested domains stay first because the first one becomes the CN
func TestWithExistingCertDomains(t *testing.T) {
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
	writeDomainsTestCert(t, "conf/certs/example.com.pem", []string{"*.example.com", "example.com"})

	got := withExistingCertDomains([]string{"example.com", "www.example.com"}, "example.com")
	want := []string{"example.com", "www.example.com", "*.example.com"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}

	//No existing certificate: only the requested domains
	if got := withExistingCertDomains([]string{"new.example.com"}, "new.example.com"); !reflect.DeepEqual(got, []string{"new.example.com"}) {
		t.Errorf("got %v for a new certificate", got)
	}

	if got := mergeDomainsKeepOrder([]string{"a.com", "a.com"}, nil); !reflect.DeepEqual(got, []string{"a.com"}) {
		t.Errorf("duplicates in the primary list not removed: %v", got)
	}
}
