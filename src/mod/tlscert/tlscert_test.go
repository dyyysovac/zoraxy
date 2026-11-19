package tlscert

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
)

// writeTestCert generates a self-signed certificate and writes it to
// <dir>/<certname>.pem and <dir>/<certname>.key
func writeTestCert(t *testing.T, dir string, certname string, cn string, dnsNames []string, notBefore time.Time, notAfter time.Time) *x509.Certificate {
	t.Helper()
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, big.NewInt(1<<62))
	if err != nil {
		t.Fatalf("failed to generate serial: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              dnsNames,
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privKey.PublicKey, privKey)
	if err != nil {
		t.Fatalf("failed to create certificate: %v", err)
	}
	keyDER, err := x509.MarshalECPrivateKey(privKey)
	if err != nil {
		t.Fatalf("failed to marshal key: %v", err)
	}
	pubPem := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	priPem := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	if err := os.WriteFile(filepath.Join(dir, certname+".pem"), pubPem, 0644); err != nil {
		t.Fatalf("failed to write cert: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, certname+".key"), priPem, 0600); err != nil {
		t.Fatalf("failed to write key: %v", err)
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("failed to parse certificate: %v", err)
	}
	return cert
}

func newTestManager(t *testing.T, certStore string) *Manager {
	t.Helper()
	l, _ := logger.NewFmtLogger()
	m := &Manager{
		CertStore:               certStore,
		LoadedCerts:             []*CertCache{},
		Logger:                  l,
		hostSpecificTlsBehavior: defaultHostSpecificTlsBehavior,
	}
	if err := m.UpdateLoadedCertList(); err != nil {
		t.Fatalf("failed to load certs: %v", err)
	}
	return m
}

func TestGetCertPairsSorted(t *testing.T) {
	input := []string{
		"zeta.com.pem", "zeta.com.key",
		"mycert.key", "mycert.pem",
		"b.com.pem", "b.com.key",
		"a.com.pem", "a.com.key",
		"orphan.pem",
		"onlykey.key",
		"k.com.key", "k.com.pem",
		"c.com.pem", "c.com.key",
		"x.org.pem", "x.org.key",
		"d.net.key", "d.net.pem",
		"_.wild.com.pem", "_.wild.com.key",
		"m.io.pem", "m.io.key",
		"fallback.json",
	}
	expected := []string{"_.wild.com", "a.com", "b.com", "c.com", "d.net", "k.com", "m.io", "mycert", "x.org", "zeta.com"}
	// Map iteration order is random, run a few times
	for i := 0; i < 20; i++ {
		result := getCertPairs(input)
		if !reflect.DeepEqual(result, expected) {
			t.Fatalf("getCertPairs() = %v, want %v", result, expected)
		}
	}
}

func certCacheEntry(name string, cert *x509.Certificate) *CertCache {
	return &CertCache{
		Cert:   cert,
		PubKey: name + ".pem",
		PriKey: name + ".key",
	}
}

func TestGetCertByX509CNHostnamePrefersValidCert(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	expired := writeTestCert(t, dir, "old", "", []string{"a.com", "b.com"}, now.Add(-100*24*time.Hour), now.Add(-10*24*time.Hour))
	valid := writeTestCert(t, dir, "new", "", []string{"a.com", "b.com"}, now.Add(-1*time.Hour), now.Add(80*24*time.Hour))

	orders := [][]*CertCache{
		{certCacheEntry("old", expired), certCacheEntry("new", valid)},
		{certCacheEntry("new", valid), certCacheEntry("old", expired)},
	}
	for i, order := range orders {
		m := &Manager{LoadedCerts: order}
		pub, pri := m.GetCertByX509CNHostname("b.com")
		if pub != "new.pem" || pri != "new.key" {
			t.Errorf("order %d: got (%s, %s), want the valid cert new.pem", i, pub, pri)
		}
	}
}

func TestGetCertByX509CNHostnamePrefersLatestExpiry(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	sooner := writeTestCert(t, dir, "sooner", "", []string{"a.com", "b.com"}, now.Add(-60*24*time.Hour), now.Add(20*24*time.Hour))
	later := writeTestCert(t, dir, "later", "", []string{"a.com", "b.com"}, now.Add(-1*time.Hour), now.Add(80*24*time.Hour))
	notYetValid := writeTestCert(t, dir, "future", "", []string{"a.com", "b.com"}, now.Add(24*time.Hour), now.Add(200*24*time.Hour))

	orders := [][]*CertCache{
		{certCacheEntry("sooner", sooner), certCacheEntry("future", notYetValid), certCacheEntry("later", later)},
		{certCacheEntry("later", later), certCacheEntry("sooner", sooner), certCacheEntry("future", notYetValid)},
		{certCacheEntry("future", notYetValid), certCacheEntry("later", later), certCacheEntry("sooner", sooner)},
	}
	for i, order := range orders {
		m := &Manager{LoadedCerts: order}
		pub, _ := m.GetCertByX509CNHostname("a.com")
		if pub != "later.pem" {
			t.Errorf("order %d: got %s, want later.pem", i, pub)
		}
	}
}

func TestGetCertByX509CNHostnameNoValidCertUsesFirstMatch(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	expiredA := writeTestCert(t, dir, "expiredA", "", []string{"a.com"}, now.Add(-100*24*time.Hour), now.Add(-10*24*time.Hour))
	expiredB := writeTestCert(t, dir, "expiredB", "", []string{"a.com"}, now.Add(-50*24*time.Hour), now.Add(-1*24*time.Hour))
	other := writeTestCert(t, dir, "other", "", []string{"other.com"}, now.Add(-1*time.Hour), now.Add(80*24*time.Hour))

	m := &Manager{LoadedCerts: []*CertCache{
		certCacheEntry("other", other),
		certCacheEntry("expiredA", expiredA),
		certCacheEntry("expiredB", expiredB),
	}}
	pub, _ := m.GetCertByX509CNHostname("a.com")
	if pub != "expiredA.pem" {
		t.Errorf("got %s, want first match expiredA.pem", pub)
	}

	pub, pri := m.GetCertByX509CNHostname("nomatch.com")
	if pub != "" || pri != "" {
		t.Errorf("got (%s, %s), want no match", pub, pri)
	}
}

// Old multi-domain cert and a new one both cover b.com. The SNI lookup
// must return the valid one, no matter which file sorts first
func TestGetCertificateByHostnameOverlappingCertsFromDisk(t *testing.T) {
	now := time.Now()
	cases := []struct {
		expiredName string
		validName   string
	}{
		{expiredName: "a.com", validName: "mycert"},
		{expiredName: "mycert", validName: "a.com"},
	}
	for _, tc := range cases {
		dir := t.TempDir()
		writeTestCert(t, dir, tc.expiredName, "", []string{"a.com", "b.com"}, now.Add(-100*24*time.Hour), now.Add(-10*24*time.Hour))
		writeTestCert(t, dir, tc.validName, "", []string{"a.com", "b.com"}, now.Add(-1*time.Hour), now.Add(80*24*time.Hour))
		m := newTestManager(t, dir)

		for i := 0; i < 10; i++ {
			pub, pri, err := m.GetCertificateByHostname("b.com")
			if err != nil {
				t.Fatalf("GetCertificateByHostname() error: %v", err)
			}
			if pub != filepath.Join(dir, tc.validName+".pem") || pri != filepath.Join(dir, tc.validName+".key") {
				t.Fatalf("expired=%s valid=%s: got (%s, %s), want the valid cert", tc.expiredName, tc.validName, pub, pri)
			}
			if err := m.UpdateLoadedCertList(); err != nil {
				t.Fatalf("failed to reload certs: %v", err)
			}
		}
	}
}

func TestHandleListDomainsCompactOverlappingCerts(t *testing.T) {
	dir := t.TempDir()
	now := time.Now()
	notBefore := now.Add(-1 * time.Hour)
	notAfter := now.Add(80 * 24 * time.Hour)
	// Every SAN of a.com.pem is also in b.com.pem (lego v5 certs have no CN)
	writeTestCert(t, dir, "a.com", "", []string{"a.com", "b.com"}, notBefore, notAfter)
	writeTestCert(t, dir, "b.com", "", []string{"a.com", "b.com", "c.com"}, notBefore, notAfter)
	// CN already in the SAN list must not be duplicated
	writeTestCert(t, dir, "d.com", "d.com", []string{"d.com", "www.d.com"}, notBefore, notAfter)
	// CN not in the SAN list is added
	writeTestCert(t, dir, "e.com", "e.com", []string{"alias.e.com"}, notBefore, notAfter)
	m := newTestManager(t, dir)

	req := httptest.NewRequest("GET", "/api/cert/listdomains?compact=true", nil)
	rec := httptest.NewRecorder()
	m.HandleListDomains(rec, req)

	result := map[string][]string{}
	if err := json.Unmarshal(rec.Body.Bytes(), &result); err != nil {
		t.Fatalf("failed to parse response %q: %v", rec.Body.String(), err)
	}
	for _, domains := range result {
		sort.Strings(domains)
	}
	expected := map[string][]string{
		"a.com": {"a.com", "b.com"},
		"b.com": {"a.com", "b.com", "c.com"},
		"d.com": {"d.com", "www.d.com"},
		"e.com": {"alias.e.com", "e.com"},
	}
	if !reflect.DeepEqual(result, expected) {
		t.Errorf("compact listdomains = %v, want %v", result, expected)
	}

	// Non-compact mode keeps mapping each domain to a cert filename
	req = httptest.NewRequest("GET", "/api/cert/listdomains", nil)
	rec = httptest.NewRecorder()
	m.HandleListDomains(rec, req)
	domainMap := map[string]string{}
	if err := json.Unmarshal(rec.Body.Bytes(), &domainMap); err != nil {
		t.Fatalf("failed to parse response %q: %v", rec.Body.String(), err)
	}
	if domainMap["c.com"] != "b.com" || domainMap["www.d.com"] != "d.com" || domainMap["alias.e.com"] != "e.com" {
		t.Errorf("non-compact listdomains = %v", domainMap)
	}
}
