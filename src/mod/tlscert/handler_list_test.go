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
	"testing"
	"time"
)

// writeCertListTestPair writes a self-signed certificate for dnsNames as
// <name>.pem / <name>.key into dir
func writeCertListTestPair(t *testing.T, dir string, name string, dnsNames []string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{},
		DNSNames:     dnsNames,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDer, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	os.WriteFile(filepath.Join(dir, name+".pem"), pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	os.WriteFile(filepath.Join(dir, name+".key"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDer}), 0o600)
}

// The certificate list must return the domains of each certificate, so the
// Renew button can renew them all instead of sending the filename as domain,
// which is not a domain for certificates named in the ACME tool
func TestHandleListCertificate_Domains(t *testing.T) {
	dir := t.TempDir()
	writeCertListTestPair(t, dir, "mycert", []string{"a.example.com", "b.example.com"})
	m := &Manager{CertStore: dir}

	w := httptest.NewRecorder()
	m.HandleListCertificate(w, httptest.NewRequest("GET", "/api/cert/list?date=true", nil))

	var list []struct {
		Filename string
		Domains  []string
	}
	if err := json.Unmarshal(w.Body.Bytes(), &list); err != nil {
		t.Fatalf("invalid response %q: %v", w.Body.String(), err)
	}
	if len(list) != 1 || list[0].Filename != "mycert" {
		t.Fatalf("unexpected list: %s", w.Body.String())
	}
	if want := []string{"a.example.com", "b.example.com"}; !reflect.DeepEqual(list[0].Domains, want) {
		t.Errorf("Domains = %v, want %v", list[0].Domains, want)
	}
}
