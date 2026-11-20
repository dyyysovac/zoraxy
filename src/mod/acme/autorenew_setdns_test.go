package acme

import (
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"strings"
	"testing"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/info/logger"
)

func postSetDNS(t *testing.T, renewer *AutoRenewer, provider string, credentials string) (kept bool) {
	t.Helper()
	form := url.Values{"filename": {"example.com"}, "dnsProvider": {provider}, "dnsCredentials": {credentials}}
	r := httptest.NewRequest("POST", "/api/acme/autoRenew/setDNS", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	renewer.HandleSetDNS(w, r)
	if strings.Contains(w.Body.String(), "error") {
		t.Fatalf("setDNS failed: %s", w.Body.String())
	}
	return strings.Contains(w.Body.String(), `"kept":true`)
}

func storedDNS(t *testing.T, db *database.Database) (string, string) {
	t.Helper()
	provider, credentials := "", ""
	db.Read("acme", "example.com_dns_provider", &provider)
	db.Read("acme", "example.com_dns_credentials", &credentials)
	return provider, credentials
}

// The ACME form never shows the stored credentials. Requesting a certificate
// again without entering any credential keeps the stored config as a whole
// (and says so), anything entered replaces it as a whole. A first
// configuration without any value (e.g. route53 with credentials from the
// environment) and a provider switch are saved
func TestHandleSetDNS_KeepsStoredCredentials(t *testing.T) {
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "test.db"), dbinc.BackendBoltDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	testLogger, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	renewer := &AutoRenewer{AcmeHandler: &ACMEHandler{Database: db}, Logger: testLogger}

	const cloudflare = `{"AuthToken":"secret","PollingInterval":"2","PropagationTimeout":"600"}`

	//First configuration without any value is saved
	if postSetDNS(t, renewer, "route53", `{"AccessKeyID":"","SecretAccessKey":"","PollingInterval":"2","PropagationTimeout":"600"}`) {
		t.Error("first configuration reported as kept")
	}
	if provider, _ := storedDNS(t, db); provider != "route53" {
		t.Fatalf("first configuration not saved, provider = %q", provider)
	}

	//A stored config without any credential is not kept, so its other
	//settings can still be changed
	const route53Retries = `{"AccessKeyID":"","MaxRetries":10,"PollingInterval":"5","PropagationTimeout":"1800","SecretAccessKey":""}`
	if postSetDNS(t, renewer, "route53", route53Retries) {
		t.Error("stored config without credentials reported as kept")
	}
	if _, credentials := storedDNS(t, db); credentials != route53Retries {
		t.Fatalf("settings of a config without credentials not saved: %q", credentials)
	}

	//Switching provider replaces the config
	postSetDNS(t, renewer, "cloudflare", cloudflare)
	if provider, credentials := storedDNS(t, db); provider != "cloudflare" || credentials != cloudflare {
		t.Fatalf("provider switch not saved: %q %q", provider, credentials)
	}

	//Same provider, nothing entered: the stored config is kept as a whole
	//and the response says so, also when another setting was changed
	for _, posted := range []string{
		`{"AuthToken":"","PollingInterval":"2","PropagationTimeout":"600"}`,
		`{"AuthToken":"","PollingInterval":"2","PropagationTimeout":"1800"}`,
	} {
		if !postSetDNS(t, renewer, "cloudflare", posted) {
			t.Errorf("%s: response does not say the stored config was kept", posted)
		}
		if _, credentials := storedDNS(t, db); credentials != cloudflare {
			t.Fatalf("%s: stored config changed: %q", posted, credentials)
		}
	}

	//Anything entered replaces the config as a whole, so another auth method
	//does not keep the old token
	const globalKey = `{"AuthEmail":"admin@example.com","AuthKey":"global-key","AuthToken":"","PollingInterval":"2","PropagationTimeout":"600"}`
	if postSetDNS(t, renewer, "cloudflare", globalKey) {
		t.Error("new credentials reported as kept")
	}
	if _, credentials := storedDNS(t, db); credentials != globalKey {
		t.Fatalf("new credentials not saved: %q", credentials)
	}
}

// Certificates saved by Zoraxy builds with lego v4 use old provider names,
// and a stored config can be "null"
func TestHandleSetDNS_LegacyAndNullStoredConfig(t *testing.T) {
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "test.db"), dbinc.BackendBoltDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	testLogger, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	renewer := &AutoRenewer{AcmeHandler: &ACMEHandler{Database: db}, Logger: testLogger}
	db.NewTable("acme")

	const rfc2136 = `{"Nameserver":"ns.example.com:53","TSIGKey":"key","TSIGSecret":"secret"}`
	db.Write("acme", "example.com_dns_provider", "rfc2136")
	db.Write("acme", "example.com_dns_credentials", rfc2136)
	if !postSetDNS(t, renewer, "dnsupdate", `{"Nameserver":"","TSIGKey":"","TSIGSecret":"","PropagationTimeout":"600"}`) {
		t.Error("stored rfc2136 config not kept for dnsupdate")
	}
	if _, credentials := storedDNS(t, db); credentials != rfc2136 {
		t.Fatalf("stored rfc2136 secrets overwritten: %q", credentials)
	}

	db.Write("acme", "example.com_dns_provider", "cloudflare")
	db.Write("acme", "example.com_dns_credentials", "null")
	const posted = `{"AuthToken":"","PropagationTimeout":"600"}`
	if postSetDNS(t, renewer, "cloudflare", posted) {
		t.Error("null stored config reported as kept")
	}
	if _, credentials := storedDNS(t, db); credentials != posted {
		t.Fatalf("config not saved over a null stored config: %q", credentials)
	}
}
