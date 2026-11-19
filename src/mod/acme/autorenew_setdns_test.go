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

func postSetDNS(t *testing.T, renewer *AutoRenewer, provider string, credentials string) {
	t.Helper()
	form := url.Values{"filename": {"example.com"}, "dnsProvider": {provider}, "dnsCredentials": {credentials}}
	r := httptest.NewRequest("POST", "/api/acme/autoRenew/setDNS", strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	w := httptest.NewRecorder()
	renewer.HandleSetDNS(w, r)
	if strings.Contains(w.Body.String(), "error") {
		t.Fatalf("setDNS failed: %s", w.Body.String())
	}
}

func storedDNS(t *testing.T, db *database.Database) (string, string) {
	t.Helper()
	provider, credentials := "", ""
	db.Read("acme", "example.com_dns_provider", &provider)
	db.Read("acme", "example.com_dns_credentials", &credentials)
	return provider, credentials
}

// The ACME form never shows the stored credentials. Requesting a certificate
// again without retyping them must keep them, while a first configuration
// without any value (e.g. route53 with credentials from the environment) and
// a provider switch must still be saved
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
	const emptyCloudflare = `{"AuthToken":"","PollingInterval":"2","PropagationTimeout":"600"}`

	//First configuration without any value is saved
	postSetDNS(t, renewer, "route53", `{"AccessKeyID":"","SecretAccessKey":"","PollingInterval":"2","PropagationTimeout":"600"}`)
	if provider, _ := storedDNS(t, db); provider != "route53" {
		t.Fatalf("first configuration not saved, provider = %q", provider)
	}

	//Switching provider replaces the config
	postSetDNS(t, renewer, "cloudflare", cloudflare)
	if provider, credentials := storedDNS(t, db); provider != "cloudflare" || credentials != cloudflare {
		t.Fatalf("provider switch not saved: %q %q", provider, credentials)
	}

	//Same provider, nothing entered: the stored secret is kept
	postSetDNS(t, renewer, "cloudflare", emptyCloudflare)
	if _, credentials := storedDNS(t, db); credentials != cloudflare {
		t.Fatalf("stored credentials overwritten with an empty config: %q", credentials)
	}

	//Same provider with a new value replaces it
	const newCloudflare = `{"AuthToken":"new-secret","PollingInterval":"2","PropagationTimeout":"600"}`
	postSetDNS(t, renewer, "cloudflare", newCloudflare)
	if _, credentials := storedDNS(t, db); credentials != newCloudflare {
		t.Fatalf("new credentials not saved: %q", credentials)
	}

	//Other settings changed without retyping the secret are saved, the
	//secret is kept
	postSetDNS(t, renewer, "cloudflare", `{"AuthToken":"","PollingInterval":"2","PropagationTimeout":"1800"}`)
	if _, credentials := storedDNS(t, db); credentials != `{"AuthToken":"new-secret","PollingInterval":"2","PropagationTimeout":"1800"}` {
		t.Fatalf("changed timeout not merged with the stored secret: %q", credentials)
	}

	postSetDNS(t, renewer, "infoblox", `{"Host":"infoblox.example.com","Password":"secret","SSLVerify":true}`)
	postSetDNS(t, renewer, "infoblox", `{"Host":"","Password":"","SSLVerify":false}`)
	if _, credentials := storedDNS(t, db); credentials != `{"Host":"infoblox.example.com","Password":"secret","SSLVerify":false}` {
		t.Fatalf("checkbox change not merged with the stored values: %q", credentials)
	}
}
