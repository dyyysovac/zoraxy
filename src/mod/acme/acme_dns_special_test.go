package acme

import (
	"os"
	"testing"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/providers/dns/plesk"
	"imuslab.com/zoraxy/mod/acme/acmedns"
)

// Plesk keeps the server base URL in an unexported config field, so it used to
// fail with "missing server base URL" whatever was entered in the UI (#1156)
func TestGetDnsChallengeProviderByName_Plesk(t *testing.T) {
	os.Unsetenv(plesk.EnvServerBaseURL)
	creds := `{"baseURL":"https://plesk.example.com:8443","Username":"admin","Password":"secret","PollingInterval":"5","PropagationTimeout":"300"}`

	provider, err := GetDnsChallengeProviderByName("plesk", creds, 600)
	if err != nil {
		t.Fatalf("unable to create plesk provider: %v", err)
	}

	timeoutProvider, ok := provider.(challenge.ProviderTimeout)
	if !ok {
		t.Fatal("plesk provider does not expose its timeouts")
	}
	timeout, interval := timeoutProvider.Timeout()
	if timeout != 300*time.Second || interval != 5*time.Second {
		t.Errorf("UI timeouts not applied, got timeout=%v interval=%v", timeout, interval)
	}

	//The credentials must not leak into the process environment
	if _, exists := os.LookupEnv(plesk.EnvServerBaseURL); exists {
		t.Errorf("%s left in the environment", plesk.EnvServerBaseURL)
	}
	if _, exists := os.LookupEnv(plesk.EnvPassword); exists {
		t.Errorf("%s left in the environment", plesk.EnvPassword)
	}
}

func TestGetDnsChallengeProviderByName_PleskMissingBaseURL(t *testing.T) {
	_, err := GetDnsChallengeProviderByName("plesk", `{"baseURL":"","Username":"admin","Password":"secret"}`, 600)
	if err == nil {
		t.Fatal("expected an error for a missing base URL")
	}
}

// selfhostde needs a record ID mapping that had no input field (#1067)
func TestGetDnsChallengeProviderByName_Selfhostde(t *testing.T) {
	structure, err := acmedns.GetProviderConfigStructure("selfhostde")
	if err != nil {
		t.Fatal(err)
	}
	if structure["RecordsMapping"] != "string" {
		t.Fatalf("RecordsMapping is not exposed to the UI: %v", structure)
	}

	creds := `{"Username":"user","Password":"secret","RecordsMapping":"example.com:123:456, other.example.com:789","PollingInterval":"2","PropagationTimeout":"600"}`
	if _, err := GetDnsChallengeProviderByName("selfhostde", creds, 600); err != nil {
		t.Fatalf("unable to create selfhostde provider: %v", err)
	}

	if _, err := GetDnsChallengeProviderByName("selfhostde", `{"Username":"user","Password":"secret","RecordsMapping":""}`, 600); err == nil {
		t.Fatal("expected an error for an empty record mapping")
	}
}

func TestParseSelfhostdeRecordsMapping(t *testing.T) {
	mapping, err := parseSelfhostdeRecordsMapping("example.com:123:456,other.example.com:789")
	if err != nil {
		t.Fatal(err)
	}
	if len(mapping) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(mapping))
	}
	//Two IDs are used in turn (wildcard + root), one ID is reused
	if a, b := mapping["example.com"].Next(), mapping["example.com"].Next(); a != "123" || b != "456" {
		t.Errorf("unexpected IDs for example.com: %s, %s", a, b)
	}
	if id := mapping["other.example.com"].Next(); id != "789" {
		t.Errorf("unexpected ID for other.example.com: %s", id)
	}

	for _, invalid := range []string{"", "example.com", "example.com:", ":123", "example.com:1:2:3"} {
		if _, err := parseSelfhostdeRecordsMapping(invalid); err == nil {
			t.Errorf("expected an error for %q", invalid)
		}
	}
}

// Numbers for the timeout fields must not panic (they used to be asserted to string)
func TestGetDnsChallengeProviderByName_NumericTimeouts(t *testing.T) {
	creds := `{"Username":"user","Password":"secret","RecordsMapping":"example.com:1","PollingInterval":3,"PropagationTimeout":120}`
	if _, err := GetDnsChallengeProviderByName("selfhostde", creds, 600); err != nil {
		t.Fatalf("numeric timeouts rejected: %v", err)
	}
}

// syse requires a zone:password credential map that was hidden from the UI
func TestGetDnsChallengeProviderByName_Syse(t *testing.T) {
	structure, err := acmedns.GetProviderConfigStructure("syse")
	if err != nil {
		t.Fatal(err)
	}
	if structure["Credentials"] != "string" {
		t.Fatalf("Credentials is not exposed to the UI: %v", structure)
	}
	creds := `{"Credentials":"example.com:password1,example.org:password2","PollingInterval":"2","PropagationTimeout":"600"}`
	if _, err := GetDnsChallengeProviderByName("syse", creds, 600); err != nil {
		t.Fatalf("unable to create syse provider: %v", err)
	}
	if _, err := GetDnsChallengeProviderByName("syse", `{"Credentials":"no-password-here"}`, 600); err == nil {
		t.Fatal("expected an error for malformed credentials")
	}
}

// yandex360 requires OrgID (int64), which the generator hid from the UI
func TestGetDnsChallengeProviderByName_Yandex360(t *testing.T) {
	structure, err := acmedns.GetProviderConfigStructure("yandex360")
	if err != nil {
		t.Fatal(err)
	}
	if structure["OrgID"] != "int" {
		t.Fatalf("OrgID is not exposed to the UI as int: %v", structure)
	}
	//The UI sends int fields as JSON numbers
	creds := `{"OAuthToken":"token","OrgID":123456,"PollingInterval":"2","PropagationTimeout":"600"}`
	if _, err := GetDnsChallengeProviderByName("yandex360", creds, 600); err != nil {
		t.Fatalf("unable to create yandex360 provider: %v", err)
	}
}

// Unexported lego fields cannot be set from JSON and must not be offered in
// the UI, except the ones Zoraxy sets by hand
func TestGetProviderConfigStructure_UnexportedFields(t *testing.T) {
	ucloud, err := acmedns.GetProviderConfigStructure("ucloud")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := ucloud["baseURL"]; ok {
		t.Error("ucloud baseURL (unexported, test only) is still offered in the UI")
	}
	pleskFields, err := acmedns.GetProviderConfigStructure("plesk")
	if err != nil {
		t.Fatal(err)
	}
	if pleskFields["baseURL"] != "string" {
		t.Error("plesk baseURL must stay configurable")
	}
}
