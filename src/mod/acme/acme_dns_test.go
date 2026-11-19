package acme

import (
	"reflect"
	"strings"
	"testing"
)

// legoConfigField reads a field of the unexported config of a lego provider
func legoConfigField(t *testing.T, provider any, field string) reflect.Value {
	t.Helper()
	config := reflect.ValueOf(provider).Elem().FieldByName("config")
	if !config.IsValid() || config.IsNil() {
		t.Fatalf("%T has no config", provider)
	}
	value := config.Elem().FieldByName(field)
	if !value.IsValid() {
		t.Fatalf("%T config has no field %s", provider, field)
	}
	return value
}

// The ACME form sends every field it shows, so fields the user did not fill in
// arrive as "" and must not replace the lego defaults
func TestGetDnsChallengeProviderByName_EmptyFieldsKeepDefaults(t *testing.T) {
	provider, err := GetDnsChallengeProviderByName("cpanel", `{"Mode":"","Username":"user","Token":"token","BaseURL":"https://cpanel.example.com:2083","PollingInterval":2,"PropagationTimeout":600}`, 600)
	if err != nil {
		t.Fatalf("cpanel: %v", err)
	}
	if mode := legoConfigField(t, provider, "Mode").String(); mode != "cpanel" {
		t.Errorf("cpanel Mode = %q, want the lego default cpanel", mode)
	}

	provider, err = GetDnsChallengeProviderByName("infoblox", `{"Host":"infoblox.example.com","Port":"","Username":"user","Password":"secret","DNSView":"","WapiVersion":"","SSLVerify":true,"CACertificate":"","HTTPTimeout":300}`, 600)
	if err != nil {
		t.Fatalf("infoblox: %v", err)
	}
	for field, want := range map[string]string{"Port": "443", "DNSView": "External", "WapiVersion": "2.11"} {
		if got := legoConfigField(t, provider, field).String(); got != want {
			t.Errorf("infoblox %s = %q, want the lego default %q", field, got, want)
		}
	}
}

func TestGetDnsChallengeProviderByName_PdnsDefaults(t *testing.T) {
	//APIVersion 10 was the value older forms pre-filled for every number field
	for _, creds := range []string{
		`{"APIKey":"key","Host":"http://127.0.0.1:1","ServerName":""}`,
		`{"APIKey":"key","Host":"http://127.0.0.1:1","ServerName":"","APIVersion":10}`,
	} {
		provider, err := GetDnsChallengeProviderByName("pdns", creds, 600)
		if err != nil {
			t.Fatalf("pdns %s: %v", creds, err)
		}
		if name := legoConfigField(t, provider, "ServerName").String(); name != "localhost" {
			t.Errorf("pdns ServerName = %q, want localhost", name)
		}
		if version := legoConfigField(t, provider, "APIVersion").Int(); version != 0 {
			t.Errorf("pdns APIVersion = %d, want 0 (auto-detect)", version)
		}
		if legoConfigField(t, provider, "Host").IsNil() {
			t.Errorf("pdns Host not set")
		}
	}
}

func TestGetDnsChallengeProviderByName_URLFields(t *testing.T) {
	//An empty or missing endpoint keeps the lego default
	for _, creds := range []string{
		`{"Endpoint":"","Username":"user","APIKey":"key"}`,
		`{"Username":"user","APIKey":"key"}`,
	} {
		provider, err := GetDnsChallengeProviderByName("zoneee", creds, 600)
		if err != nil {
			t.Fatalf("zoneee %s: %v", creds, err)
		}
		if endpoint := legoConfigField(t, provider, "Endpoint").Elem().FieldByName("Host").String(); endpoint != "api.zone.eu" {
			t.Errorf("zoneee endpoint host = %q, want api.zone.eu", endpoint)
		}
	}

	//checkdomain has no endpoint in its lego default config
	provider, err := GetDnsChallengeProviderByName("checkdomain", `{"Endpoint":"","Token":"token"}`, 600)
	if err != nil {
		t.Fatalf("checkdomain: %v", err)
	}
	if endpoint := legoConfigField(t, provider, "Endpoint").Elem().FieldByName("Host").String(); endpoint != "api.checkdomain.de" {
		t.Errorf("checkdomain endpoint host = %q, want api.checkdomain.de", endpoint)
	}

	//A value entered by the user is used, whatever the key case
	provider, err = GetDnsChallengeProviderByName("zoneee", `{"endpoint":"https://zone.example.com/v2/","Username":"user","APIKey":"key"}`, 600)
	if err != nil {
		t.Fatalf("zoneee lowercase key: %v", err)
	}
	if endpoint := legoConfigField(t, provider, "Endpoint").Elem().FieldByName("Host").String(); endpoint != "zone.example.com" {
		t.Errorf("zoneee endpoint host = %q, want zone.example.com", endpoint)
	}

	//Invalid values are errors, not a panic or a relative URL
	for _, creds := range []string{
		`{"Endpoint":1,"Username":"user","APIKey":"key"}`,
		`{"Endpoint":true,"Username":"user","APIKey":"key"}`,
		`{"Endpoint":"api.zone.eu/v2","Username":"user","APIKey":"key"}`,
	} {
		if _, err := GetDnsChallengeProviderByName("zoneee", creds, 600); err == nil {
			t.Errorf("zoneee %s: expected an error", creds)
		}
	}
}

// Provider names and keys saved by Zoraxy builds that used lego v4
func TestGetDnsChallengeProviderByName_LegacyCredentials(t *testing.T) {
	if _, err := GetDnsChallengeProviderByName("rfc2136", `{"Nameserver":"ns.example.com:53","TSIGAlgorithm":"","TSIGKey":"","TSIGSecret":""}`, 600); err != nil {
		t.Errorf("rfc2136: %v", err)
	}
	if _, err := GetDnsChallengeProviderByName("webnames", `{"APIKey":"key"}`, 600); err != nil {
		t.Errorf("webnames: %v", err)
	}

	provider, err := GetDnsChallengeProviderByName("scaleway", `{"ProjectID":"","Token":"11111111-1111-1111-1111-111111111111","AccessKey":""}`, 600)
	if err != nil {
		t.Fatalf("scaleway with the old Token key: %v", err)
	}
	if secret := legoConfigField(t, provider, "SecretKey").String(); secret != "11111111-1111-1111-1111-111111111111" {
		t.Errorf("scaleway SecretKey = %q, want the saved Token", secret)
	}

	_, err = GetDnsChallengeProviderByName("azure", `{"ClientID":"id"}`, 600)
	if err == nil || !strings.Contains(err.Error(), "azuredns") {
		t.Errorf("azure: expected an error naming azuredns, got %v", err)
	}
}
