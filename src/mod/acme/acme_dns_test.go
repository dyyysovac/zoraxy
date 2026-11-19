package acme

import (
	"reflect"
	"strings"
	"testing"

	"github.com/go-acme/lego/v5/providers/dns/exoscale"
	"github.com/go-acme/lego/v5/providers/dns/jdcloud"
	"github.com/go-acme/lego/v5/providers/dns/lightsail"
	"github.com/go-acme/lego/v5/providers/dns/vkcloud"
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

// Some lego defaults are only set by the env based NewDNSProvider(), not by
// NewDefaultConfig(). The form sends only the credentials, the rest is ""
func TestGetDnsChallengeProviderByName_EnvOnlyDefaults(t *testing.T) {
	tests := []struct {
		provider string
		creds    string
		want     map[string]string // config field => lego default
		envVars  []string          // lego environment variables of the fields
	}{
		{
			provider: "exoscale",
			creds:    `{"APIKey":"key","APISecret":"secret","Endpoint":"","PropagationTimeout":"600","PollingInterval":"2"}`,
			want:     map[string]string{"Endpoint": "https://api-ch-gva-2.exoscale.com/v2"},
			envVars:  []string{exoscale.EnvEndpoint},
		},
		{
			provider: "jdcloud",
			creds:    `{"AccessKeyID":"id","AccessKeySecret":"secret","RegionID":"","PropagationTimeout":"600","PollingInterval":"2"}`,
			want:     map[string]string{"RegionID": "cn-north-1"},
			envVars:  []string{jdcloud.EnvRegionID},
		},
		{
			//lightsail takes the AWS credentials from the environment, the form has no credential field
			provider: "lightsail",
			creds:    `{"DNSZone":"","Region":"","PropagationTimeout":"600","PollingInterval":"2"}`,
			want:     map[string]string{"Region": "us-east-1"},
			envVars:  []string{lightsail.EnvRegion},
		},
		{
			provider: "vkcloud",
			creds:    `{"ProjectID":"project","Username":"user","Password":"secret","DNSEndpoint":"","IdentityEndpoint":"","DomainName":"","PropagationTimeout":"600","PollingInterval":"2"}`,
			want: map[string]string{
				"DNSEndpoint":      "https://mcs.mail.ru/public-dns/v2/dns",
				"IdentityEndpoint": "https://infra.mail.ru/identity/v3/",
				"DomainName":       "users",
			},
			envVars: []string{vkcloud.EnvDNSEndpoint, vkcloud.EnvIdentityEndpoint, vkcloud.EnvDomainName},
		},
	}

	for _, tt := range tests {
		t.Run(tt.provider, func(t *testing.T) {
			for _, envVar := range tt.envVars {
				t.Setenv(envVar, "")
			}

			provider, err := GetDnsChallengeProviderByName(tt.provider, tt.creds, 600)
			if err != nil {
				t.Fatalf("%s: %v", tt.provider, err)
			}
			for field, want := range tt.want {
				if got := legoConfigField(t, provider, field).String(); got != want {
					t.Errorf("%s %s = %q, want the lego default %q", tt.provider, field, got, want)
				}
			}
		})
	}
}

// A value entered in the form or set in the lego environment variable is used
// instead of the default, the same way lego's NewDNSProvider() does
func TestGetDnsChallengeProviderByName_EnvOnlyDefaultsOverride(t *testing.T) {
	t.Setenv(jdcloud.EnvRegionID, "cn-east-2")

	provider, err := GetDnsChallengeProviderByName("jdcloud", `{"AccessKeyID":"id","AccessKeySecret":"secret","RegionID":""}`, 600)
	if err != nil {
		t.Fatalf("jdcloud: %v", err)
	}
	if region := legoConfigField(t, provider, "RegionID").String(); region != "cn-east-2" {
		t.Errorf("jdcloud RegionID = %q, want %s from the environment", region, jdcloud.EnvRegionID)
	}

	for _, creds := range []string{
		`{"AccessKeyID":"id","AccessKeySecret":"secret","RegionID":"cn-south-1"}`,
		`{"AccessKeyID":"id","AccessKeySecret":"secret","regionid":"cn-south-1"}`,
	} {
		provider, err = GetDnsChallengeProviderByName("jdcloud", creds, 600)
		if err != nil {
			t.Fatalf("jdcloud %s: %v", creds, err)
		}
		if region := legoConfigField(t, provider, "RegionID").String(); region != "cn-south-1" {
			t.Errorf("jdcloud %s: RegionID = %q, want the value entered by the user", creds, region)
		}
	}
}
