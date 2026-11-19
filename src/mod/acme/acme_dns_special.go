package acme

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/platform/env"
	"github.com/go-acme/lego/v5/providers/dns/plesk"
	"github.com/go-acme/lego/v5/providers/dns/selfhostde"
	"github.com/go-acme/lego/v5/providers/dns/syse"
)

/*
	acme_dns_special.go

	A few lego DNS providers cannot be fully configured by unmarshalling the
	credential JSON from the UI into their lego Config struct, which is what the
	generated acmedns.GetDNSProviderByJsonConfig() does:

	- plesk: Config.baseURL is unexported and can only be set by lego itself
	  from the PLESK_SERVER_BASE_URL environment variable (#1156)
	- selfhostde: Config.RecordsMapping is a map[string]*selfhostde.Seq that
	  has no JSON representation and was never shown in the UI (#1067)
	- syse: the required Config.Credentials map[string]string was hidden from
	  the UI and the UI can only send it as a string

	The providers in this file are built by hand instead.
*/

// getSpecialDnsProvider builds the DNS providers listed above. handled is
// false if the provider is not one of them and the generic path should be used
func getSpecialDnsProvider(dnsProvider string, credentials map[string]any, propagationTimeout int, pollingInterval int) (provider challenge.Provider, handled bool, err error) {
	switch dnsProvider {
	case "plesk":
		provider, err := newPleskProvider(credentials, propagationTimeout, pollingInterval)
		return provider, true, err
	case "selfhostde":
		provider, err := newSelfhostdeProvider(credentials, propagationTimeout, pollingInterval)
		return provider, true, err
	case "syse":
		provider, err := newSyseProvider(credentials, propagationTimeout, pollingInterval)
		return provider, true, err
	}
	return nil, false, nil
}

// credentialString reads a string credential, accepting numbers as well
func credentialString(credentials map[string]any, key string) string {
	switch v := credentials[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// envOverrideMutex serializes providers that are configured through process
// environment variables, so concurrent requests never see each other's values
var envOverrideMutex sync.Mutex

// withEnvOverride sets the given environment variables, runs fn and restores
// the previous environment before returning
func withEnvOverride(vars map[string]string, fn func() error) error {
	envOverrideMutex.Lock()
	defer envOverrideMutex.Unlock()

	type previousValue struct {
		value  string
		exists bool
	}
	previous := map[string]previousValue{}
	defer func() {
		for key, prev := range previous {
			if prev.exists {
				os.Setenv(key, prev.value)
			} else {
				os.Unsetenv(key)
			}
		}
	}()

	for key, value := range vars {
		oldValue, exists := os.LookupEnv(key)
		previous[key] = previousValue{value: oldValue, exists: exists}
		if err := os.Setenv(key, value); err != nil {
			return err
		}
	}

	return fn()
}

// newPleskProvider creates the Plesk provider. lego only accepts the server
// base URL from the environment, so all settings are passed that way
func newPleskProvider(credentials map[string]any, propagationTimeout int, pollingInterval int) (challenge.Provider, error) {
	baseURL := credentialString(credentials, "baseURL")
	if baseURL == "" {
		//Accept the exported spelling as well
		baseURL = credentialString(credentials, "BaseURL")
	}
	if baseURL == "" {
		return nil, errors.New("plesk: missing server base URL (e.g. https://plesk.example.com:8443)")
	}

	vars := map[string]string{
		plesk.EnvServerBaseURL:      baseURL,
		plesk.EnvUsername:           credentialString(credentials, "Username"),
		plesk.EnvPassword:           credentialString(credentials, "Password"),
		plesk.EnvPropagationTimeout: strconv.Itoa(propagationTimeout),
		plesk.EnvPollingInterval:    strconv.Itoa(pollingInterval),
	}

	var provider *plesk.DNSProvider
	err := withEnvOverride(vars, func() error {
		var err error
		provider, err = plesk.NewDNSProvider()
		return err
	})
	if err != nil {
		return nil, err
	}
	return provider, nil
}

// newSelfhostdeProvider creates the selfhost.de provider with the record ID
// mapping entered in the UI
func newSelfhostdeProvider(credentials map[string]any, propagationTimeout int, pollingInterval int) (challenge.Provider, error) {
	mapping, err := parseSelfhostdeRecordsMapping(credentialString(credentials, "RecordsMapping"))
	if err != nil {
		return nil, fmt.Errorf("selfhostde: invalid RecordsMapping: %w", err)
	}

	//Unmarshal the remaining plain fields (Username, Password...) into the config
	plainFields := map[string]any{}
	for key, value := range credentials {
		if key != "RecordsMapping" {
			plainFields[key] = value
		}
	}
	js, err := json.Marshal(plainFields)
	if err != nil {
		return nil, err
	}

	cfg := selfhostde.NewDefaultConfig()
	if err := json.Unmarshal(js, cfg); err != nil {
		return nil, err
	}
	cfg.RecordsMapping = mapping
	cfg.PropagationTimeout = time.Duration(propagationTimeout) * time.Second
	cfg.PollingInterval = time.Duration(pollingInterval) * time.Second

	return selfhostde.NewDNSProviderConfig(cfg)
}

// newSyseProvider creates the syse provider from the "zone:password,..."
// credential list entered in the UI (same format as SYSE_CREDENTIALS)
func newSyseProvider(credentials map[string]any, propagationTimeout int, pollingInterval int) (challenge.Provider, error) {
	raw := credentialString(credentials, "Credentials")
	if raw == "" {
		return nil, errors.New("syse: missing credentials, expected zone:password[,zone:password] (see https://go-acme.github.io/lego/dns/syse/)")
	}
	pairs, err := env.ParsePairs(raw)
	if err != nil {
		return nil, fmt.Errorf("syse: invalid Credentials: %w", err)
	}

	cfg := syse.NewDefaultConfig()
	cfg.Credentials = pairs
	cfg.PropagationTimeout = time.Duration(propagationTimeout) * time.Second
	cfg.PollingInterval = time.Duration(pollingInterval) * time.Second

	return syse.NewDNSProviderConfig(cfg)
}

// parseSelfhostdeRecordsMapping parses the selfhost.de record mapping in the
// same format as lego's SELFHOSTDE_RECORDS_MAPPING, e.g.
// "example.com:123:456,other.example.com:789". Each domain takes one record ID,
// or two if a wildcard certificate is requested for it
func parseSelfhostdeRecordsMapping(raw string) (map[string]*selfhostde.Seq, error) {
	raw = strings.ReplaceAll(raw, " ", "")
	if raw == "" {
		return nil, errors.New("missing record mapping, expected domain:recordID[:recordID],... (see https://go-acme.github.io/lego/dns/selfhostde/)")
	}

	mapping := map[string]*selfhostde.Seq{}
	for _, line := range strings.Split(raw, ",") {
		if line == "" {
			continue
		}
		parts := strings.Split(line, ":")
		if len(parts) < 2 {
			return nil, fmt.Errorf("missing record ID for %q", line)
		}
		if len(parts) > 3 {
			return nil, fmt.Errorf("too many record IDs for one domain: %s", line)
		}
		domain, ids := parts[0], parts[1:]
		if domain == "" {
			return nil, fmt.Errorf("missing domain in %q", line)
		}
		for _, id := range ids {
			if id == "" {
				return nil, fmt.Errorf("empty record ID for %q", domain)
			}
		}
		mapping[domain] = selfhostde.NewSeq(ids...)
	}

	if len(mapping) == 0 {
		return nil, errors.New("missing record mapping")
	}
	return mapping, nil
}
