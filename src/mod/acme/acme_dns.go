package acme

import (
	"encoding/json"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/go-acme/lego/v5/challenge"
	"github.com/go-acme/lego/v5/platform/env"
	"github.com/go-acme/lego/v5/providers/dns/exoscale"
	"github.com/go-acme/lego/v5/providers/dns/jdcloud"
	"github.com/go-acme/lego/v5/providers/dns/lightsail"
	"github.com/go-acme/lego/v5/providers/dns/vkcloud"
	"imuslab.com/zoraxy/mod/acme/acmedns"
)

// Preprocessor function to get DNS challenge provider by name
func GetDnsChallengeProviderByName(dnsProvider string, dnsCredentials string, ppgTimeout int) (challenge.Provider, error) {
	// Unpack the dnsCredentials (json string) to map
	var dnsCredentialsMap map[string]any
	err := json.Unmarshal([]byte(dnsCredentials), &dnsCredentialsMap)
	if err != nil {
		return nil, err
	}

	// The UI sends every field, empty or not. An empty value must not replace
	// the lego default (e.g. cpanel Mode, pdns ServerName, infoblox WapiVersion)
	dropUnsetDnsCredentials(dnsCredentialsMap)

	// Credentials saved by older Zoraxy versions can use lego v4 names
	dnsProvider, err = migrateLegacyDnsCredentials(dnsProvider, dnsCredentialsMap)
	if err != nil {
		return nil, err
	}

	// Fill the defaults lego only sets when it reads its config from the
	// environment (e.g. vkcloud DNSEndpoint, lightsail Region)
	applyEnvOnlyDnsProviderDefaults(dnsProvider, dnsCredentialsMap)

	// Clear the PollingInterval and PropagationTimeout field and conert to int
	userDefinedPollingInterval := 2
	if dnsCredentialsMap["PollingInterval"] != nil {
		userDefinedPollingIntervalRaw := credentialString(dnsCredentialsMap, "PollingInterval")
		delete(dnsCredentialsMap, "PollingInterval")
		convertedPollingInterval, err := strconv.Atoi(userDefinedPollingIntervalRaw)
		if err == nil {
			userDefinedPollingInterval = convertedPollingInterval
		}
	}

	userDefinedPropagationTimeout := ppgTimeout
	if dnsCredentialsMap["PropagationTimeout"] != nil {
		userDefinedPropagationTimeoutRaw := credentialString(dnsCredentialsMap, "PropagationTimeout")
		delete(dnsCredentialsMap, "PropagationTimeout")
		convertedPropagationTimeout, err := strconv.Atoi(userDefinedPropagationTimeoutRaw)
		if err == nil {
			// Overwrite the default propagation timeout if it is requeted from UI
			userDefinedPropagationTimeout = convertedPropagationTimeout
		}
	}

	// Providers whose lego config cannot be filled from JSON (see acme_dns_special.go)
	provider, handled, err := getSpecialDnsProvider(dnsProvider, dnsCredentialsMap, userDefinedPropagationTimeout, userDefinedPollingInterval)
	if handled {
		return provider, err
	}

	providerConfigStructure, err := acmedns.GetProviderConfigStructure(dnsProvider)
	if err != nil {
		return nil, err
	}

	// Extract the *url.URL field (ex. powerdns Host) and delete it from the map,
	// json.Unmarshal cannot fill a *url.URL from a string
	hostURL, err := extractDnsProviderURL(dnsProvider, providerConfigStructure, dnsCredentialsMap)
	if err != nil {
		return nil, err
	}

	// Restructure dnsCredentials string from map
	dnsCredentialsBytes, err := json.Marshal(dnsCredentialsMap)
	if err != nil {
		return nil, err
	}
	dnsCredentials = string(dnsCredentialsBytes)

	// Using acmedns CICD pipeline generated datatype to optain the DNS provider
	return acmedns.GetDNSProviderByJsonConfig(
		dnsProvider,
		dnsCredentials,
		int64(userDefinedPropagationTimeout),
		int64(userDefinedPollingInterval),
		hostURL,
	)
}

// dropUnsetDnsCredentials removes the fields that were left empty, so
// json.Unmarshal keeps the value lego's NewDefaultConfig() put there
func dropUnsetDnsCredentials(credentials map[string]any) {
	for key, value := range credentials {
		switch v := value.(type) {
		case nil:
			delete(credentials, key)
		case string:
			if strings.TrimSpace(v) == "" {
				delete(credentials, key)
			}
		}
	}
}

// legacyDnsProviderNames maps provider names saved by Zoraxy builds that
// used lego v4 to the lego v5 name of the same provider
var legacyDnsProviderNames = map[string]string{
	"rfc2136":  "dnsupdate",
	"webnames": "webnamesru",
}

// removedDnsProviders lists the providers lego v5 removed, with the provider
// lego names as their replacement (empty if there is none)
var removedDnsProviders = map[string]string{
	"azure":         "azuredns",
	"brandit":       "",
	"cloudxns":      "",
	"dnspod":        "tencentcloud",
	"googledomains": "",
	"iij":           "iijdpf",
	"iwantmyname":   "",
}

// migrateLegacyDnsCredentials updates a provider name and credentials saved by
// an older Zoraxy version to the current ones
func migrateLegacyDnsCredentials(dnsProvider string, credentials map[string]any) (string, error) {
	if newName, ok := legacyDnsProviderNames[dnsProvider]; ok {
		dnsProvider = newName
	}

	if replacement, ok := removedDnsProviders[dnsProvider]; ok {
		if replacement != "" {
			return dnsProvider, fmt.Errorf("DNS provider %q was removed in lego v5, select %q and enter its credentials again", dnsProvider, replacement)
		}
		return dnsProvider, fmt.Errorf("DNS provider %q was removed in lego v5, select another DNS provider", dnsProvider)
	}

	switch dnsProvider {
	case "scaleway":
		// lego v5 renamed Config.Token to Config.SecretKey
		if token, ok := credentials["Token"]; ok {
			if _, hasSecretKey := credentials["SecretKey"]; !hasSecretKey {
				credentials["SecretKey"] = token
			}
			delete(credentials, "Token")
		}
	case "pdns":
		// Older forms pre-filled every number field with 10. PowerDNS only has
		// API v1 and lego detects the version itself when it is not set
		if version, ok := credentials["APIVersion"].(float64); ok && version == 10 {
			delete(credentials, "APIVersion")
		}
	}
	return dnsProvider, nil
}

// defaultDnsProviderEndpoints are the API endpoints of providers whose lego
// NewDefaultConfig() leaves the endpoint empty (lego only sets it in the
// env based NewDNSProvider()), used when the user leaves the field empty
var defaultDnsProviderEndpoints = map[string]string{
	"checkdomain": "https://api.checkdomain.de", // lego checkdomain internal.DefaultEndpoint
}

// envOnlyDnsProviderDefault is a default that lego reads from envVar in its
// NewDNSProvider(), falling back to value if the variable is not set
type envOnlyDnsProviderDefault struct {
	envVar string
	value  string
}

// envOnlyDnsProviderDefaults are the settings of providers whose lego
// NewDefaultConfig() leaves them empty (lego only sets them in the env based
// NewDNSProvider()), used when the user leaves the field empty. Without them
// the provider cannot be created or its API requests fail
var envOnlyDnsProviderDefaults = map[string]map[string]envOnlyDnsProviderDefault{
	"exoscale": {
		// lego exoscale NewDNSProvider(): string(egoscale.CHGva2). An empty
		// endpoint replaces the egoscale default with ""
		"Endpoint": {exoscale.EnvEndpoint, "https://api-ch-gva-2.exoscale.com/v2"},
	},
	"jdcloud": {
		// lego jdcloud NewDNSProvider(): "cn-north-1"
		"RegionID": {jdcloud.EnvRegionID, "cn-north-1"},
	},
	"lightsail": {
		// lego lightsail NewDNSProvider(): "us-east-1"
		"Region": {lightsail.EnvRegion, "us-east-1"},
	},
	"vkcloud": {
		// lego vkcloud defaultDNSEndpoint
		"DNSEndpoint": {vkcloud.EnvDNSEndpoint, "https://mcs.mail.ru/public-dns/v2/dns"},
		// lego vkcloud defaultIdentityEndpoint
		"IdentityEndpoint": {vkcloud.EnvIdentityEndpoint, "https://infra.mail.ru/identity/v3/"},
		// lego vkcloud defaultDomainName
		"DomainName": {vkcloud.EnvDomainName, "users"},
	},
}

// applyEnvOnlyDnsProviderDefaults adds the envOnlyDnsProviderDefaults of the
// provider that are missing from the credentials. Like lego, the environment
// variable is used if it is set
func applyEnvOnlyDnsProviderDefaults(dnsProvider string, credentials map[string]any) {
	for field, fieldDefault := range envOnlyDnsProviderDefaults[dnsProvider] {
		// json.Unmarshal matches keys case-insensitively
		isSet := false
		for key := range credentials {
			if strings.EqualFold(key, field) {
				isSet = true
				break
			}
		}
		if !isSet {
			credentials[field] = env.GetOrDefaultString(fieldDefault.envVar, fieldDefault.value)
		}
	}
}

// extractDnsProviderURL removes the *url.URL field of the provider from the
// credentials and returns it parsed. It returns nil if the field is not set
// and the provider has no default, so the lego config keeps its own value
func extractDnsProviderURL(dnsProvider string, configStructure map[string]string, credentials map[string]any) (*url.URL, error) {
	for configTitle, configDataType := range configStructure {
		if configDataType != "*url.URL" {
			continue
		}

		// json.Unmarshal matches keys case-insensitively, so every spelling of
		// the key has to be removed, not only the one in providers.json
		var rawValue any
		for key, value := range credentials {
			if !strings.EqualFold(key, configTitle) {
				continue
			}
			if rawValue == nil || key == configTitle {
				rawValue = value
			}
			delete(credentials, key)
		}

		if rawValue == nil {
			defaultEndpoint, ok := defaultDnsProviderEndpoints[dnsProvider]
			if !ok {
				return nil, nil
			}
			rawValue = defaultEndpoint
		}

		urlStr, ok := rawValue.(string)
		if !ok {
			return nil, fmt.Errorf("%s: %s must be a URL", dnsProvider, configTitle)
		}
		hostURL, err := url.Parse(strings.TrimSpace(urlStr))
		if err != nil {
			return nil, fmt.Errorf("%s: invalid %s: %w", dnsProvider, configTitle, err)
		}
		if hostURL.Scheme == "" || hostURL.Host == "" {
			return nil, fmt.Errorf("%s: %s must be a full URL including the scheme, e.g. https://example.com", dnsProvider, configTitle)
		}
		// Each provider has at most one *url.URL field
		return hostURL, nil
	}
	return nil, nil
}
