package main

import (
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/dynamicproxy/loadbalance"
	"imuslab.com/zoraxy/mod/uptime"
)

/*
	Tests for buildUptimeTargets, the pure helper behind
	GetUptimeTargetsFromReverseProxyRules.

	Virtual directories must be probed with their own TLS settings
	(RequireTLS / SkipCertValidations), not with the parent host's
	upstream settings, and must appear exactly once each even when
	the parent host has multiple upstreams.
*/

func indexTargetsByID(t *testing.T, targets []*uptime.Target) map[string]*uptime.Target {
	t.Helper()
	m := map[string]*uptime.Target{}
	for _, target := range targets {
		if _, exists := m[target.ID]; exists {
			t.Fatalf("duplicate uptime target ID %q", target.ID)
		}
		m[target.ID] = target
	}
	return m
}

func TestBuildUptimeTargets_VdirUsesOwnTLSSettingsAndAppearsOnce(t *testing.T) {
	hosts := map[string]*dynamicproxy.ProxyEndpoint{
		"example.com": {
			UptimeMonitorURI: "/healthz",
			ActiveOrigins: []*loadbalance.Upstream{
				{
					OriginIpOrDomain:    "10.0.0.1:80",
					RequireTLS:          false,
					SkipCertValidations: false,
				},
				{
					OriginIpOrDomain:    "10.0.0.2:80",
					RequireTLS:          false,
					SkipCertValidations: false,
				},
			},
			VirtualDirectories: []*dynamicproxy.VirtualDirectoryEndpoint{
				{
					MatchingPath:        "/api",
					Domain:              "10.0.0.3:8443",
					RequireTLS:          true,
					SkipCertValidations: true,
				},
				{
					MatchingPath: "/disabled",
					Domain:       "10.0.0.4:80",
					Disabled:     true,
				},
			},
		},
	}

	targets := buildUptimeTargets(hosts)
	if len(targets) != 3 {
		t.Fatalf("expected 3 targets (2 upstreams + 1 enabled vdir), got %d: %+v", len(targets), targets)
	}
	byID := indexTargetsByID(t, targets)

	//Upstream targets keep their own (plain HTTP) settings
	for _, tc := range []struct {
		id  string
		url string
	}{
		{"example.com (upstream:0)", "http://10.0.0.1:80"},
		{"example.com (upstream:1)", "http://10.0.0.2:80"},
	} {
		got, ok := byID[tc.id]
		if !ok {
			t.Fatalf("missing upstream target %q", tc.id)
		}
		if got.URL != tc.url || got.Protocol != "http" || got.SkipTlsValidation {
			t.Errorf("upstream %q: got URL=%q Protocol=%q SkipTlsValidation=%v, want URL=%q Protocol=http SkipTlsValidation=false",
				tc.id, got.URL, got.Protocol, got.SkipTlsValidation, tc.url)
		}
		if got.ProxyType != uptime.ProxyType_Host {
			t.Errorf("upstream %q: got ProxyType=%v, want ProxyType_Host", tc.id, got.ProxyType)
		}
		if got.HealthCheckURI != "/healthz" {
			t.Errorf("upstream %q: got HealthCheckURI=%q, want /healthz", tc.id, got.HealthCheckURI)
		}
	}

	//Vdir target uses the vdir's own TLS settings
	vdir, ok := byID["example.com/api"]
	if !ok {
		t.Fatalf("missing vdir target %q", "example.com/api")
	}
	if vdir.URL != "https://10.0.0.3:8443" {
		t.Errorf("vdir URL: got %q, want %q", vdir.URL, "https://10.0.0.3:8443")
	}
	if vdir.Protocol != "https" {
		t.Errorf("vdir Protocol: got %q, want https", vdir.Protocol)
	}
	if !vdir.SkipTlsValidation {
		t.Errorf("vdir SkipTlsValidation: got false, want true")
	}
	if vdir.ProxyType != uptime.ProxyType_Vdir {
		t.Errorf("vdir ProxyType: got %v, want ProxyType_Vdir", vdir.ProxyType)
	}

	//Disabled vdir is skipped
	if _, ok := byID["example.com/disabled"]; ok {
		t.Errorf("disabled vdir should not produce an uptime target")
	}
}

func TestBuildUptimeTargets_VdirPlainHTTPUnderTLSHost(t *testing.T) {
	//The reverse case: parent upstream is HTTPS with skip-verify, vdir is plain HTTP.
	hosts := map[string]*dynamicproxy.ProxyEndpoint{
		"secure.example.com": {
			ActiveOrigins: []*loadbalance.Upstream{
				{
					OriginIpOrDomain:    "10.0.1.1:443",
					RequireTLS:          true,
					SkipCertValidations: true,
				},
			},
			VirtualDirectories: []*dynamicproxy.VirtualDirectoryEndpoint{
				{
					MatchingPath: "/legacy",
					Domain:       "10.0.1.2:80",
				},
			},
		},
	}

	byID := indexTargetsByID(t, buildUptimeTargets(hosts))
	if len(byID) != 2 {
		t.Fatalf("expected 2 targets, got %d", len(byID))
	}

	host, ok := byID["secure.example.com"]
	if !ok {
		t.Fatalf("missing host target")
	}
	if host.URL != "https://10.0.1.1:443" || host.Protocol != "https" || !host.SkipTlsValidation {
		t.Errorf("host target: got URL=%q Protocol=%q SkipTlsValidation=%v", host.URL, host.Protocol, host.SkipTlsValidation)
	}

	vdir, ok := byID["secure.example.com/legacy"]
	if !ok {
		t.Fatalf("missing vdir target")
	}
	if vdir.URL != "http://10.0.1.2:80" || vdir.Protocol != "http" || vdir.SkipTlsValidation {
		t.Errorf("vdir target: got URL=%q Protocol=%q SkipTlsValidation=%v, want http://10.0.1.2:80, http, false",
			vdir.URL, vdir.Protocol, vdir.SkipTlsValidation)
	}
}

func TestBuildUptimeTargets_SkipsDisabledHosts(t *testing.T) {
	hosts := map[string]*dynamicproxy.ProxyEndpoint{
		"disabled.example.com": {
			Disabled: true,
			ActiveOrigins: []*loadbalance.Upstream{
				{OriginIpOrDomain: "10.0.2.1:80"},
			},
			VirtualDirectories: []*dynamicproxy.VirtualDirectoryEndpoint{
				{MatchingPath: "/a", Domain: "10.0.2.2:80"},
			},
		},
		"nomonitor.example.com": {
			DisableUptimeMonitor: true,
			ActiveOrigins: []*loadbalance.Upstream{
				{OriginIpOrDomain: "10.0.3.1:80"},
			},
		},
	}

	if targets := buildUptimeTargets(hosts); len(targets) != 0 {
		t.Fatalf("expected no targets for disabled hosts, got %d: %+v", len(targets), targets)
	}
}
