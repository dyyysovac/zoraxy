package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
)

// newTestPort80Router builds a router with one proxy endpoint and an
// ACME-like special routing rule, without starting any listener
func newTestPort80Router(bypassGlobalTLS bool, forceHttpsRedirect bool) (*Router, *bool) {
	endpoints := &sync.Map{}
	endpoints.Store("plain.example.com", &ProxyEndpoint{
		RootOrMatchingDomain: "plain.example.com",
		BypassGlobalTLS:      bypassGlobalTLS,
	})

	routingRuleHit := false
	router := &Router{
		Option: &RouterOption{
			Port:               443,
			ForceHttpsRedirect: forceHttpsRedirect,
		},
		ProxyEndpoints: endpoints,
	}
	router.AddRoutingRules(&RoutingRule{
		ID:      "acme-autorenew",
		Enabled: true,
		MatchRule: func(r *http.Request) bool {
			return strings.HasPrefix(r.URL.Path, "/.well-known/acme-challenge/")
		},
		RoutingHandler: func(w http.ResponseWriter, r *http.Request) {
			routingRuleHit = true
			w.Write([]byte("key-authorization"))
		},
	})
	return router, &routingRuleHit
}

// newTestPort80Request builds a request as it arrives on the wire, where
// RequestURI only carries the path (httptest uses the full URL otherwise)
func newTestPort80Request(path string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	r.Host = "plain.example.com"
	return r
}

// Hosts with "Allow plain HTTP access" must still let the ACME HTTP-01
// responder answer the challenge on port 80 (#490, #1342)
func TestPort80Handler_RoutingRuleBeforeBypassGlobalTLS(t *testing.T) {
	router, hit := newTestPort80Router(true, true)

	w := httptest.NewRecorder()
	r := newTestPort80Request("/.well-known/acme-challenge/token123")
	router.port80Handler().ServeHTTP(w, r)

	if !*hit {
		t.Fatal("ACME routing rule was not consulted for a BypassGlobalTLS host on port 80")
	}
	if got := w.Body.String(); got != "key-authorization" {
		t.Errorf("unexpected response body %q", got)
	}
}

// The routing rule must also win over the HTTPS redirect, so the challenge is
// answered directly instead of relying on the CA following the redirect
func TestPort80Handler_RoutingRuleBeforeHttpsRedirect(t *testing.T) {
	router, hit := newTestPort80Router(false, true)

	w := httptest.NewRecorder()
	r := newTestPort80Request("/.well-known/acme-challenge/token123")
	router.port80Handler().ServeHTTP(w, r)

	if !*hit {
		t.Fatal("ACME routing rule was not consulted before the HTTPS redirect")
	}
	if w.Code == http.StatusTemporaryRedirect {
		t.Error("ACME challenge request was redirected instead of answered")
	}
}

// Requests that do not match a routing rule keep the previous behaviour
func TestPort80Handler_NonMatchingRequestStillRedirects(t *testing.T) {
	router, hit := newTestPort80Router(false, true)

	w := httptest.NewRecorder()
	r := newTestPort80Request("/index.html")
	router.port80Handler().ServeHTTP(w, r)

	if *hit {
		t.Fatal("routing rule must not match unrelated paths")
	}
	if w.Code != http.StatusTemporaryRedirect {
		t.Fatalf("expected redirect, got status %d", w.Code)
	}
	if loc := w.Header().Get("Location"); loc != "https://plain.example.com/index.html" {
		t.Errorf("unexpected redirect target %q", loc)
	}
}

// Secondary listening ports must consult the special routing rules too,
// otherwise the ACME challenge is proxied to the backend there (#1342)
func TestSecondaryPortHandler_RoutingRuleFirst(t *testing.T) {
	router, hit := newTestPort80Router(true, false)
	ep, _ := router.ProxyEndpoints.Load("plain.example.com")
	ep.(*ProxyEndpoint).ListeningPorts = []string{":8080"}

	w := httptest.NewRecorder()
	r := newTestPort80Request("/.well-known/acme-challenge/token123")
	router.secondaryPortHandler(":8080").ServeHTTP(w, r)

	if !*hit {
		t.Fatal("ACME routing rule was not consulted on a secondary listening port")
	}
}
