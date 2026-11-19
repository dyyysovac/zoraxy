package dynamicproxy

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/access"
	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/info/logger"
)

// newTestRateLimitRouter builds a minimal Router wired with a real access
// controller, so the rate limiter resolves client IPs the same way it does
// in production.
func newTestRateLimitRouter(t *testing.T, trustProxyHeaders bool, trustedProxies ...string) *Router {
	t.Helper()
	tmpDir := t.TempDir()

	sysdb, err := database.NewDatabase(filepath.Join(tmpDir, "sysdb"), database.GetRecommendedBackendType())
	if err != nil {
		t.Fatalf("unable to create test database: %v", err)
	}
	t.Cleanup(func() { sysdb.Close() })

	testLogger, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatalf("unable to create test logger: %v", err)
	}

	accessController, err := access.NewAccessController(&access.Options{
		Logger:             *testLogger,
		ConfigFolder:       filepath.Join(tmpDir, "access"),
		TrustedProxiesFile: filepath.Join(tmpDir, "trusted_proxies.json"),
		Database:           sysdb,
	})
	if err != nil {
		t.Fatalf("unable to create access controller: %v", err)
	}

	defaultRule, err := accessController.GetAccessRuleByID("default")
	if err != nil {
		t.Fatalf("unable to load default access rule: %v", err)
	}
	defaultRule.TrustProxyHeadersOnly = trustProxyHeaders
	for _, proxy := range trustedProxies {
		accessController.AddTrustedProxy(proxy, "test")
	}

	return &Router{
		Option:           &RouterOption{AccessController: accessController},
		rateLimitCounter: RequestCountPerIpTable{},
	}
}

func newTestRequest(remoteAddr string, headers map[string]string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "https://host.example.com/", nil)
	r.RemoteAddr = remoteAddr
	for k, v := range headers {
		r.Header.Set(k, v)
	}
	return r
}

// A header supplied client IP carries no port. The limiter must still count it
// instead of silently failing open. Regression test for the CDN bypass where
// net.SplitHostPort() on a bare address aborted the whole check.
func TestHandleRateLimit_BareHeaderIPStillCounts(t *testing.T) {
	for _, headerName := range []string{"CF-Connecting-IP", "Fastly-Client-IP", "X-Real-Ip", "X-Forwarded-For"} {
		t.Run(headerName, func(t *testing.T) {
			router := newTestRateLimitRouter(t, true, "104.16.0.0/13")
			pe := &ProxyEndpoint{RequireRateLimit: true, RateLimit: 3}

			blocked := 0
			for i := 0; i < 10; i++ {
				w := httptest.NewRecorder()
				r := newTestRequest("104.16.5.1:443", map[string]string{headerName: "203.0.113.99"})
				if err := router.handleRateLimit(w, r, pe); err != nil {
					blocked++
					if w.Code != 429 {
						t.Errorf("expected status 429 on block, got %d", w.Code)
					}
				}
			}

			if blocked == 0 {
				t.Fatalf("%s: rate limit never fired, limiter failed open", headerName)
			}
			if got := router.rateLimitCounter.GetCount(rateLimitCounterKey(pe, "203.0.113.99")); got != 10 {
				t.Errorf("%s: expected 10 requests counted against 203.0.113.99, got %d", headerName, got)
			}
		})
	}
}

// Every visitor behind the CDN must get their own counter rather than sharing
// the edge address, otherwise one busy client 429s everyone else.
func TestHandleRateLimit_CountsPerRealClient(t *testing.T) {
	router := newTestRateLimitRouter(t, true, "104.16.0.0/13")
	pe := &ProxyEndpoint{RequireRateLimit: true, RateLimit: 3}

	//A limit of 3 lets 3 requests through before the fourth is rejected
	for i := 0; i < 3; i++ {
		w := httptest.NewRecorder()
		r := newTestRequest("104.16.5.1:443", map[string]string{"CF-Connecting-IP": "203.0.113.1"})
		if err := router.handleRateLimit(w, r, pe); err != nil {
			t.Fatalf("first client blocked too early at request %d", i)
		}
	}
	w := httptest.NewRecorder()
	r := newTestRequest("104.16.5.1:443", map[string]string{"CF-Connecting-IP": "203.0.113.1"})
	if err := router.handleRateLimit(w, r, pe); err == nil {
		t.Fatal("first client was not blocked after using up its limit")
	}

	//A different client through the same edge node must not be affected
	w = httptest.NewRecorder()
	r = newTestRequest("104.16.5.1:443", map[string]string{"CF-Connecting-IP": "203.0.113.2"})
	if err := router.handleRateLimit(w, r, pe); err != nil {
		t.Fatalf("second client should not share the first client's counter")
	}
}

// A spoofed header from a peer that is not on the trusted proxy list must not
// let a client escape the limiter by rotating the header value.
func TestHandleRateLimit_SpoofedHeaderFromUntrustedPeerIgnored(t *testing.T) {
	router := newTestRateLimitRouter(t, true) //no trusted proxies configured
	pe := &ProxyEndpoint{RequireRateLimit: true, RateLimit: 3}

	blocked := 0
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		//Every request claims a different origin IP
		r := newTestRequest("198.51.100.7:51000", map[string]string{
			"CF-Connecting-IP": "203.0.113." + string(rune('0'+i)),
		})
		if err := router.handleRateLimit(w, r, pe); err != nil {
			blocked++
		}
	}

	if blocked == 0 {
		t.Fatal("spoofed CF-Connecting-IP allowed a client to bypass the rate limit")
	}
	if got := router.rateLimitCounter.GetCount(rateLimitCounterKey(pe, "198.51.100.7")); got != 10 {
		t.Errorf("expected all 10 requests counted against the real peer, got %d", got)
	}
}

// The pre-existing behaviour of counting the direct peer when no proxy header
// is involved must be unchanged.
func TestHandleRateLimit_DirectConnection(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RequireRateLimit: true, RateLimit: 3}

	blocked := 0
	for i := 0; i < 10; i++ {
		w := httptest.NewRecorder()
		r := newTestRequest("198.51.100.20:44321", nil)
		if err := router.handleRateLimit(w, r, pe); err != nil {
			blocked++
		}
	}

	if blocked != 7 {
		t.Errorf("expected 7 of 10 requests blocked at limit 3, got %d", blocked)
	}
}

// A limit of N must allow exactly N requests per second, not N-1. With the
// old off by one, a limit of 1 blocked every request with 429
func TestHandleRateLimit_AllowsExactlyLimitRequests(t *testing.T) {
	for _, limit := range []int64{1, 2, 5} {
		router := newTestRateLimitRouter(t, false)
		pe := &ProxyEndpoint{RequireRateLimit: true, RateLimit: limit}

		for i := int64(0); i < limit; i++ {
			w := httptest.NewRecorder()
			r := newTestRequest("198.51.100.21:44321", nil)
			if err := router.handleRateLimit(w, r, pe); err != nil {
				t.Fatalf("limit %d: request %d blocked, expected %d requests to pass", limit, i+1, limit)
			}
		}

		w := httptest.NewRecorder()
		r := newTestRequest("198.51.100.21:44321", nil)
		if err := router.handleRateLimit(w, r, pe); err == nil {
			t.Fatalf("limit %d: request %d was not blocked", limit, limit+1)
		}
		if w.Code != 429 {
			t.Errorf("limit %d: expected status 429 on block, got %d", limit, w.Code)
		}

		//The next one second window starts from zero again
		router.rateLimitCounter.Clear()
		w = httptest.NewRecorder()
		r = newTestRequest("198.51.100.21:44321", nil)
		if err := router.handleRateLimit(w, r, pe); err != nil {
			t.Fatalf("limit %d: request blocked after the counter was reset", limit)
		}
	}
}

// A rule with rate limiting enabled but no usable limit (e.g. RateLimit 0 in a
// hand edited config file) must not block all traffic to that rule
func TestHandleRateLimit_ZeroLimitNeverBlocks(t *testing.T) {
	for _, limit := range []int64{0, -1} {
		router := newTestRateLimitRouter(t, false)
		pe := &ProxyEndpoint{RequireRateLimit: true, RateLimit: limit}

		for i := 0; i < 20; i++ {
			w := httptest.NewRecorder()
			r := newTestRequest("198.51.100.22:44321", nil)
			if err := router.handleRateLimit(w, r, pe); err != nil {
				t.Fatalf("limit %d: request %d blocked, expected no limit", limit, i+1)
			}
			if w.Code == 429 {
				t.Fatalf("limit %d: request %d got status 429", limit, i+1)
			}
		}
	}
}

// Each proxy rule must enforce its own limit. Requests to one rule must not
// count against the limit of another rule (#1107)
func TestHandleRateLimit_CountsPerProxyRule(t *testing.T) {
	router := newTestRateLimitRouter(t, false)
	busySite := &ProxyEndpoint{RootOrMatchingDomain: "busy.example.com", RequireRateLimit: true, RateLimit: 100}
	quietSite := &ProxyEndpoint{RootOrMatchingDomain: "quiet.example.com", RequireRateLimit: true, RateLimit: 3}

	//Heavy but allowed traffic to the first site
	for i := 0; i < 50; i++ {
		w := httptest.NewRecorder()
		r := newTestRequest("198.51.100.30:40000", nil)
		if err := router.handleRateLimit(w, r, busySite); err != nil {
			t.Fatalf("busy site blocked at request %d below its limit", i)
		}
	}

	//The same client must still be able to use the second site
	w := httptest.NewRecorder()
	r := newTestRequest("198.51.100.30:40000", nil)
	if err := router.handleRateLimit(w, r, quietSite); err != nil {
		t.Fatal("traffic to another proxy rule counted against this rule's rate limit")
	}

	//And the second site still enforces its own, lower limit
	blocked := 0
	for i := 0; i < 5; i++ {
		w := httptest.NewRecorder()
		r := newTestRequest("198.51.100.30:40000", nil)
		if err := router.handleRateLimit(w, r, quietSite); err != nil {
			blocked++
		}
	}
	if blocked == 0 {
		t.Fatal("quiet site did not enforce its own rate limit")
	}
}

// Requests arriving at the same time must not see each other's increments:
// with N+1 concurrent requests exactly one is blocked
func TestHandleRateLimit_ConcurrentRequests(t *testing.T) {
	const limit = 5
	router := newTestRateLimitRouter(t, false)
	pe := &ProxyEndpoint{RootOrMatchingDomain: "concurrent.example.com", RequireRateLimit: true, RateLimit: limit}
	for run := 0; run < 2000; run++ {
		router.rateLimitCounter.Clear()
		start := make(chan struct{})
		results := make(chan error, limit+1)
		for i := 0; i < limit+1; i++ {
			go func() {
				<-start
				results <- router.handleRateLimit(httptest.NewRecorder(), newTestRequest("203.0.113.7:1234", nil), pe)
			}()
		}
		close(start)
		blocked := 0
		for i := 0; i < limit+1; i++ {
			if <-results != nil {
				blocked++
			}
		}
		if blocked != 1 {
			t.Fatalf("run %d: %d of %d concurrent requests blocked at limit %d, want 1", run, blocked, limit+1, limit)
		}
	}
}
