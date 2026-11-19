package main

import (
	"net/http/httptest"
	"testing"

	"imuslab.com/zoraxy/mod/acme"
)

// Challenge requests Zoraxy is not presenting itself (e.g. of a backend with
// its own ACME client) must be routed to the backend (#1342). The positive
// case is covered by TestHTTP01TokenTracker in mod/acme
func TestAcmeIsOwnHTTP01Challenge(t *testing.T) {
	previous := acmeHandler
	defer func() { acmeHandler = previous }()

	for _, handler := range []*acme.ACMEHandler{nil, acme.NewACME("0", nil, nil, true, 0o600, 0o644)} {
		acmeHandler = handler
		for _, path := range []string{"/.well-known/acme-challenge/backend-token", "/index.html"} {
			if acmeIsOwnHTTP01Challenge(httptest.NewRequest("GET", path, nil)) {
				t.Errorf("handler %v: %s intercepted", handler != nil, path)
			}
		}
	}
}
