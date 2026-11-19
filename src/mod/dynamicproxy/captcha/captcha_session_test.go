package captcha

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// A session solved on one proxy rule must only be accepted on that rule, not
// on another rule that might use stricter CAPTCHA settings
func TestSessionStoreScopedToRule(t *testing.T) {
	store := NewSessionStore()
	defer store.Close()

	store.AddSession("session-a", "a.example.com", 3600)

	if !store.IsValidSession("session-a", "a.example.com") {
		t.Error("session is not valid on the rule it was solved on")
	}
	if store.IsValidSession("session-a", "b.example.com") {
		t.Error("session solved on a.example.com was accepted on b.example.com")
	}
	if store.IsValidSession("unknown-session", "a.example.com") {
		t.Error("unknown session was accepted")
	}
}

func TestSessionStoreExpiry(t *testing.T) {
	store := NewSessionStore()
	defer store.Close()

	store.AddSession("expired", "a.example.com", -60)
	if store.IsValidSession("expired", "a.example.com") {
		t.Error("expired session was accepted on the rule it was solved on")
	}

	store.AddSession("expires-now", "a.example.com", 0)
	if store.IsValidSession("expires-now", "a.example.com") {
		t.Error("session with a zero duration was accepted")
	}

	store.AddSession("active", "a.example.com", 60)
	if !store.IsValidSession("active", "a.example.com") {
		t.Error("unexpired session was rejected")
	}

	store.RemoveSession("active")
	if store.IsValidSession("active", "a.example.com") {
		t.Error("removed session was accepted")
	}
}

func TestCheckSessionScopedToRule(t *testing.T) {
	store := NewSessionStore()
	defer store.Close()

	store.AddSession("session-a", "a.example.com", 3600)

	r := httptest.NewRequest(http.MethodGet, "https://b.example.com/", nil)
	r.AddCookie(&http.Cookie{Name: CookieName, Value: "session-a"})
	if !CheckSession(r, store, "a.example.com") {
		t.Error("session cookie was rejected on the rule it was solved on")
	}
	if CheckSession(r, store, "b.example.com") {
		t.Error("session cookie solved on a.example.com was accepted on b.example.com")
	}

	r = httptest.NewRequest(http.MethodGet, "https://a.example.com/", nil)
	if CheckSession(r, store, "a.example.com") {
		t.Error("request without a session cookie was accepted")
	}
}
