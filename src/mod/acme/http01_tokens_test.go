package acme

import (
	"context"
	"errors"
	"testing"
)

type fakeHTTP01Provider struct {
	presentErr error
}

func (f *fakeHTTP01Provider) Present(ctx context.Context, domain, token, keyAuth string) error {
	return f.presentErr
}

func (f *fakeHTTP01Provider) CleanUp(ctx context.Context, domain, token, keyAuth string) error {
	return nil
}

// Only the tokens Zoraxy presents may be answered by Zoraxy, so challenges of
// backends with their own ACME client are not hijacked (#1342)
func TestHTTP01TokenTracker(t *testing.T) {
	handler := &ACMEHandler{}
	tracker := &http01TokenTracker{Provider: &fakeHTTP01Provider{}, handler: handler}
	ctx := context.Background()

	if handler.IsPresentingHTTP01Token("own-token") {
		t.Fatal("token reported before it was presented")
	}
	if err := tracker.Present(ctx, "example.com", "own-token", "key"); err != nil {
		t.Fatal(err)
	}
	if !handler.IsPresentingHTTP01Token("own-token") {
		t.Error("presented token not reported")
	}
	if handler.IsPresentingHTTP01Token("backend-token") {
		t.Error("token of another ACME client reported while Zoraxy presents its own")
	}
	if err := tracker.CleanUp(ctx, "example.com", "own-token", "key"); err != nil {
		t.Fatal(err)
	}
	if handler.IsPresentingHTTP01Token("own-token") {
		t.Error("token still reported after clean up")
	}

	//A token whose presentation failed is not kept
	failing := &http01TokenTracker{Provider: &fakeHTTP01Provider{presentErr: errors.New("port in use")}, handler: handler}
	if err := failing.Present(ctx, "example.com", "failed-token", "key"); err == nil {
		t.Fatal("expected the error of the wrapped provider")
	}
	if handler.IsPresentingHTTP01Token("failed-token") {
		t.Error("token kept after a failed Present")
	}
}
