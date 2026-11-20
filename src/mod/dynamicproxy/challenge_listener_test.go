package dynamicproxy

import (
	"io"
	"net/http"
	"testing"
	"time"

	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/netutils"
)

// The temporary ACME challenge listener answers routing rules only, and the
// proxy takes port 80 over from it when it serves port 80 itself, here with a
// secondary listening port 80. The challenge is still answered afterwards
func TestChallengeListenerTakenOverBySecondaryPort80(t *testing.T) {
	if netutils.CheckIfPortOccupied(80) {
		t.Skip("port 80 must be free")
	}
	testLogger, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	router, err := NewDynamicProxy(RouterOption{Port: 443, Logger: testLogger})
	if err != nil {
		t.Fatal(err)
	}
	router.AddRoutingRules(&RoutingRule{
		ID:      "test-challenge",
		Enabled: true,
		MatchRule: func(r *http.Request) bool {
			return r.URL.Path == "/.well-known/acme-challenge/test-token"
		},
		RoutingHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("test-token.key"))
		},
	})

	get := func(path string) (int, string) {
		t.Helper()
		var lastErr error
		for i := 0; i < 20; i++ {
			res, err := http.Get("http://127.0.0.1:80" + path)
			if err == nil {
				defer res.Body.Close()
				body, _ := io.ReadAll(res.Body)
				return res.StatusCode, string(body)
			}
			lastErr = err
			time.Sleep(50 * time.Millisecond)
		}
		t.Fatalf("GET %s: %v", path, lastErr)
		return 0, ""
	}

	if err := router.StartChallengeListener(":80"); err != nil {
		t.Fatal(err)
	}
	if !router.ChallengeListenerRunning() {
		t.Fatal("challenge listener not reported as running")
	}
	if status, body := get("/.well-known/acme-challenge/test-token"); status != 200 || body != "test-token.key" {
		t.Fatalf("challenge not answered: %d %q", status, body)
	}
	if status, _ := get("/index.html"); status != 404 {
		t.Errorf("other request answered with %d, want 404", status)
	}

	//A host gets the secondary listening port 80 during the challenge
	router.ProxyEndpoints.Store("plain.example.com", &ProxyEndpoint{
		RootOrMatchingDomain: "plain.example.com",
		ListeningPorts:       []string{":80"},
	})
	router.Running = true
	router.UpdateSecondaryListeners()
	defer func() {
		router.ProxyEndpoints.Delete("plain.example.com")
		router.UpdateSecondaryListeners()
	}()

	if router.ChallengeListenerRunning() {
		t.Error("challenge listener still running after the proxy took port 80 over")
	}
	if status, body := get("/.well-known/acme-challenge/test-token"); status != 200 || body != "test-token.key" {
		t.Errorf("challenge not answered by the secondary listener: %d %q", status, body)
	}
	if router.StopChallengeListener() {
		t.Error("stopping a challenge listener that was taken over reported it as running")
	}
}
