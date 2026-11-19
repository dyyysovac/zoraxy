package main

import (
	"io"
	"net/http"
	"testing"

	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/netutils"
)

// While an HTTP-01 challenge runs with the port 80 listener off, port 80
// answers the challenge and nothing else. The proxy itself is not touched, so
// a proxy the user stops in the meantime stays stopped
func TestAcmePrepareHTTP01ChallengeListener(t *testing.T) {
	if netutils.CheckIfPortOccupied(80) {
		t.Skip("port 80 must be free")
	}

	testLogger, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	router, err := dynamicproxy.NewDynamicProxy(dynamicproxy.RouterOption{
		Port:           443,
		ListenOnPort80: false,
		Logger:         testLogger,
	})
	if err != nil {
		t.Fatal(err)
	}
	router.Root = &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "/"}
	router.AddRoutingRules(&dynamicproxy.RoutingRule{
		ID:      "test-challenge",
		Enabled: true,
		MatchRule: func(r *http.Request) bool {
			return r.URL.Path == "/.well-known/acme-challenge/test-token"
		},
		RoutingHandler: func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("test-token.key"))
		},
	})

	previousRouter, previousLogger := dynamicProxyRouter, SystemWideLogger
	dynamicProxyRouter, SystemWideLogger = router, testLogger
	defer func() {
		dynamicProxyRouter, SystemWideLogger = previousRouter, previousLogger
	}()
	markReverseProxyStarted()

	//Only the running state matters to the challenge, the proxy listeners
	//themselves are not needed
	router.Running = true

	get := func(path string) (int, string, error) {
		res, err := http.Get("http://127.0.0.1:80" + path)
		if err != nil {
			return 0, "", err
		}
		defer res.Body.Close()
		body, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(body), nil
	}

	release := acmePrepareHTTP01Challenge()
	if status, body, err := get("/.well-known/acme-challenge/test-token"); err != nil || status != 200 || body != "test-token.key" {
		t.Fatalf("challenge not answered on port 80: status=%d body=%q err=%v", status, body, err)
	}
	if status, _, err := get("/index.html"); err != nil || status != 404 {
		t.Errorf("other request on the challenge listener: status=%d err=%v, want 404", status, err)
	}

	//The user stops the proxy while the challenge is running
	router.Running = false
	release()

	if router.Running {
		t.Error("the stopped proxy was started again when the challenge finished")
	}
	if router.Option.ListenOnPort80 {
		t.Error("port 80 listener setting of the proxy changed")
	}
	if _, _, err := get("/.well-known/acme-challenge/test-token"); err == nil {
		t.Error("port 80 still served after the challenge")
	}
}
