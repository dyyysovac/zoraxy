package dynamicproxy

import (
	"context"
	"net"
	"net/http"
	"time"
)

/*
	challenge_listener.go

	A temporary port 80 listener for ACME HTTP-01 challenges while the proxy
	does not serve port 80 itself. It only answers requests matched by a
	routing rule (e.g. the ACME challenge rule) and does not touch the proxy,
	so the proxy is never restarted, and never started when the user stopped
	it, to serve a challenge. When the proxy starts serving port 80 itself
	(port 80 listener turned on, inbound port 80, a secondary listening port
	80), it takes the port over from this listener.
*/

// StartChallengeListener listens on addr (e.g. ":80") and answers requests
// that match a routing rule, every other request gets 404. It does nothing if
// the challenge listener is already running
func (router *Router) StartChallengeListener(addr string) error {
	router.challengeListenerLock.Lock()
	defer router.challengeListenerLock.Unlock()
	if router.challengeListenerStop != nil {
		return nil
	}

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}

	server := &http.Server{
		Handler:           router.challengeOnlyHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go server.Serve(listener)

	router.challengeListenerStop = func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			server.Close()
		}
	}
	return nil
}

// StopChallengeListener stops the challenge listener and returns true if it
// was running. The port is free when it returns
func (router *Router) StopChallengeListener() bool {
	router.challengeListenerLock.Lock()
	defer router.challengeListenerLock.Unlock()
	if router.challengeListenerStop == nil {
		return false
	}
	router.challengeListenerStop()
	router.challengeListenerStop = nil
	return true
}

// ChallengeListenerRunning returns true while the challenge listener runs
func (router *Router) ChallengeListenerRunning() bool {
	router.challengeListenerLock.Lock()
	defer router.challengeListenerLock.Unlock()
	return router.challengeListenerStop != nil
}

// challengeOnlyHandler answers requests matched by a routing rule only
func (router *Router) challengeOnlyHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if matchedRoutingRule := router.GetMatchingRoutingRule(r); matchedRoutingRule != nil {
			matchedRoutingRule.Route(w, r)
			return
		}
		http.NotFound(w, r)
	})
}
