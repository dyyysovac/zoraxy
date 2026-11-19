package dynamicproxy

import (
	"context"
	"net"
	"net/http"
	"time"
)

/*
	challenge_listener.go

	A temporary port 80 listener for ACME HTTP-01 challenges while the port 80
	listener of the proxy is turned off. It only answers requests matched by a
	routing rule (e.g. the ACME challenge rule) and does not touch the proxy
	itself, so the proxy is never restarted, and never started when the user
	stopped it, to serve a challenge
*/

// StartChallengeListener listens on addr (e.g. ":80") and answers requests
// that match a routing rule, every other request gets 404. Call the returned
// function to stop the listener
func (router *Router) StartChallengeListener(addr string) (stop func(), err error) {
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, err
	}

	server := &http.Server{
		Handler:           router.challengeOnlyHandler(),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go server.Serve(listener)

	return func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := server.Shutdown(ctx); err != nil {
			server.Close()
		}
	}, nil
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
