package main

import (
	"sync"
	"time"
)

/*
	acme_port80.go

	The CA validates HTTP-01 challenges on port 80. When Zoraxy listens on
	port 443 with the port 80 listener turned off, a temporary listener that
	only answers the challenges is opened for the time of the challenge. This
	used to be done only for certificates requested in the UI, so renewals by
	the auto renewer (at startup, on its timer and with Renew Now) could never
	be validated.
*/

var (
	// Closed once ReverseProxyInit has started (or tried to start) the proxy
	reverseProxyStarted     = make(chan struct{})
	reverseProxyStartedOnce sync.Once

	acmePort80Lock sync.Mutex
	// Number of HTTP-01 challenges in progress
	acmePort80Users int
	// The temporary challenge listener was started for the challenges in progress
	acmeChallengeListenerStarted bool
)

// markReverseProxyStarted signals that the reverse proxy start up is done
func markReverseProxyStarted() {
	reverseProxyStartedOnce.Do(func() {
		close(reverseProxyStarted)
	})
}

// acmePrepareHTTP01Challenge is called by the ACME handler before every HTTP-01
// challenge. It makes sure port 80 is served and returns the function to call
// once the challenge is done
func acmePrepareHTTP01Challenge() (release func()) {
	// The renew check on startup runs before the proxy listeners are started
	select {
	case <-reverseProxyStarted:
	case <-time.After(2 * time.Minute):
		SystemWideLogger.PrintAndLog("ACME", "Reverse proxy not started yet, the HTTP-01 challenge might not be reachable", nil)
	}

	acmePort80Lock.Lock()
	defer acmePort80Lock.Unlock()
	acmePort80Users++
	if acmePort80Users == 1 && dynamicProxyRouter != nil && dynamicProxyRouter.Running &&
		dynamicProxyRouter.Option.Port == 443 && !dynamicProxyRouter.GetPort80ListenerState() {
		if err := dynamicProxyRouter.StartChallengeListener(":80"); err != nil {
			SystemWideLogger.PrintAndLog("ACME", "Unable to listen on port 80 for the HTTP-01 challenge, another program using port 80 has to forward it to Zoraxy", err)
		} else {
			SystemWideLogger.PrintAndLog("ACME", "Temporarily listening on port 80 to answer the HTTP-01 challenge", nil)
			acmeChallengeListenerStarted = true
		}
	}

	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(acmeReleaseHTTP01Challenge)
	}
}

// acmeReleaseHTTP01Challenge stops the temporary challenge listener once the
// last HTTP-01 challenge is done
func acmeReleaseHTTP01Challenge() {
	acmePort80Lock.Lock()
	defer acmePort80Lock.Unlock()
	acmePort80Users--
	if acmePort80Users > 0 || !acmeChallengeListenerStarted {
		return
	}
	acmeChallengeListenerStarted = false
	// The proxy may have taken port 80 over in the meantime (see
	// challenge_listener.go), then there is nothing to stop
	if dynamicProxyRouter.StopChallengeListener() {
		SystemWideLogger.PrintAndLog("ACME", "Temporary port 80 challenge listener stopped", nil)
	}
}
