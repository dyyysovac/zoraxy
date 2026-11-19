package main

import (
	"sync"
	"time"

	"imuslab.com/zoraxy/mod/netutils"
)

/*
	acme_port80.go

	The CA validates HTTP-01 challenges on port 80. When Zoraxy listens on
	port 443 with the port 80 listener turned off, the listener is enabled for
	the time of the challenge. This used to be done only for certificates
	requested in the UI, so renewals by the auto renewer (at startup, on its
	timer and with Renew Now) could never be validated.
*/

var (
	// Closed once ReverseProxyInit has started (or tried to start) the proxy
	reverseProxyStarted     = make(chan struct{})
	reverseProxyStartedOnce sync.Once

	acmePort80Lock sync.Mutex
	// Number of HTTP-01 challenges in progress
	acmePort80Users int
	// The port 80 listener was turned on for the challenges in progress
	acmePort80TemporarilyEnabled bool
)

// markReverseProxyStarted signals that the reverse proxy start up is done
func markReverseProxyStarted() {
	reverseProxyStartedOnce.Do(func() {
		close(reverseProxyStarted)
	})
}

// acmePrepareHTTP01Challenge is called by the ACME handler before every HTTP-01
// challenge. It makes sure port 80 is served and returns the function that
// restores the previous port 80 listener state
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
		dynamicProxyRouter.Option.Port == 443 && !dynamicProxyRouter.Option.ListenOnPort80 {
		if netutils.CheckIfPortOccupied(80) {
			SystemWideLogger.PrintAndLog("ACME", "Port 80 is used by another program, it has to forward the HTTP-01 challenge to Zoraxy", nil)
		} else {
			SystemWideLogger.PrintAndLog("ACME", "Temporarily enabling port 80 listener to handle ACME request", nil)
			dynamicProxyRouter.UpdatePort80ListenerState(true)
			acmePort80TemporarilyEnabled = true
			time.Sleep(2 * time.Second)
		}
	}

	var releaseOnce sync.Once
	return func() {
		releaseOnce.Do(acmeReleaseHTTP01Challenge)
	}
}

// acmeReleaseHTTP01Challenge turns the port 80 listener off again once the
// last HTTP-01 challenge is done, if it was turned on for the challenges
func acmeReleaseHTTP01Challenge() {
	acmePort80Lock.Lock()
	defer acmePort80Lock.Unlock()
	acmePort80Users--
	if acmePort80Users > 0 || !acmePort80TemporarilyEnabled {
		return
	}
	acmePort80TemporarilyEnabled = false

	// Keep the listener if the user turned it on in the meantime
	listenOnPort80 := true
	sysdb.Read("settings", "listenP80", &listenOnPort80)
	if listenOnPort80 {
		return
	}
	SystemWideLogger.PrintAndLog("ACME", "Restoring previous port 80 listener settings", nil)
	dynamicProxyRouter.UpdatePort80ListenerState(false)
}
