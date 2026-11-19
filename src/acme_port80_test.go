package main

import (
	"path/filepath"
	"testing"

	"imuslab.com/zoraxy/mod/database"
	"imuslab.com/zoraxy/mod/database/dbinc"
	"imuslab.com/zoraxy/mod/dynamicproxy"
	"imuslab.com/zoraxy/mod/info/logger"
	"imuslab.com/zoraxy/mod/netutils"
)

// A proxy the user stops while an HTTP-01 challenge is running must stay
// stopped when the temporary port 80 listener is turned off again
func TestAcmeReleaseHTTP01ChallengeKeepsStoppedProxyStopped(t *testing.T) {
	if netutils.CheckIfPortOccupied(443) || netutils.CheckIfPortOccupied(80) {
		t.Skip("ports 443 and 80 must be free")
	}

	testLogger, err := logger.NewFmtLogger()
	if err != nil {
		t.Fatal(err)
	}
	db, err := database.NewDatabase(filepath.Join(t.TempDir(), "sys.db"), dbinc.BackendBoltDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.NewTable("settings")
	db.Write("settings", "listenP80", false)

	router, err := dynamicproxy.NewDynamicProxy(dynamicproxy.RouterOption{
		Port:           443,
		ListenOnPort80: false,
		Logger:         testLogger,
	})
	if err != nil {
		t.Fatal(err)
	}
	router.Root = &dynamicproxy.ProxyEndpoint{RootOrMatchingDomain: "/"}

	previousRouter, previousDb, previousLogger := dynamicProxyRouter, sysdb, SystemWideLogger
	dynamicProxyRouter, sysdb, SystemWideLogger = router, db, testLogger
	defer func() {
		dynamicProxyRouter, sysdb, SystemWideLogger = previousRouter, previousDb, previousLogger
	}()
	markReverseProxyStarted()

	if err := router.StartProxyService(); err != nil {
		t.Skipf("unable to start the proxy on port 443: %v", err)
	}
	defer func() {
		if router.Running {
			router.StopProxyService()
		}
	}()

	release := acmePrepareHTTP01Challenge()
	if !router.Option.ListenOnPort80 {
		t.Fatal("port 80 listener not enabled for the challenge")
	}

	//The user stops the proxy while the challenge is running
	if err := router.StopProxyService(); err != nil {
		t.Fatal(err)
	}
	release()

	if router.Running {
		t.Error("the stopped proxy was started again when the challenge finished")
	}
	if router.Option.ListenOnPort80 {
		t.Error("port 80 listener setting not restored")
	}
}
