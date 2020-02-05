package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"testing"
	"time"
)

var (
	address     = "127.0.0.1:9550"
	binaryName  = "systemd_exporter"
	defaultArgs = []string{binaryName, fmt.Sprintf("--web.listen-address=%s", address)}
)

func TestMain(m *testing.M) {
	// TODO accept arg for listen address
	os.Exit(m.Run())
}

// TestNoop only exists as an example of how you can test
func TestNoop(t *testing.T) {
	noop := func() error { return nil }
	if err := runServerAndTest(defaultArgs, address, noop); err != nil {
		t.Errorf("No op failed")
	}
}

// TestVersionFlag is an example of running a test that does not rely on the server being
// online. TODO make a reusable runTest() for this use case
// TODO this is broken. Because runServerAndTest is waiting for the server to come online,
// but it never does (becaseu our args mean it prints version and exits), we do not exit
// cleanly. Somethign hangs, which means test coverage is never written out. Bummer
// func TestVersionFlag(t *testing.T) {
// 	noop := func() error { return nil }
// 	runServerAndTest(append(defaultArgs, "--version"), address, noop)
// }

func TestMetricEndpointReturnsHttp200(t *testing.T) {
	test := func() error {
		resp, err := getMetrics()
		if err != nil {
			return err
		}
		if want, have := http.StatusOK, resp.StatusCode; want != have {
			return fmt.Errorf("wanted status code %d, received %d", want, have)
		}
		return nil
	}
	if err := runServerAndTest(defaultArgs, address, test); err != nil {
		t.Errorf("Metric 200 failed")
	}
}

func runServerAndTest(args []string, url string, fn func() error) error {
	// Request server startup
	serverDone := &sync.WaitGroup{}
	serverDone.Add(1)
	// TODO it would be cleaner to change main.go to use kingpin.MustParse
	os.Args = args
	srv := testMain(serverDone)

	// ensure server is online before running test
	fmt.Println("Waiting on test server startup...")
	for i := 0; i < 10; i++ {
		root := fmt.Sprintf("http://%s/", address)
		if resp, err := getURL(root); err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(10 * time.Millisecond)
		if i == 9 {
			return fmt.Errorf("can't connect to %s - unable to run any tests", root)
		}
	}
	fmt.Println("Test server ready, running test...")

	// Run the test
	err := fn()

	// Shutdown the server before we return
	fmt.Println("Test complete, shutting down server...")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel() // TODO is this correct?

	if err := srv.Shutdown(ctx); err != nil {
		// TODO is this what we shold do with serverDone?
		defer serverDone.Wait()
		return fmt.Errorf("failed to start command: %s", err)
	}

	serverDone.Wait()
	fmt.Println("Test server shutdown, testcase complete.")

	return err
}

func getMetrics() (*http.Response, error) {
	return getURL(fmt.Sprintf("http://%s/metrics", address))
}

func getURL(url string) (*http.Response, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, err
	}
	// b, err := ioutil.ReadAll(resp.Body)
	// if err != nil {
	// 	return nil, err
	// }
	// if err := resp.Body.Close(); err != nil {
	// 	return nil, err
	// }
	// if want, have := http.StatusOK, resp.StatusCode; want != have {
	// 	return nil, fmt.Errorf("want /metrics status code %d, have %d. Body:\n%s", want, have, b)
	// }
	return resp, nil
}
