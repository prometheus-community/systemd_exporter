package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

var (
	binaryName = "systemd_exporter"
	binaryPath = filepath.Join(binaryName)
	// os.Getenv("GOPATH"), "bin/node_exporter")
)

const (
	address = "localhost:9558"
)

func TestWhatTheHack(t *testing.T) {
	serverDone := &sync.WaitGroup{}
	serverDone.Add(1)
	// os.Args = []string{binaryName, "--version"}
	os.Args = []string{binaryName, "--web.listen-address=127.0.0.1:9558", "--log.level=debug"}
	srv := testMain(serverDone)

	// Running some fancy tests right here :-)
	time.Sleep(5 * time.Second)

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	if err := srv.Shutdown(ctx); err != nil {
		panic(err) // failure/timeout shutting down the server gracefully
	}

	serverDone.Wait()
}

func testFlagVersion(t *testing.T) {
	if _, err := os.Stat(binaryPath); err != nil {
		t.Skipf("binary not available, try to run `go build` first: %s", err)
	}
	exporter := exec.Command(binaryPath, "--version", address)
	if err := exporter.Run(); err != nil {
		t.Error(err)
	}
}

func testMetricsReturns200(t *testing.T) {
	if _, err := os.Stat(binaryPath); err != nil {
		t.Skipf("binary not available, try to run `go build` first: %s", err)
	}

	exporter := exec.Command(binaryPath, "--web.listen-address", address)
	test := func(_ int) error {
		resp, err := queryExporterMetrics()
		if err != nil {
			return err
		}
		if want, have := http.StatusOK, resp.StatusCode; want != have {
			return fmt.Errorf("wanted status code %d, received %d", want, have)
		}

		return nil
	}

	if err := runCommandAndTests(exporter, address, test); err != nil {
		t.Error(err)
	}
}

func queryExporterMetrics() (*http.Response, error) {
	return queryExporter(fmt.Sprintf("http://%s/metrics", address))
}

func queryExporter(url string) (*http.Response, error) {
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

func runCommandAndTests(cmd *exec.Cmd, address string, fn func(pid int) error) error {
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("failed to start command: %s", err)
	}

	// ensure server is online before running test
	time.Sleep(10 * time.Millisecond)
	for i := 0; i < 10; i++ {
		root := fmt.Sprintf("http://%s/", address)
		if resp, err := queryExporter(root); err == nil && resp.StatusCode == http.StatusOK {
			break
		}
		time.Sleep(500 * time.Millisecond)
		if cmd.Process == nil || i == 9 {
			return fmt.Errorf("can't connect to %s - unable to run any tests", root)
		}
	}

	errc := make(chan error)
	go func(pid int) {
		errc <- fn(pid)
	}(cmd.Process.Pid)

	err := <-errc
	if cmd.Process != nil {
		cmd.Process.Kill()
	}
	return err
}
