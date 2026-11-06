// Copyright 2023 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package resolved

import (
	"log/slog"
	"os"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

func noopLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// TestNewCollectorDBus verifies that NewCollector with the "dbus" backend
// constructs a valid Collector.
func TestNewCollectorDBus(t *testing.T) {
	c, err := NewCollector(noopLogger(), "dbus")
	if err != nil {
		t.Fatalf("NewCollector(\"dbus\") returned unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("NewCollector(\"dbus\") returned nil collector")
	}
	if c.backend != "dbus" {
		t.Fatalf("expected backend \"dbus\", got %q", c.backend)
	}
}

// TestNewCollectorCLI verifies that NewCollector with the "cli" backend
// constructs a valid Collector.
func TestNewCollectorCLI(t *testing.T) {
	c, err := NewCollector(noopLogger(), "cli")
	if err != nil {
		t.Fatalf("NewCollector(\"cli\") returned unexpected error: %v", err)
	}
	if c == nil {
		t.Fatal("NewCollector(\"cli\") returned nil collector")
	}
	if c.backend != "cli" {
		t.Fatalf("expected backend \"cli\", got %q", c.backend)
	}
}

// TestNewCollectorUnknownBackend verifies that an unknown backend returns an error.
func TestNewCollectorUnknownBackend(t *testing.T) {
	_, err := NewCollector(noopLogger(), "grpc")
	if err == nil {
		t.Fatal("NewCollector(\"grpc\") expected error, got nil")
	}
}

// TestParseCLIStats exercises the JSON parsing of the resolvectl statistics
// output format without running the actual binary.
func TestParseCLIStats(t *testing.T) {
	input := []byte(`{
		"transactions": {
			"currentTransactions": 2,
			"totalTransactions": 364,
			"totalTimeouts": 7,
			"totalTimeoutsServedStale": 3,
			"totalFailedResponses": 5,
			"totalFailedResponsesServedStale": 1
		},
		"cache": {
			"size": 127,
			"hits": 1821,
			"misses": 364
		},
		"dnssec": {
			"secure": 10,
			"insecure": 20,
			"bogus": 1,
			"indeterminate": 2
		}
	}`)

	s, err := parseCLIStats(input)
	if err != nil {
		t.Fatalf("parseCLIStats returned error: %v", err)
	}

	if s.Transactions.CurrentTransactions != 2 {
		t.Errorf("CurrentTransactions: want 2, got %d", s.Transactions.CurrentTransactions)
	}
	if s.Transactions.TotalTransactions != 364 {
		t.Errorf("TotalTransactions: want 364, got %d", s.Transactions.TotalTransactions)
	}
	if s.Transactions.TotalTimeouts != 7 {
		t.Errorf("TotalTimeouts: want 7, got %d", s.Transactions.TotalTimeouts)
	}
	if s.Transactions.TotalTimeoutsServedStale != 3 {
		t.Errorf("TotalTimeoutsServedStale: want 3, got %d", s.Transactions.TotalTimeoutsServedStale)
	}
	if s.Transactions.TotalFailedResponses != 5 {
		t.Errorf("TotalFailedResponses: want 5, got %d", s.Transactions.TotalFailedResponses)
	}
	if s.Transactions.TotalFailedResponsesServedStale != 1 {
		t.Errorf("TotalFailedResponsesServedStale: want 1, got %d", s.Transactions.TotalFailedResponsesServedStale)
	}
	if s.Cache.Size != 127 {
		t.Errorf("Cache.Size: want 127, got %d", s.Cache.Size)
	}
	if s.Cache.Hits != 1821 {
		t.Errorf("Cache.Hits: want 1821, got %d", s.Cache.Hits)
	}
	if s.Cache.Misses != 364 {
		t.Errorf("Cache.Misses: want 364, got %d", s.Cache.Misses)
	}
	if s.DNSSEC.Secure != 10 {
		t.Errorf("DNSSEC.Secure: want 10, got %d", s.DNSSEC.Secure)
	}
	if s.DNSSEC.Bogus != 1 {
		t.Errorf("DNSSEC.Bogus: want 1, got %d", s.DNSSEC.Bogus)
	}
	if s.DNSSEC.Indeterminate != 2 {
		t.Errorf("DNSSEC.Indeterminate: want 2, got %d", s.DNSSEC.Indeterminate)
	}
}

// TestDescribeDBusBackend checks that Describe sends exactly 9 descriptors
// for the D-Bus backend.
func TestDescribeDBusBackend(t *testing.T) {
	c, err := NewCollector(noopLogger(), "dbus")
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	ch := make(chan *prometheus.Desc, 20)
	c.Describe(ch)
	close(ch)

	var count int
	for range ch {
		count++
	}
	const wantDbus = 9
	if count != wantDbus {
		t.Errorf("Describe(dbus): want %d descriptors, got %d", wantDbus, count)
	}
}

// TestDescribeCLIBackend checks that Describe sends exactly 13 descriptors
// for the CLI backend (9 base + 4 CLI-only).
func TestDescribeCLIBackend(t *testing.T) {
	c, err := NewCollector(noopLogger(), "cli")
	if err != nil {
		t.Fatalf("NewCollector: %v", err)
	}
	ch := make(chan *prometheus.Desc, 20)
	c.Describe(ch)
	close(ch)

	var count int
	for range ch {
		count++
	}
	const wantCLI = 13
	if count != wantCLI {
		t.Errorf("Describe(cli): want %d descriptors, got %d", wantCLI, count)
	}
}
