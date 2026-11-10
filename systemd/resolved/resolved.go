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
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os/exec"
	"time"

	"github.com/godbus/dbus/v5"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "systemd"
	subsystem = "resolved"
)

// Collector collects systemd-resolved statistics.
// It supports two backends:
//   - "dbus" (default): reads statistics via the D-Bus API. All 9 base metrics
//     are available but timeout/failed-response counts are structurally absent
//     from the D-Bus TransactionStatistics property (a 2-element array).
//   - "cli": runs `resolvectl statistics --json=short` and parses the JSON
//     output. All 9 base metrics plus 4 new timeout/failure metrics are
//     available.
type Collector struct {
	backend string
	logger  *slog.Logger
}

var (
	// Base metrics (both backends)
	resolvedCurrentTransactions = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "current_transactions"),
		"Resolved Current Transactions",
		nil, nil,
	)
	resolvedTotalTransactions = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "transactions_total"),
		"Resolved Total Transactions",
		nil, nil,
	)
	resolvedCurrentCacheSize = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "current_cache_size"),
		"Resolved Current Cache Size",
		nil, nil,
	)
	resolvedTotalCacheHits = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "cache_hits_total"),
		"Resolved Total Cache Hits",
		nil, nil,
	)
	resolvedTotalCacheMisses = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "cache_misses_total"),
		"Resolved Total Cache Misses",
		nil, nil,
	)
	resolvedTotalSecure = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "dnssec_secure_total"),
		"Resolved Total number of DNSSEC Verdicts Secure",
		nil, nil,
	)
	resolvedTotalInsecure = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "dnssec_insecure_total"),
		"Resolved Total number of DNSSEC Verdicts Insecure",
		nil, nil,
	)
	resolvedTotalBogus = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "dnssec_bogus_total"),
		"Resolved Total number of DNSSEC Verdicts Bogus",
		nil, nil,
	)
	resolvedTotalIndeterminate = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "dnssec_indeterminate_total"),
		"Resolved Total number of DNSSEC Verdicts Indeterminate",
		nil, nil,
	)

	// CLI-only metrics — not available via the D-Bus API because
	// TransactionStatistics is a 2-element array [current, total] and has no
	// slots for timeout or failure counts.
	resolvedTransactionTimeouts = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "transaction_timeouts_total"),
		"Resolved Total number of DNS transactions that timed out",
		nil, nil,
	)
	resolvedFailedResponses = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "failed_responses_total"),
		"Resolved Total number of failed DNS responses",
		nil, nil,
	)
	resolvedTransactionTimeoutsServedStale = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "transaction_timeouts_served_stale_total"),
		"Resolved Total number of timed-out DNS transactions that were served from stale cache",
		nil, nil,
	)
	resolvedFailedResponsesServedStale = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "failed_responses_served_stale_total"),
		"Resolved Total number of failed DNS responses that were served from stale cache",
		nil, nil,
	)
)

// cliStats mirrors the JSON structure emitted by `resolvectl statistics --json=short`.
type cliStats struct {
	Transactions struct {
		CurrentTransactions            uint64 `json:"currentTransactions"`
		TotalTransactions              uint64 `json:"totalTransactions"`
		TotalTimeouts                  uint64 `json:"totalTimeouts"`
		TotalTimeoutsServedStale       uint64 `json:"totalTimeoutsServedStale"`
		TotalFailedResponses           uint64 `json:"totalFailedResponses"`
		TotalFailedResponsesServedStale uint64 `json:"totalFailedResponsesServedStale"`
	} `json:"transactions"`
	Cache struct {
		Size   uint64 `json:"size"`
		Hits   uint64 `json:"hits"`
		Misses uint64 `json:"misses"`
	} `json:"cache"`
	DNSSEC struct {
		Secure        uint64 `json:"secure"`
		Insecure      uint64 `json:"insecure"`
		Bogus         uint64 `json:"bogus"`
		Indeterminate uint64 `json:"indeterminate"`
	} `json:"dnssec"`
}

// NewCollector returns a new Collector exporting resolved statistics.
// The backend parameter selects the data source:
//   - "dbus" (default): D-Bus API. Backward-compatible; does not expose
//     timeout/failed-response metrics because they are absent from the D-Bus
//     TransactionStatistics property.
//   - "cli": `resolvectl statistics --json=short`. Exposes all 9 base metrics
//     plus 4 new timeout/failure metrics. Requires resolvectl in $PATH.
func NewCollector(logger *slog.Logger, backend string) (*Collector, error) {
	switch backend {
	case "dbus", "cli":
		// valid
	default:
		return nil, fmt.Errorf("resolved: unknown backend %q, must be \"dbus\" or \"cli\"", backend)
	}
	return &Collector{
		backend: backend,
		logger:  logger,
	}, nil
}

// Collect gathers metrics from resolved.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	var err error
	if c.backend == "cli" {
		err = c.collectCLI(ch)
	} else {
		err = c.collectDBus(ch)
	}
	if err != nil {
		c.logger.Error("error collecting resolved metrics",
			"backend", c.backend,
			"err", err.Error())
	}
}

// Describe sends all metric descriptors to desc.
func (c *Collector) Describe(desc chan<- *prometheus.Desc) {
	desc <- resolvedCurrentTransactions
	desc <- resolvedTotalTransactions
	desc <- resolvedCurrentCacheSize
	desc <- resolvedTotalCacheHits
	desc <- resolvedTotalCacheMisses
	desc <- resolvedTotalSecure
	desc <- resolvedTotalInsecure
	desc <- resolvedTotalBogus
	desc <- resolvedTotalIndeterminate
	if c.backend == "cli" {
		desc <- resolvedTransactionTimeouts
		desc <- resolvedFailedResponses
		desc <- resolvedTransactionTimeoutsServedStale
		desc <- resolvedFailedResponsesServedStale
	}
}

// parseProperty reads a []uint64 D-Bus variant from obj at path.
func parseProperty(object dbus.BusObject, path string) ([]float64, error) {
	variant, err := object.GetProperty(path)
	if err != nil {
		return nil, err
	}
	var ret []float64
	for _, v := range variant.Value().([]any) {
		i := v.(uint64)
		ret = append(ret, float64(i))
	}
	return ret, nil
}

// collectDBus collects the 9 base metrics via the D-Bus API.
func (c *Collector) collectDBus(ch chan<- prometheus.Metric) error {
	conn, err := dbus.ConnectSystemBus()
	if err != nil {
		return err
	}
	defer conn.Close()

	obj := conn.Object("org.freedesktop.resolve1", "/org/freedesktop/resolve1")

	cacheStats, err := parseProperty(obj, "org.freedesktop.resolve1.Manager.CacheStatistics")
	if err != nil {
		return err
	}
	ch <- prometheus.MustNewConstMetric(resolvedCurrentCacheSize, prometheus.GaugeValue,
		cacheStats[0])
	ch <- prometheus.MustNewConstMetric(resolvedTotalCacheHits, prometheus.CounterValue,
		cacheStats[1])
	ch <- prometheus.MustNewConstMetric(resolvedTotalCacheMisses, prometheus.CounterValue,
		cacheStats[2])

	transactionStats, err := parseProperty(obj, "org.freedesktop.resolve1.Manager.TransactionStatistics")
	if err != nil {
		return err
	}
	ch <- prometheus.MustNewConstMetric(resolvedCurrentTransactions, prometheus.GaugeValue,
		transactionStats[0])
	ch <- prometheus.MustNewConstMetric(resolvedTotalTransactions, prometheus.CounterValue,
		transactionStats[1])

	dnssecStats, err := parseProperty(obj, "org.freedesktop.resolve1.Manager.DNSSECStatistics")
	if err != nil {
		return err
	}
	ch <- prometheus.MustNewConstMetric(resolvedTotalSecure, prometheus.CounterValue,
		dnssecStats[0])
	ch <- prometheus.MustNewConstMetric(resolvedTotalInsecure, prometheus.CounterValue,
		dnssecStats[1])
	ch <- prometheus.MustNewConstMetric(resolvedTotalBogus, prometheus.CounterValue,
		dnssecStats[2])
	ch <- prometheus.MustNewConstMetric(resolvedTotalIndeterminate, prometheus.CounterValue,
		dnssecStats[3])
	return nil
}

// fetchCLIStats runs `resolvectl statistics --json=short` and parses the output.
// Exported so it can be tested directly with injected JSON.
func parseCLIStats(data []byte) (*cliStats, error) {
	var s cliStats
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("resolved: failed to parse resolvectl statistics JSON: %w", err)
	}
	return &s, nil
}

// collectCLI collects all 13 metrics via `resolvectl statistics --json=short`.
func (c *Collector) collectCLI(ch chan<- prometheus.Metric) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, "resolvectl", "statistics", "--json=short")
	var out bytes.Buffer
	cmd.Stdout = &out
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("resolved: resolvectl statistics failed: %w", err)
	}

	s, err := parseCLIStats(out.Bytes())
	if err != nil {
		return err
	}

	// Base metrics
	ch <- prometheus.MustNewConstMetric(resolvedCurrentTransactions, prometheus.GaugeValue,
		float64(s.Transactions.CurrentTransactions))
	ch <- prometheus.MustNewConstMetric(resolvedTotalTransactions, prometheus.CounterValue,
		float64(s.Transactions.TotalTransactions))
	ch <- prometheus.MustNewConstMetric(resolvedCurrentCacheSize, prometheus.GaugeValue,
		float64(s.Cache.Size))
	ch <- prometheus.MustNewConstMetric(resolvedTotalCacheHits, prometheus.CounterValue,
		float64(s.Cache.Hits))
	ch <- prometheus.MustNewConstMetric(resolvedTotalCacheMisses, prometheus.CounterValue,
		float64(s.Cache.Misses))
	ch <- prometheus.MustNewConstMetric(resolvedTotalSecure, prometheus.CounterValue,
		float64(s.DNSSEC.Secure))
	ch <- prometheus.MustNewConstMetric(resolvedTotalInsecure, prometheus.CounterValue,
		float64(s.DNSSEC.Insecure))
	ch <- prometheus.MustNewConstMetric(resolvedTotalBogus, prometheus.CounterValue,
		float64(s.DNSSEC.Bogus))
	ch <- prometheus.MustNewConstMetric(resolvedTotalIndeterminate, prometheus.CounterValue,
		float64(s.DNSSEC.Indeterminate))

	// CLI-only metrics
	ch <- prometheus.MustNewConstMetric(resolvedTransactionTimeouts, prometheus.CounterValue,
		float64(s.Transactions.TotalTimeouts))
	ch <- prometheus.MustNewConstMetric(resolvedFailedResponses, prometheus.CounterValue,
		float64(s.Transactions.TotalFailedResponses))
	ch <- prometheus.MustNewConstMetric(resolvedTransactionTimeoutsServedStale, prometheus.CounterValue,
		float64(s.Transactions.TotalTimeoutsServedStale))
	ch <- prometheus.MustNewConstMetric(resolvedFailedResponsesServedStale, prometheus.CounterValue,
		float64(s.Transactions.TotalFailedResponsesServedStale))
	return nil
}
