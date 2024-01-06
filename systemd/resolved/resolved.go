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
	"context"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/godbus/dbus/v5"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "systemd_resolved"

type Collector struct {
	ctx                         context.Context
	logger                      log.Logger
	resolvedCurrentTransactions *prometheus.Desc
	resolvedTotalTransactions   *prometheus.Desc
	resolvedCurrentCacheSize    *prometheus.Desc
	resolvedTotalCacheHits      *prometheus.Desc
	resolvedTotalCacheMisses    *prometheus.Desc
	resolvedTotalSecure         *prometheus.Desc
	resolvedTotalInsecure       *prometheus.Desc
	resolvedTotalBogus          *prometheus.Desc
	resolvedTotalIndeterminate  *prometheus.Desc
}

// NewCollector returns a new Collector exporing networkd statistics
func NewCollector(logger log.Logger) (*Collector, error) {

	// resolved metrics
	resolvedCurrentTransactions := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "current_transactions"),
		"Resolved Current Transactions",
		nil, nil,
	)
	resolvedTotalTransactions := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "transactions_total"),
		"Resolved Total Transactions",
		nil, nil,
	)
	resolvedCurrentCacheSize := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "current_cache_size"),
		"Resolved Current Cache Size",
		nil, nil,
	)
	resolvedTotalCacheHits := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cache_hits_total"),
		"Resolved Total Cache Hits",
		nil, nil,
	)
	resolvedTotalCacheMisses := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "cache_misses_total"),
		"Resolved Total Cache Misses",
		nil, nil,
	)
	resolvedTotalSecure := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dnssec_secure_total"),
		"Resolved Total number of DNSSEC Verdicts Secure",
		nil, nil,
	)
	resolvedTotalInsecure := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dnssec_insecure_total"),
		"Resolved Total number of DNSSEC Verdicts Insecure",
		nil, nil,
	)
	resolvedTotalBogus := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dnssec_bogus_total"),
		"Resolved Total number of DNSSEC Verdicts Boguss",
		nil, nil,
	)
	resolvedTotalIndeterminate := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "dnssec_indeterminate_total"),
		"Resolved Total number of DNSSEC Verdicts Indeterminat",
		nil, nil,
	)

	ctx := context.TODO()
	return &Collector{
		ctx:                         ctx,
		logger:                      logger,
		resolvedCurrentTransactions: resolvedCurrentTransactions,
		resolvedTotalTransactions:   resolvedTotalTransactions,
		resolvedCurrentCacheSize:    resolvedCurrentCacheSize,
		resolvedTotalCacheHits:      resolvedTotalCacheHits,
		resolvedTotalCacheMisses:    resolvedTotalCacheMisses,
		resolvedTotalSecure:         resolvedTotalSecure,
		resolvedTotalInsecure:       resolvedTotalInsecure,
		resolvedTotalBogus:          resolvedTotalBogus,
		resolvedTotalIndeterminate:  resolvedTotalIndeterminate,
	}, nil
}

// Collect gathers metrics from networkd
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	err := c.collect(ch)
	if err != nil {
		level.Error(c.logger).Log("msg", "error collecting metrics",
			"err", err)
	}
}

// Describe gathers descriptions of metrics
func (c *Collector) Describe(desc chan<- *prometheus.Desc) {
	desc <- c.resolvedCurrentTransactions
	desc <- c.resolvedTotalTransactions
	desc <- c.resolvedCurrentCacheSize
	desc <- c.resolvedTotalCacheHits
	desc <- c.resolvedTotalCacheMisses
	desc <- c.resolvedTotalSecure
	desc <- c.resolvedTotalInsecure
	desc <- c.resolvedTotalBogus
	desc <- c.resolvedTotalIndeterminate
}

func parseProperty(object dbus.BusObject, path string) (ret []float64, err error) {
	variant, err := object.GetProperty(path)
	if err != nil {
		return nil, err
	}
	for _, v := range variant.Value().([]interface{}) {
		i := v.(uint64)
		ret = append(ret, float64(i))
	}
	return ret, err
}

func (c *Collector) collect(ch chan<- prometheus.Metric) error {

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

	ch <- prometheus.MustNewConstMetric(c.resolvedCurrentCacheSize, prometheus.GaugeValue,
		float64(cacheStats[0]))
	ch <- prometheus.MustNewConstMetric(c.resolvedTotalCacheHits, prometheus.CounterValue,
		float64(cacheStats[1]))
	ch <- prometheus.MustNewConstMetric(c.resolvedTotalCacheMisses, prometheus.CounterValue,
		float64(cacheStats[2]))

	transactionStats, err := parseProperty(obj, "org.freedesktop.resolve1.Manager.TransactionStatistics")
	ch <- prometheus.MustNewConstMetric(c.resolvedCurrentTransactions, prometheus.GaugeValue,
		float64(transactionStats[0]))
	ch <- prometheus.MustNewConstMetric(c.resolvedTotalTransactions, prometheus.CounterValue,
		float64(transactionStats[1]))
	if err != nil {
		return err
	}

	dnssecStats, err := parseProperty(obj, "org.freedesktop.resolve1.Manager.DNSSECStatistics")
	ch <- prometheus.MustNewConstMetric(c.resolvedTotalSecure, prometheus.CounterValue,
		float64(dnssecStats[0]))
	ch <- prometheus.MustNewConstMetric(c.resolvedTotalInsecure, prometheus.CounterValue,
		float64(dnssecStats[1]))
	ch <- prometheus.MustNewConstMetric(c.resolvedTotalBogus, prometheus.CounterValue,
		float64(dnssecStats[2]))
	ch <- prometheus.MustNewConstMetric(c.resolvedTotalIndeterminate, prometheus.CounterValue,
		float64(dnssecStats[3]))
	if err != nil {
		return err
	}
	return nil
}
