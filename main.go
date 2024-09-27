// Copyright 2022 The Prometheus Authors
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

package main

import (
	"net/http"
	_ "net/http/pprof"
	"os"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus-community/systemd_exporter/systemd"
	"github.com/prometheus-community/systemd_exporter/systemd/resolved"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	"github.com/prometheus/common/promslog/flag"
	commonVersion "github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
)

func main() {
	var (
		metricsPath = kingpin.Flag(
			"web.telemetry-path",
			"Path under which to expose metrics.",
		).Default("/metrics").String()
		disableExporterMetrics = kingpin.Flag(
			"web.disable-exporter-metrics",
			"Exclude metrics about the exporter itself (promhttp_*, process_*, go_*).",
		).Bool()
		maxRequests = kingpin.Flag(
			"web.max-requests",
			"Maximum number of parallel scrape requests. Use 0 to disable.",
		).Default("40").Int()
		enableResolvedgMetrics = kingpin.Flag("systemd.collector.enable-resolved", "Enable systemd-resolved statistics").Bool()

		toolkitFlags = webflag.AddFlags(kingpin.CommandLine, ":9558")
	)

	promslogConfig := &promslog.Config{}
	flag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.Version(commonVersion.Print("systemd_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promslog.New(promslogConfig)

	logger.Info("Starting systemd_exporter", "version", commonVersion.Info())
	logger.Info("Build context", "build_context", commonVersion.BuildContext())

	exporterMetricsRegistry := prometheus.NewRegistry()
	r := prometheus.NewRegistry()

	r.MustRegister(version.NewCollector("systemd_exporter"))

	collector, err := systemd.NewCollector(logger)
	if err != nil {
		logger.Error("Couldn't create collector", "err", err)
		os.Exit(1)
	}

	if err := r.Register(collector); err != nil {
		logger.Error("Couldn't register systemd collector", "err", err)
		os.Exit(1)
	}

	handler := promhttp.HandlerFor(
		prometheus.Gatherers{exporterMetricsRegistry, r},
		promhttp.HandlerOpts{
			ErrorHandling:       promhttp.ContinueOnError,
			MaxRequestsInFlight: *maxRequests,
		},
	)

	if !*disableExporterMetrics {
		handler = promhttp.InstrumentMetricHandler(
			exporterMetricsRegistry, handler,
		)
	}
	if *enableResolvedgMetrics {
		resolvedCollector, err := resolved.NewCollector(logger)
		if err != nil {
			logger.Error("Couldn't create resolved collector", "err", err)
			os.Exit(1)
		}

		if err := r.Register(resolvedCollector); err != nil {
			logger.Error("Couldn't register resolved collector", "err", err)
			os.Exit(1)
		}
	}

	http.Handle(*metricsPath, handler)
	if *metricsPath != "/" && *metricsPath != "" {
		landingConfig := web.LandingConfig{
			Name:        "systemd Exporter",
			Description: "Prometheus Exporter for systemd",
			Version:     commonVersion.Info(),
			Links: []web.LandingLinks{
				{
					Address: *metricsPath,
					Text:    "Metrics",
				},
			},
		}
		landingPage, err := web.NewLandingPage(landingConfig)
		if err != nil {
			logger.Error("Couldn't create landing page", "err", err.Error())
			os.Exit(1)
		}
		http.Handle("/", landingPage)
	}

	srv := &http.Server{}
	if err := web.ListenAndServe(srv, toolkitFlags, logger); err != nil {
		logger.Error("Error starting server", "err", err)
		os.Exit(1)
	}
}
