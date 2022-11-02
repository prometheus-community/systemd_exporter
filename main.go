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
	"sync"

	"github.com/go-kit/log/level"
	"github.com/prometheus-community/systemd_exporter/systemd"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promlog"
	"github.com/prometheus/common/promlog/flag"
	"github.com/prometheus/common/version"
	// "github.com/prometheus/exporter-toolkit/web"
	// webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"gopkg.in/alecthomas/kingpin.v2"
)

func main() {
	listenAddress := mainCore()

	tempPromlogConfig := &promlog.Config{}
	tempLogger := promlog.New(tempPromlogConfig)

	level.Info(tempLogger).Log("msg", "Listening on", "addr", listenAddress)
	if err := http.ListenAndServe(listenAddress, nil); err != nil {
		level.Error(tempLogger).Log("err", err)
	}

}

func testMain(wg *sync.WaitGroup) *http.Server {
	listenAddress := mainCore()

	tempPromlogConfig := &promlog.Config{}
	tempLogger := promlog.New(tempPromlogConfig)

	// Launch server in background
	srv := &http.Server{Addr: listenAddress}
	level.Info(tempLogger).Log("msg", "Queuing test server startup")
	go func() {
		defer wg.Done()

		// ErrServerClosed indicates graceful close
		level.Info(tempLogger).Log("msg", "Test server listening on", "addr", listenAddress)
		if err := srv.ListenAndServe(); err != http.ErrServerClosed {
			// unexpected error. port in use?
			level.Error(tempLogger).Log("msg", "ListenAndServe()", "addr", err)
		}

		// Reset http package
		http.DefaultServeMux = http.NewServeMux()
		level.Info(tempLogger).Log("msg", "Test server shutdown")
	}()

	return srv
}

func mainCore() string {
	var (
		listenAddress = kingpin.Flag(
			"web.listen-address",
			"Address on which to expose metrics and web interface.",
		).Default(":9558").String()
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
		//toolkitFlags = webflag.AddFlags(kingpin.CommandLine, ":9558")
	)

	promlogConfig := &promlog.Config{}
	flag.AddFlags(kingpin.CommandLine, promlogConfig)
	kingpin.Version(version.Print("systemd_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()
	logger := promlog.New(promlogConfig)

	level.Debug(logger).Log("msg", "Parsed", "args", os.Args)
	level.Info(logger).Log("msg", "Starting systemd_exporter", "version", version.Info())
	level.Info(logger).Log("msg", "Build context", "build_context", version.BuildContext())

	exporterMetricsRegistry := prometheus.NewRegistry()
	r := prometheus.NewRegistry()

	r.MustRegister(version.NewCollector("systemd_exporter"))

	collector, err := systemd.NewCollector(logger)
	if err != nil {
		level.Error(logger).Log("msg", "Couldn't create collector", "err", err)
		os.Exit(1)
	}

	if err := r.Register(collector); err != nil {
		level.Error(logger).Log("msg", "Couldn't register systemd collector", "err", err)
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

	http.Handle(*metricsPath, handler)
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, err := w.Write([]byte(`<html>
			<head><title>Systemd Exporter</title></head>
			<body>
			<h1>Systemd Exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
		if err != nil {
			level.Error(logger).Log("msg", "Couldn't write response", "err", err)
		}
	})

	return *listenAddress
}
