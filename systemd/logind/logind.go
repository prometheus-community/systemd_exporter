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

package logind

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/coreos/go-systemd/v22/login1"
	"github.com/prometheus/client_golang/prometheus"
)

const (
	namespace = "systemd"
	subsystem = "logind"
)

var (
	logindSessions = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "sessions_current"),
		"Number of sessions Logind is currently tracking",
		nil, nil,
	)
	logindUsers = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "users_current"),
		"Number of users Logind is currently tracking",
		nil, nil,
	)
	logindScrapeSuccess = prometheus.NewDesc(
		prometheus.BuildFQName(namespace, subsystem, "scrape_success"),
		"Whether the metric retrieval succeeded",
		nil, nil,
	)
)

type Collector struct {
	ctx    context.Context
	logger *slog.Logger
}

// NewCollector returns a new Collector providing logind statistics
func NewCollector(logger *slog.Logger) (*Collector, error) {

	ctx := context.TODO()
	return &Collector{
		ctx:    ctx,
		logger: logger,
	}, nil
}

// Collect gathers metrics from logind
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	err := c.collect(ch)
	if err != nil {
		c.logger.Error("error collecting logind metrics",
			"err", err.Error())
		ch <- prometheus.MustNewConstMetric(logindScrapeSuccess, prometheus.GaugeValue, 0)
	} else {
		ch <- prometheus.MustNewConstMetric(logindScrapeSuccess, prometheus.GaugeValue, 1)
	}
}

// Describe gathers descriptions of metrics
func (c *Collector) Describe(desc chan<- *prometheus.Desc) {
	desc <- logindSessions
	desc <- logindUsers
	desc <- logindScrapeSuccess
}

func (c *Collector) collect(ch chan<- prometheus.Metric) error {
	conn, err := login1.New()
	if err != nil {
		return fmt.Errorf("couldn't get logind connection: %w", err)
	}
	defer conn.Close()

	sessions, err := conn.ListSessionsContext(c.ctx)
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(logindSessions, prometheus.GaugeValue,
		float64(len(sessions)))

	users, err := conn.ListUsersContext(c.ctx)
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(logindUsers, prometheus.GaugeValue,
		float64(len(users)))

	return nil
}
