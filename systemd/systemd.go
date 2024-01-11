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

package systemd

import (
	"context"
	"fmt"
	"math"
	"strconv"

	// Register pprof-over-http handlers
	_ "net/http/pprof"
	"regexp"
	"strings"
	"sync"
	"time"

	kingpin "github.com/alecthomas/kingpin/v2"
	"github.com/coreos/go-systemd/v22/dbus"
	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
)

const namespace = "systemd"

var (
	unitInclude               = kingpin.Flag("systemd.collector.unit-include", "Regexp of systemd units to include. Units must both match include and not match exclude to be included.").Default(".+").String()
	unitExclude               = kingpin.Flag("systemd.collector.unit-exclude", "Regexp of systemd units to exclude. Units must both match include and not match exclude to be included.").Default(".+\\.(device)").String()
	systemdPrivate            = kingpin.Flag("systemd.collector.private", "Establish a private, direct connection to systemd without dbus.").Bool()
	systemdUser               = kingpin.Flag("systemd.collector.user", "Connect to the user systemd instance.").Bool()
	enableRestartsMetrics     = kingpin.Flag("systemd.collector.enable-restart-count", "Enables service restart count metrics. This feature only works with systemd 235 and above.").Bool()
	enableIPAccountingMetrics = kingpin.Flag("systemd.collector.enable-ip-accounting", "Enables service ip accounting metrics. This feature only works with systemd 235 and above.").Bool()
	bootTimeRE                = regexp.MustCompile(`\d+`)
)

var unitStatesName = []string{"active", "activating", "deactivating", "inactive", "failed"}

var (
	errGetPropertyMsg           = "couldn't get unit's %s property"
	errConvertUint64PropertyMsg = "couldn't convert unit's %s property %v to uint64"
	errConvertUint32PropertyMsg = "couldn't convert unit's %s property %v to uint32"
	errConvertStringPropertyMsg = "couldn't convert unit's %s property %v to string"
	errUnitMetricsMsg           = "couldn't get unit's metrics: %s"
	infoUnitNoHandler           = "no unit type handler for %s"
)

type Collector struct {
	ctx                           context.Context
	logger                        log.Logger
	systemdBootMonotonic          *prometheus.Desc
	systemdBootTime               *prometheus.Desc
	unitCPUTotal                  *prometheus.Desc
	unitState                     *prometheus.Desc
	unitInfo                      *prometheus.Desc
	unitStartTimeDesc             *prometheus.Desc
	unitTasksCurrentDesc          *prometheus.Desc
	unitTasksMaxDesc              *prometheus.Desc
	unitActiveEnterTimeDesc       *prometheus.Desc
	unitActiveExitTimeDesc        *prometheus.Desc
	unitInactiveEnterTimeDesc     *prometheus.Desc
	unitInactiveExitTimeDesc      *prometheus.Desc
	nRestartsDesc                 *prometheus.Desc
	timerLastTriggerDesc          *prometheus.Desc
	socketAcceptedConnectionsDesc *prometheus.Desc
	socketCurrentConnectionsDesc  *prometheus.Desc
	socketRefusedConnectionsDesc  *prometheus.Desc
	ipIngressBytes                *prometheus.Desc
	ipEgressBytes                 *prometheus.Desc
	ipIngressPackets              *prometheus.Desc
	ipEgressPackets               *prometheus.Desc
	scrapeDurationDesc            *prometheus.Desc
	scrapeSuccessDesc             *prometheus.Desc

	unitIncludePattern *regexp.Regexp
	unitExcludePattern *regexp.Regexp
}

// NewCollector returns a new Collector exposing systemd statistics.
func NewCollector(logger log.Logger) (*Collector, error) {
	systemdBootMonotonic := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "boot_monotonic_seconds"),
		"Systemd boot stage monotonic timestamps", []string{"stage"}, nil,
	)
	systemdBootTime := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "boot_time_seconds"),
		"Systemd boot stage timestamps", []string{"stage"}, nil,
	)
	// Type is labeled twice e.g. name="foo.service" and type="service" to maintain compatibility
	// with users before we started exporting type label
	unitState := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_state"),
		"Systemd unit", []string{"name", "type", "state"}, nil,
	)
	// TODO think about if we want to have 1) one unit_info metric which has all possible labels
	// for all possible unit type variables (at least, the relatively static ones that we care
	// about such as type, generated-vs-real-unit, etc). Cons: a) huge waste since all these labels
	// have to be set to foo="" on non-relevant types. b) accidental overloading (e.g. we have type
	// label, but it means something different for a service vs a mount. Right now it's impossible to
	// detangle that.
	// Option 1) is we have service_info, mount_info, target_info, etc. Many more metrics, but far fewer
	// wasted labels and little chance of semantic confusion. Our current codebase is not tuned for this,
	// we would be adding likt 30% more lines of just boilerplate to declare these different metrics
	// w.r.t. cardinality and performance, option 2 is slightly better performance due to smaller scrape payloads
	// but otherwise (1) and (2) seem similar
	unitInfo := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_info"),
		"Mostly-static metadata for all unit types",
		[]string{"name", "type", "mount_type", "service_type"}, nil,
	)
	unitStartTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_start_time_seconds"),
		"Start time of the unit since unix epoch in seconds.",
		[]string{"name", "type"}, nil,
	)
	unitTasksCurrentDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_tasks_current"),
		"Current number of tasks per Systemd unit",
		[]string{"name"}, nil,
	)
	unitTasksMaxDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_tasks_max"),
		"Maximum number of tasks per Systemd unit",
		[]string{"name", "type"}, nil,
	)
	unitActiveEnterTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_active_enter_time_seconds"),
		"Last time the unit transitioned into the active state",
		[]string{"name", "type"}, nil,
	)
	unitActiveExitTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_active_exit_time_seconds"),
		"Last time the unit transitioned out of the active state",
		[]string{"name", "type"}, nil,
	)
	unitInactiveEnterTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_inactive_enter_time_seconds"),
		"Last time the unit transitioned into the inactive state",
		[]string{"name", "type"}, nil,
	)
	unitInactiveExitTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_inactive_exit_time_seconds"),
		"Last time the unit transitioned out of the inactive state",
		[]string{"name", "type"}, nil,
	)
	nRestartsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "service_restart_total"),
		"Service unit count of Restart triggers", []string{"name"}, nil)
	timerLastTriggerDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "timer_last_trigger_seconds"),
		"Seconds since epoch of last trigger.", []string{"name"}, nil)
	socketAcceptedConnectionsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "socket_accepted_connections_total"),
		"Total number of accepted socket connections", []string{"name"}, nil)
	socketCurrentConnectionsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "socket_current_connections"),
		"Current number of socket connections", []string{"name"}, nil)
	socketRefusedConnectionsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "socket_refused_connections_total"),
		"Total number of refused socket connections", []string{"name"}, nil)

	// We could add a cpu label, but IMO that could cause a cardinality explosion. We already export
	// two modes per unit (user/system), and on a modest 4 core machine adding a cpu label would cause us to export 8 metrics
	// e.g. (2 modes * 4 cores) per enabled unit
	unitCPUTotal := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_cpu_seconds_total"),
		"Unit CPU time in seconds",
		[]string{"name", "type", "mode"}, nil,
	)

	ipIngressBytes := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "service_ip_ingress_bytes"),
		"Service unit ingress IP accounting in bytes.",
		[]string{"name"}, nil,
	)
	ipEgressBytes := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "service_ip_egress_bytes"),
		"Service unit egress IP accounting in bytes.",
		[]string{"name"}, nil,
	)
	ipIngressPackets := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "service_ip_ingress_packets_total"),
		"Service unit ingress IP accounting in packets.",
		[]string{"name"}, nil,
	)
	ipEgressPackets := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "service_ip_egress_packets_total"),
		"Service unit egress IP accounting in packets.",
		[]string{"name"}, nil,
	)
	scrapeDurationDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "collector_duration_seconds"),
		"systemd_exporter: Duration of a systemd collector scrape.",
		[]string{"collector"}, nil,
	)
	scrapeSuccessDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "exporter", "collector_success"),
		"systemd_exporter: Whether the systemd collector succeeded.",
		[]string{"collector"}, nil,
	)
	unitIncludePattern := regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *unitInclude))
	unitExcludePattern := regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *unitExclude))

	// TODO: Build a custom handler to pass in the scrape http context.
	ctx := context.TODO()
	return &Collector{
		ctx:                           ctx,
		logger:                        logger,
		systemdBootMonotonic:          systemdBootMonotonic,
		systemdBootTime:               systemdBootTime,
		unitCPUTotal:                  unitCPUTotal,
		unitState:                     unitState,
		unitInfo:                      unitInfo,
		unitStartTimeDesc:             unitStartTimeDesc,
		unitTasksCurrentDesc:          unitTasksCurrentDesc,
		unitTasksMaxDesc:              unitTasksMaxDesc,
		unitActiveEnterTimeDesc:       unitActiveEnterTimeDesc,
		unitActiveExitTimeDesc:        unitActiveExitTimeDesc,
		unitInactiveEnterTimeDesc:     unitInactiveEnterTimeDesc,
		unitInactiveExitTimeDesc:      unitInactiveExitTimeDesc,
		nRestartsDesc:                 nRestartsDesc,
		timerLastTriggerDesc:          timerLastTriggerDesc,
		socketAcceptedConnectionsDesc: socketAcceptedConnectionsDesc,
		socketCurrentConnectionsDesc:  socketCurrentConnectionsDesc,
		socketRefusedConnectionsDesc:  socketRefusedConnectionsDesc,
		ipIngressBytes:                ipIngressBytes,
		ipEgressBytes:                 ipEgressBytes,
		ipIngressPackets:              ipIngressPackets,
		ipEgressPackets:               ipEgressPackets,
		scrapeSuccessDesc:             scrapeSuccessDesc,
		scrapeDurationDesc:            scrapeDurationDesc,
		unitIncludePattern:            unitIncludePattern,
		unitExcludePattern:            unitExcludePattern,
	}, nil
}

// Collect gathers metrics from systemd.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	begin := time.Now()

	err := c.collect(ch)
	if err != nil {
		level.Error(c.logger).Log("msg", "error collecting metrics", "err", err)
		ch <- prometheus.MustNewConstMetric(
			c.scrapeSuccessDesc, prometheus.GaugeValue, 0, namespace)
	} else {
		ch <- prometheus.MustNewConstMetric(
			c.scrapeSuccessDesc, prometheus.GaugeValue, 1, namespace)
	}

	ch <- prometheus.MustNewConstMetric(c.scrapeDurationDesc, prometheus.GaugeValue, time.Since(begin).Seconds(), namespace)
}

// Describe gathers descriptions of Metrics
func (c *Collector) Describe(desc chan<- *prometheus.Desc) {
	desc <- c.systemdBootMonotonic
	desc <- c.systemdBootTime
	desc <- c.unitCPUTotal
	desc <- c.unitState
	desc <- c.unitInfo
	desc <- c.unitStartTimeDesc
	desc <- c.unitTasksCurrentDesc
	desc <- c.unitTasksMaxDesc
	desc <- c.nRestartsDesc
	desc <- c.timerLastTriggerDesc
	desc <- c.socketAcceptedConnectionsDesc
	desc <- c.socketCurrentConnectionsDesc
	desc <- c.socketRefusedConnectionsDesc
	desc <- c.ipIngressBytes
	desc <- c.ipEgressBytes
	desc <- c.ipIngressPackets
	desc <- c.ipEgressPackets
	desc <- c.scrapeDurationDesc
	desc <- c.scrapeSuccessDesc

}

func parseUnitType(unit dbus.UnitStatus) string {
	t := strings.Split(unit.Name, ".")
	return t[len(t)-1]
}

func (c *Collector) collect(ch chan<- prometheus.Metric) error {
	begin := time.Now()
	conn, err := c.newDbus()
	if err != nil {
		return errors.Wrapf(err, "couldn't get dbus connection")
	}
	defer conn.Close()

	err = c.collectBootStageTimestamps(conn, ch)
	if err != nil {
		level.Debug(c.logger).Log("msg", "Failed to collect boot stage timestamps", "err", err)
	}

	allUnits, err := conn.ListUnitsContext(c.ctx)
	if err != nil {
		return errors.Wrap(err, "could not get list of systemd units from dbus")
	}

	level.Debug(c.logger).Log("msg", "systemd ListUnits took", "seconds", time.Since(begin).Seconds())
	begin = time.Now()
	units := c.filterUnits(allUnits, c.unitIncludePattern, c.unitExcludePattern)
	level.Debug(c.logger).Log("msg", "systemd filterUnits took", "seconds", time.Since(begin).Seconds())

	var wg sync.WaitGroup
	wg.Add(len(units))
	for _, unit := range units {
		go func(unit dbus.UnitStatus) {
			err := c.collectUnit(conn, ch, unit)
			if err != nil {
				level.Warn(c.logger).Log("msg", errUnitMetricsMsg, "err", err)
			}
			wg.Done()
		}(unit)
	}

	wg.Wait()
	return nil
}

func (c *Collector) collectBootStageTimestamps(conn *dbus.Conn, ch chan<- prometheus.Metric) error {
	stages := []string{"Finish", "Firmware", "Loader", "Kernel", "InitRD",
		"InitRDGeneratorsStart", "InitRDGeneratorsFinish",
		"InitRDSecurityStart", "InitRDSecurityFinish",
		"InitRDUnitsLoadStart", "InitRDUnitsLoadFinish",
		"GeneratorsStart", "GeneratorsFinish",
		"SecurityStart", "SecurityFinish", "Userspace",
		"UnitsLoadStart", "UnitsLoadFinish"}

	for _, stage := range stages {
		stageMonotonicValue, err := conn.GetManagerProperty(fmt.Sprintf("%sTimestampMonotonic", stage))
		if err != nil {
			return err
		}

		stageTimestampValue, err := conn.GetManagerProperty(fmt.Sprintf("%sTimestamp", stage))
		if err != nil {
			return err
		}

		stageMonotonic := strings.TrimPrefix(strings.TrimSuffix(stageMonotonicValue, `"`), `"`)
		stageTimestamp := strings.TrimPrefix(strings.TrimSuffix(stageTimestampValue, `"`), `"`)

		parsedStageMonotonic := bootTimeRE.FindString(stageMonotonic)
		parsedStageTime := bootTimeRE.FindString(stageTimestamp)

		vMonotonic, err := strconv.ParseFloat(parsedStageMonotonic, 64)
		if err != nil {
			return err
		}

		vTimestamp, err := strconv.ParseFloat(parsedStageTime, 64)
		if err != nil {
			return err
		}

		ch <- prometheus.MustNewConstMetric(
			c.systemdBootMonotonic, prometheus.GaugeValue, float64(vMonotonic)/1e6,
			stage)
		ch <- prometheus.MustNewConstMetric(
			c.systemdBootTime, prometheus.GaugeValue, float64(vTimestamp)/1e6,
			stage)
	}

	return nil
}

func (c *Collector) collectUnit(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	logger := log.With(c.logger, "unit", unit.Name)

	// Collect unit_state for all
	err := c.collectUnitState(ch, unit)
	if err != nil {
		level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
		// TODO should we continue processing here?
	}

	err = c.collectUnitTimeMetrics(conn, ch, unit)
	if err != nil {
		level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
	}

	switch {
	case strings.HasSuffix(unit.Name, ".service"):
		err = c.collectServiceMetainfo(conn, ch, unit)
		if err != nil {
			level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
		}

		err = c.collectServiceStartTimeMetrics(conn, ch, unit)
		if err != nil {
			level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
		}

		if *enableRestartsMetrics {
			err = c.collectServiceRestartCount(conn, ch, unit)
			if err != nil {
				level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
			}
		}

		err = c.collectServiceTasksMetrics(conn, ch, unit)
		if err != nil {
			level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
		}

		if *enableIPAccountingMetrics {
			err = c.collectIPAccountingMetrics(conn, ch, unit)
			if err != nil {
				level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
			}
		}
	case strings.HasSuffix(unit.Name, ".mount"):
		err = c.collectMountMetainfo(conn, ch, unit)
		if err != nil {
			level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
		}
	case strings.HasSuffix(unit.Name, ".timer"):
		err := c.collectTimerTriggerTime(conn, ch, unit)
		if err != nil {
			level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
		}
	case strings.HasSuffix(unit.Name, ".socket"):
		err := c.collectSocketConnMetrics(conn, ch, unit)
		if err != nil {
			level.Warn(logger).Log("msg", errUnitMetricsMsg, "err", err)
		}
	default:
		level.Debug(c.logger).Log("msg", infoUnitNoHandler, unit.Name)
	}

	return nil
}

func (c *Collector) collectUnitState(ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	// TODO: wrap GetUnitTypePropertyString(
	// serviceTypeProperty, err := conn.GetUnitTypeProperty(unit.Name, "Timer", "NextElapseUSecMonotonic")

	for _, stateName := range unitStatesName {
		isActive := 0.0
		if stateName == unit.ActiveState {
			isActive = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.unitState, prometheus.GaugeValue, isActive,
			unit.Name, parseUnitType(unit), stateName)
	}

	return nil
}

func (c *Collector) collectUnitTimeMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	err := c.collectUnitTimeMetric(conn, ch, unit, c.unitActiveEnterTimeDesc, "ActiveEnterTimestamp")
	if err != nil {
		return err
	}
	err = c.collectUnitTimeMetric(conn, ch, unit, c.unitActiveExitTimeDesc, "ActiveExitTimestamp")
	if err != nil {
		return err
	}
	err = c.collectUnitTimeMetric(conn, ch, unit, c.unitInactiveEnterTimeDesc, "InactiveEnterTimestamp")
	if err != nil {
		return err
	}
	err = c.collectUnitTimeMetric(conn, ch, unit, c.unitInactiveExitTimeDesc, "InactiveExitTimestamp")
	if err != nil {
		return err
	}

	return nil
}

func (c *Collector) collectUnitTimeMetric(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus, desc *prometheus.Desc, propertyName string) error {
	timestampValue, err := conn.GetUnitPropertyContext(c.ctx, unit.Name, propertyName)
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, propertyName)
	}
	startTimeUsec, ok := timestampValue.Value.Value().(uint64)
	if !ok {
		return errors.Errorf(errConvertUint64PropertyMsg, propertyName, timestampValue.Value.Value())
	}

	ch <- prometheus.MustNewConstMetric(desc, prometheus.GaugeValue, float64(startTimeUsec)/1e6, unit.Name, parseUnitType(unit))

	return nil
}

// TODO metric is named unit but function is "Mount"
func (c *Collector) collectMountMetainfo(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	// TODO: wrap GetUnitTypePropertyString(
	serviceTypeProperty, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Mount", "Type")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "Type")
	}

	serviceType, ok := serviceTypeProperty.Value.Value().(string)
	if !ok {
		return errors.Errorf(errConvertStringPropertyMsg, "Type", serviceTypeProperty.Value.Value())
	}

	ch <- prometheus.MustNewConstMetric(
		c.unitInfo, prometheus.GaugeValue, 1.0,
		unit.Name, parseUnitType(unit), serviceType, "")

	return nil
}

// TODO the metric is named unit_info but function is named "Service"
func (c *Collector) collectServiceMetainfo(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	serviceTypeProperty, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Service", "Type")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "Type")
	}
	serviceType, ok := serviceTypeProperty.Value.Value().(string)
	if !ok {
		return errors.Errorf(errConvertStringPropertyMsg, "Type", serviceTypeProperty.Value.Value())
	}

	ch <- prometheus.MustNewConstMetric(
		c.unitInfo, prometheus.GaugeValue, 1.0,
		unit.Name, parseUnitType(unit), "", serviceType)
	return nil
}

func (c *Collector) collectServiceRestartCount(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	restartsCount, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Service", "NRestarts")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NRestarts")
	}
	val, ok := restartsCount.Value.Value().(uint32)
	if !ok {
		return errors.Errorf(errConvertUint32PropertyMsg, "NRestarts", restartsCount.Value.Value())
	}
	ch <- prometheus.MustNewConstMetric(
		c.nRestartsDesc, prometheus.CounterValue,
		float64(val), unit.Name)
	return nil
}

// TODO metric is named unit but function is "Service"
func (c *Collector) collectServiceStartTimeMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	var startTimeUsec uint64

	switch unit.ActiveState {
	case "active":
		timestampValue, err := conn.GetUnitPropertyContext(c.ctx, unit.Name, "ActiveEnterTimestamp")
		if err != nil {
			return errors.Wrapf(err, errGetPropertyMsg, "ActiveEnterTimestamp")
		}
		startTime, ok := timestampValue.Value.Value().(uint64)
		if !ok {
			return errors.Errorf(errConvertUint64PropertyMsg, "ActiveEnterTimestamp", timestampValue.Value.Value())
		}
		startTimeUsec = startTime

	default:
		startTimeUsec = 0
	}

	ch <- prometheus.MustNewConstMetric(
		c.unitStartTimeDesc, prometheus.GaugeValue,
		float64(startTimeUsec)/1e6, unit.Name, parseUnitType(unit))

	return nil
}

func (c *Collector) collectSocketConnMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	acceptedConnectionCount, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Socket", "NAccepted")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NAccepted")
	}

	ch <- prometheus.MustNewConstMetric(
		c.socketAcceptedConnectionsDesc, prometheus.CounterValue,
		float64(acceptedConnectionCount.Value.Value().(uint32)), unit.Name)

	currentConnectionCount, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Socket", "NConnections")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NConnections")
	}
	ch <- prometheus.MustNewConstMetric(
		c.socketCurrentConnectionsDesc, prometheus.GaugeValue,
		float64(currentConnectionCount.Value.Value().(uint32)), unit.Name)

	// NRefused wasn't added until systemd 239.
	refusedConnectionCount, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Socket", "NRefused")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NRefused")
	}
	ch <- prometheus.MustNewConstMetric(
		c.socketRefusedConnectionsDesc, prometheus.GaugeValue,
		float64(refusedConnectionCount.Value.Value().(uint32)), unit.Name)

	return nil
}

func (c *Collector) collectIPAccountingMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	unitPropertyToPromDesc := map[string]*prometheus.Desc{
		"IPIngressBytes":   c.ipIngressBytes,
		"IPEgressBytes":    c.ipEgressBytes,
		"IPIngressPackets": c.ipIngressPackets,
		"IPEgressPackets":  c.ipEgressPackets,
	}

	for propertyName, desc := range unitPropertyToPromDesc {
		property, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Service", propertyName)
		if err != nil {
			return errors.Wrapf(err, errGetPropertyMsg, propertyName)
		}

		counter, ok := property.Value.Value().(uint64)
		if !ok {
			return errors.Errorf(errConvertUint64PropertyMsg, propertyName, property.Value.Value())
		}

		ch <- prometheus.MustNewConstMetric(desc, prometheus.CounterValue,
			float64(counter), unit.Name)
	}

	return nil
}

// TODO either the unit should be called service_tasks, or it should work for all
// units. It's currently named unit_task
func (c *Collector) collectServiceTasksMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	tasksCurrentCount, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Service", "TasksCurrent")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "TasksCurrent")
	}

	currentCount, ok := tasksCurrentCount.Value.Value().(uint64)
	if !ok {
		return errors.Errorf(errConvertUint64PropertyMsg, "TasksCurrent", tasksCurrentCount.Value.Value())
	}

	// Don't set if tasksCurrent if dbus reports MaxUint64.
	if currentCount != math.MaxUint64 {
		ch <- prometheus.MustNewConstMetric(
			c.unitTasksCurrentDesc, prometheus.GaugeValue,
			float64(currentCount), unit.Name)
	}

	tasksMaxCount, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Service", "TasksMax")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "TasksMax")
	}

	maxCount, ok := tasksMaxCount.Value.Value().(uint64)
	if !ok {
		return errors.Errorf(errConvertUint64PropertyMsg, "TasksMax", tasksMaxCount.Value.Value())
	}
	// Don't set if tasksMax if dbus reports MaxUint64.
	if maxCount != math.MaxUint64 {
		ch <- prometheus.MustNewConstMetric(
			c.unitTasksMaxDesc, prometheus.GaugeValue,
			float64(maxCount), unit.Name, parseUnitType(unit))
	}

	return nil
}

func (c *Collector) collectTimerTriggerTime(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	lastTriggerValue, err := conn.GetUnitTypePropertyContext(c.ctx, unit.Name, "Timer", "LastTriggerUSec")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "LastTriggerUSec")
	}
	val, ok := lastTriggerValue.Value.Value().(uint64)
	if !ok {
		return errors.Errorf(errConvertUint64PropertyMsg, "LastTriggerUSec", lastTriggerValue.Value.Value())
	}
	ch <- prometheus.MustNewConstMetric(
		c.timerLastTriggerDesc, prometheus.GaugeValue,
		float64(val)/1e6, unit.Name)
	return nil
}

func (c *Collector) newDbus() (*dbus.Conn, error) {
	if *systemdPrivate {
		return dbus.NewSystemdConnectionContext(c.ctx)
	}
	if *systemdUser {
		return dbus.NewUserConnectionContext(c.ctx)
	}
	return dbus.NewWithContext(c.ctx)
}

func (c *Collector) filterUnits(units []dbus.UnitStatus, includePattern, excludePattern *regexp.Regexp) []dbus.UnitStatus {
	filtered := make([]dbus.UnitStatus, 0, len(units))
	for _, unit := range units {
		if includePattern.MatchString(unit.Name) &&
			!excludePattern.MatchString(unit.Name) &&
			unit.LoadState == "loaded" {

			level.Debug(c.logger).Log("msg", "Adding unit", "unit", unit.Name)
			filtered = append(filtered, unit)
		} else {
			level.Debug(c.logger).Log("msg", "Ignoring unit", "unit", unit.Name)
		}
	}

	return filtered
}
