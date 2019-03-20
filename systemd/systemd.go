package systemd

import (
	"fmt"
	"math"
	"regexp"
	"strings"
	"time"

	"github.com/coreos/go-systemd/dbus"
	"github.com/pkg/errors"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"github.com/prometheus/procfs"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
)

const namespace = "systemd"

var (
	unitWhitelist         = kingpin.Flag("collector.unit-whitelist", "Regexp of systemd units to whitelist. Units must both match whitelist and not match blacklist to be included.").Default(".+").String()
	unitBlacklist         = kingpin.Flag("collector.unit-blacklist", "Regexp of systemd units to blacklist. Units must both match whitelist and not match blacklist to be included.").Default(".+\\.(automount|device|mount|scope|slice)").String()
	systemdPrivate        = kingpin.Flag("collector.private", "Establish a private, direct connection to systemd without dbus.").Bool()
	procPath              = kingpin.Flag("path.procfs", "procfs mountpoint.").Default(procfs.DefaultMountPoint).String()
	enableRestartsMetrics = kingpin.Flag("collector.enable-restart-count", "Enables service restart count metrics. This feature onlyworks with systemd 235 and above.").Bool()
)

var unitStatesName = []string{"active", "activating", "deactivating", "inactive", "failed"}

var (
	errGetPropertyMsg           = "couldn't get unit's %s property"
	errConvertUint64PropertyMsg = "couldn't convert unit's %s property %v to uint64"
	errConvertUint32PropertyMsg = "couldn't convert unit's %s property %v to uint32"
	errConvertStringPropertyMsg = "couldn't convert unit's %s property %v to string"
	errUnitMetricsMsg           = "couldn't get unit's metrics: %s"
)

type Collector struct {
	logger                        log.Logger
	unitDesc                      *prometheus.Desc
	unitStartTimeDesc             *prometheus.Desc
	unitTasksCurrentDesc          *prometheus.Desc
	unitTasksMaxDesc              *prometheus.Desc
	nRestartsDesc                 *prometheus.Desc
	timerLastTriggerDesc          *prometheus.Desc
	socketAcceptedConnectionsDesc *prometheus.Desc
	socketCurrentConnectionsDesc  *prometheus.Desc
	socketRefusedConnectionsDesc  *prometheus.Desc
	cpuTotalDesc                  *prometheus.Desc
	openFDs                       *prometheus.Desc
	maxFDs                        *prometheus.Desc
	vsize                         *prometheus.Desc
	maxVsize                      *prometheus.Desc
	rss                           *prometheus.Desc

	unitWhitelistPattern *regexp.Regexp
	unitBlacklistPattern *regexp.Regexp
}

// NewCollector returns a new Collector exposing systemd statistics.
func NewCollector(logger log.Logger) (*Collector, error) {
	unitDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_state"),
		"Systemd unit", []string{"name", "state", "type"}, nil,
	)
	unitStartTimeDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_start_time_seconds"),
		"Start time of the unit since unix epoch in seconds.", []string{"name"}, nil,
	)
	unitTasksCurrentDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_tasks_current"),
		"Current number of tasks per Systemd unit", []string{"name"}, nil,
	)
	unitTasksMaxDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "unit_tasks_max"),
		"Maximum number of tasks per Systemd unit", []string{"name"}, nil,
	)
	nRestartsDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "service_restart_total"),
		"Service unit count of Restart triggers", []string{"state"}, nil)
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

	cpuTotalDesc := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_cpu_seconds_total"),
		"Total user and system CPU time spent in seconds.",
		[]string{"name"}, nil,
	)

	openFDs := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_open_fds"),
		"Number of open file descriptors.",
		[]string{"name"}, nil,
	)

	maxFDs := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_max_fds"),
		"Maximum number of open file descriptors.",
		[]string{"name"}, nil,
	)
	vsize := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_virtual_memory_bytes"),
		"Virtual memory size in bytes.",
		[]string{"name"}, nil,
	)

	maxVsize := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_virtual_memory_max_bytes"),
		"Maximum amount of virtual memory available in bytes.",
		[]string{"name"}, nil,
	)

	rss := prometheus.NewDesc(
		prometheus.BuildFQName(namespace, "", "process_resident_memory_bytes"),
		"Resident memory size in bytes.",
		[]string{"name"}, nil,
	)
	unitWhitelistPattern := regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *unitWhitelist))
	unitBlacklistPattern := regexp.MustCompile(fmt.Sprintf("^(?:%s)$", *unitBlacklist))

	return &Collector{
		logger:                        logger,
		unitDesc:                      unitDesc,
		unitStartTimeDesc:             unitStartTimeDesc,
		unitTasksCurrentDesc:          unitTasksCurrentDesc,
		unitTasksMaxDesc:              unitTasksMaxDesc,
		nRestartsDesc:                 nRestartsDesc,
		timerLastTriggerDesc:          timerLastTriggerDesc,
		socketAcceptedConnectionsDesc: socketAcceptedConnectionsDesc,
		socketCurrentConnectionsDesc:  socketCurrentConnectionsDesc,
		socketRefusedConnectionsDesc:  socketRefusedConnectionsDesc,
		cpuTotalDesc:                  cpuTotalDesc,
		openFDs:                       openFDs,
		maxFDs:                        maxFDs,
		vsize:                         vsize,
		maxVsize:                      maxVsize,
		rss:                           rss,
		unitWhitelistPattern:          unitWhitelistPattern,
		unitBlacklistPattern:          unitBlacklistPattern,
	}, nil
}

// Collect gathers metrics from systemd.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	err := c.collect(ch)
	if err != nil {
		c.logger.Error(err)
	}
}

// Describe gathers descriptions of Metrics
func (c *Collector) Describe(desc chan<- *prometheus.Desc) {
	desc <- c.unitDesc
	desc <- c.unitStartTimeDesc
	desc <- c.unitTasksCurrentDesc
	desc <- c.unitTasksMaxDesc
	desc <- c.nRestartsDesc
	desc <- c.timerLastTriggerDesc
	desc <- c.socketAcceptedConnectionsDesc
	desc <- c.socketCurrentConnectionsDesc
	desc <- c.socketRefusedConnectionsDesc
	desc <- c.cpuTotalDesc
	desc <- c.openFDs
	desc <- c.maxFDs
	desc <- c.vsize
	desc <- c.maxVsize
	desc <- c.rss
}

func (c *Collector) collect(ch chan<- prometheus.Metric) error {
	begin := time.Now()
	conn, err := c.newDbus()
	if err != nil {
		return errors.Wrapf(err, "couldn't get dbus connection")
	}
	defer conn.Close()

	allUnits, err := conn.ListUnits()
	if err != nil {
		return errors.Wrap(err, "couldn't get units")
	}

	c.logger.Debugf("systemd getAllUnits took %f", time.Since(begin).Seconds())
	begin = time.Now()
	units := filterUnits(allUnits, c.unitWhitelistPattern, c.unitBlacklistPattern)
	c.logger.Debugf("systemd filterUnits took %f", time.Since(begin).Seconds())

	for _, unit := range units {
		logger := c.logger.With("unit", unit.Name)

		switch {
		case strings.HasSuffix(unit.Name, ".service"):
			err = c.collectServiceState(conn, ch, unit)
			if err != nil {
				logger.Warnf(errUnitMetricsMsg, err)
			}

			err = c.collectServiceStartTimeMetrics(conn, ch, unit)
			if err != nil {
				logger.Warnf(errUnitMetricsMsg, err)
			}

			if *enableRestartsMetrics {
				err = c.collectServiceRestartCount(conn, ch, unit)
				if err != nil {
					logger.Warnf(errUnitMetricsMsg, err)
				}
			}

			err = c.collectServiceTasksMetrics(conn, ch, unit)
			if err != nil {
				logger.Warnf(errUnitMetricsMsg, err)
			}

			err = c.collectServiceProcessMetrics(conn, ch, unit)
			if err != nil {
				logger.Warnf(errUnitMetricsMsg, err)
			}
		case strings.HasSuffix(unit.Name, ".mount"):
			err = c.collectMountState(conn, ch, unit)
			if err != nil {
				logger.Warnf(errUnitMetricsMsg, err)
			}

		case strings.HasSuffix(unit.Name, ".trigger"):
			err := c.collectTimerTriggerTime(conn, ch, unit)
			if err != nil {
				logger.Warnf(errUnitMetricsMsg, err)
			}
		case strings.HasSuffix(unit.Name, ".socket"):
			err := c.collectSocketConnMetrics(conn, ch, unit)
			if err != nil {
				logger.Warnf(errUnitMetricsMsg, err)
			}
		}
	}

	return nil
}

func (c *Collector) collectMountState(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	//TODO: wrap GetUnitTypePropertyString(
	serviceTypeProperty, err := conn.GetUnitTypeProperty(unit.Name, "Mount", "Type")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "Type")
	}

	serviceType, ok := serviceTypeProperty.Value.Value().(string)
	if !ok {
		return errors.Errorf(errConvertStringPropertyMsg, "Type", serviceTypeProperty.Value.Value())
	}

	for _, stateName := range unitStatesName {
		isActive := 0.0
		if stateName == unit.ActiveState {
			isActive = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.unitDesc, prometheus.GaugeValue, isActive,
			unit.Name, stateName, serviceType)
	}

	return nil
}

func (c *Collector) collectServiceState(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	serviceTypeProperty, err := conn.GetUnitTypeProperty(unit.Name, "Service", "Type")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "Type")
	}
	serviceType, ok := serviceTypeProperty.Value.Value().(string)
	if !ok {
		return errors.Errorf(errConvertStringPropertyMsg, "Type", serviceTypeProperty.Value.Value())
	}

	for _, stateName := range unitStatesName {
		isActive := 0.0
		if stateName == unit.ActiveState {
			isActive = 1.0
		}
		ch <- prometheus.MustNewConstMetric(
			c.unitDesc, prometheus.GaugeValue, isActive,
			unit.Name, stateName, serviceType)
	}

	return nil
}

func (c *Collector) collectServiceRestartCount(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	restartsCount, err := conn.GetUnitTypeProperty(unit.Name, "Service", "NRestarts")
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

func (c *Collector) collectServiceStartTimeMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	var startTimeUsec uint64

	switch unit.ActiveState {
	case "active":
		timestampValue, err := conn.GetUnitProperty(unit.Name, "ActiveEnterTimestamp")
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
		float64(startTimeUsec)/1e6, unit.Name)

	return nil
}

func (c *Collector) collectServiceProcessMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	// TODO: ExecStart type property, has a slice with process information.
	// When systemd manages multiple processes, maybe we should add them all?

	mainPID, err := conn.GetUnitTypeProperty(unit.Name, "Service", "MainPID")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "MainPID")
	}

	pid, ok := mainPID.Value.Value().(uint32)
	if !ok {
		return errors.Errorf(errConvertUint32PropertyMsg, "MainPID", mainPID.Value.Value())
	}

	// MainPID 0 when the service currently has no main PID
	if pid == 0 {
		return nil
	}

	fs, err := procfs.NewFS(*procPath)
	if err != nil {
		return err
	}
	p, err := fs.NewProc(int(pid))
	if err != nil {
		return err
	}

	stat, err := p.NewStat()
	if err != nil {
		return err
	}

	ch <- prometheus.MustNewConstMetric(
		c.cpuTotalDesc, prometheus.CounterValue,
		stat.CPUTime(), unit.Name)
	ch <- prometheus.MustNewConstMetric(c.vsize, prometheus.GaugeValue,
		float64(stat.VirtualMemory()), unit.Name)
	ch <- prometheus.MustNewConstMetric(c.rss, prometheus.GaugeValue,
		float64(stat.ResidentMemory()), unit.Name)

	limits, err := p.NewLimits()
	if err != nil {
		return errors.Wrap(err, "couldn't get process limits")
	}
	ch <- prometheus.MustNewConstMetric(c.maxFDs, prometheus.GaugeValue,
		float64(limits.OpenFiles), unit.Name)
	ch <- prometheus.MustNewConstMetric(c.maxVsize, prometheus.GaugeValue,
		float64(limits.AddressSpace), unit.Name)

	fds, err := p.FileDescriptorsLen()
	if err != nil {
		return errors.Wrap(err, "couldn't get process file descriptor size")
	}
	ch <- prometheus.MustNewConstMetric(c.openFDs, prometheus.GaugeValue,
		float64(fds), unit.Name)

	return nil
}

func (c *Collector) collectSocketConnMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	acceptedConnectionCount, err := conn.GetUnitTypeProperty(unit.Name, "Socket", "NAccepted")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NAccepted")
	}

	ch <- prometheus.MustNewConstMetric(
		c.socketAcceptedConnectionsDesc, prometheus.CounterValue,
		float64(acceptedConnectionCount.Value.Value().(uint32)), unit.Name)

	currentConnectionCount, err := conn.GetUnitTypeProperty(unit.Name, "Socket", "NConnections")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NConnections")
	}
	ch <- prometheus.MustNewConstMetric(
		c.socketCurrentConnectionsDesc, prometheus.GaugeValue,
		float64(currentConnectionCount.Value.Value().(uint32)), unit.Name)

	// NRefused wasn't added until systemd 239.
	refusedConnectionCount, err := conn.GetUnitTypeProperty(unit.Name, "Socket", "NRefused")
	if err != nil {
		return errors.Wrapf(err, errGetPropertyMsg, "NRefused")
	}
	ch <- prometheus.MustNewConstMetric(
		c.socketRefusedConnectionsDesc, prometheus.GaugeValue,
		float64(refusedConnectionCount.Value.Value().(uint32)), unit.Name)

	return nil
}

func (c *Collector) collectServiceTasksMetrics(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	tasksCurrentCount, err := conn.GetUnitTypeProperty(unit.Name, "Service", "TasksCurrent")
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

	tasksMaxCount, err := conn.GetUnitTypeProperty(unit.Name, "Service", "TasksMax")
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
			float64(maxCount), unit.Name)
	}

	return nil
}

func (c *Collector) collectTimerTriggerTime(conn *dbus.Conn, ch chan<- prometheus.Metric, unit dbus.UnitStatus) error {
	lastTriggerValue, err := conn.GetUnitTypeProperty(unit.Name, "Timer", "LastTriggerUSec")
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
		return dbus.NewSystemdConnection()
	}
	return dbus.New()
}

func filterUnits(units []dbus.UnitStatus, whitelistPattern, blacklistPattern *regexp.Regexp) []dbus.UnitStatus {
	filtered := make([]dbus.UnitStatus, 0, len(units))
	for _, unit := range units {
		if whitelistPattern.MatchString(unit.Name) &&
			!blacklistPattern.MatchString(unit.Name) &&
			unit.LoadState == "loaded" {

			log.Debugf("Adding unit: %s", unit.Name)
			filtered = append(filtered, unit)
		} else {
			log.Debugf("Ignoring unit: %s", unit.Name)
		}
	}

	return filtered
}
