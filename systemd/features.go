package systemd

import kingpin "github.com/alecthomas/kingpin/v2"

var (
	autoEnableFeatures        = kingpin.Flag("systemd.collector.auto-enable", "Automatically enables collection of metrics when the detected systemd version is new enough.").Bool()
	enableRestartsMetrics     = kingpin.Flag("systemd.collector.enable-restart-count", "Enables service restart count metrics (requires systemd >= 235).").Bool()
	enableIPAccountingMetrics = kingpin.Flag("systemd.collector.enable-ip-accounting", "Enables service IP accounting metrics (requires systemd >= 235).").Bool()
)

func shouldCollectRestartsMetrics(systemdMajorVersion int) bool {
	return *enableRestartsMetrics || *autoEnableFeatures && systemdMajorVersion >= 235
}

func shouldCollectIPAccountingMetrics(systemdMajorVersion int) bool {
	return *enableIPAccountingMetrics || *autoEnableFeatures && systemdMajorVersion >= 235
}
