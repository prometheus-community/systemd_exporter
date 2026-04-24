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
