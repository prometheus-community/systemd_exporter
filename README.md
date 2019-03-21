# Systemd exporter

![build](https://travis-ci.com/povilasv/systemd_exporter.svg?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/povilasv/systemd_exporter)](https://goreportcard.com/report/github.com/povilasv/systemd_exporter)
[![Docker Repository on Quay](https://quay.io/repository/povilasv/systemd_exporter/status "Docker Repository on Quay")](https://quay.io/repository/povilasv/systemd_exporter)
[![Docker Pulls](https://img.shields.io/docker/pulls/povilasv/systemd_exporter.svg?maxAge=604800)](https://hub.docker.com/r/povilasv/systemd_exporter)

Prometheus exporter for systemd services, written in Go.

# Relation to Node Exporter

Node Exporter provides machine metrics, metrics about systemd itself and some summarized systemd service metrics. 
For example, you can't retrieve systemd service process metrics like CPU usage or Memory form it.
I've even created a Pull request for it in Node Exporter repository, but got rejected as it has no place in Node Exporter.
So this project was born :)


Some metrics are duplicated in both exporters, so make sure to disable Node Exporter's flags.

# Systemd versions

There is varying support for different metrics based on systemd version. 
Flags that come from newer systemd versions are disabled by default to avoid breaking things for users using older systemd versions. Try enabling different flags, to see what works on your system.

Optional Flags:

Name     | Description | 
---------|-------------|
--collector.enable-restart-count | Enables service restart count metrics. This feature only works with systemd 235 and above.
--collector.enable-file-descriptor-size | Enables file descriptor size metrics. Systemd Exporter needs access to /proc/X/fd files.

# Deployment

Take a look at `examples` for daemonset manifests for Kubernetes.

# User privilleges

User need to access systemd dbus, `/proc` for exporter to work.

# Metrics

All metrics have `name` label, which contains systemd unit name. For example `name="bluetooh.service"` or `name="systemd-coredump.socket"`.

Metric name| Metric type | Status |
---------- | ----------- | ----------- |
systemd_unit_state | Gauge |  UNSTABLE
systemd_unit_tasks_current | Gauge | UNSTABLE
systemd_unit_tasks_max | Gauge | UNSTABLE
systemd_unit_start_time_seconds | Gauge |  UNSTABLE
systemd_service_restart_total | Gauge |  UNSTABLE
systemd_socket_accepted_connections_total | Counter | UNSTBLE
systemd_timer_last_trigger_seconds | Gauge | UNSTABLE
systemd_socket_current_connections | Gauge | UNSTABLE
systemd_socket_refused_connections_total | Gauge | UNSTABLE
systemd_process_resident_memory_bytes| Gauge | UNSTABLE
systemd_process_virtual_memory_bytes | Gauge | UNSTABLE
systemd_process_virtual_memory_max_bytes | Gauge |  UNSTABLE
systemd_process_open_fds | Gauge | UNSTABLE
systemd_process_max_fds | Gauge | UNSTABLE
systemd_process_cpu_seconds_total | Counter | UNSTABLE

