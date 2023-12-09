# Systemd exporter

[![CircleCI](https://circleci.com/gh/prometheus-community/systemd_exporter/tree/master.svg?style=shield)](circleci)
[![Go Report Card](https://goreportcard.com/badge/github.com/prometheus-community/systemd_exporter)](https://goreportcard.com/report/github.com/prometheus-community/systemd_exporter)
[![Docker Pulls](https://img.shields.io/docker/pulls/prometheuscommunity/systemd-exporter.svg?maxAge=604800)](https://hub.docker.com/r/prometheuscommunity/systemd-exporter)
[![Docker Repository on Quay](https://quay.io/repository/prometheuscommunity/systemd-exporter/status)][quay]

Prometheus exporter for systemd units, written in Go.

## Relation to Node and Process Exporter

The focus on each exporter is different. For example, the [node_exporter](https://github.com/prometheus/node_exporter/) has a broad node level focus, and the [process-exporter](https://github.com/ncabatoff/process-exporter)
is focused on deep analysis of specific processes. systemd-exporter aims to fit in the middle, taking 
advantage of systemd's builtin process and thread grouping to provide application-level metrics. 

| Exporter         | Metric Goals                               | Example                                            |
| ---------------- | ------------------------------------------ | -------------------------------------------------- |
| node-exporter    | Machine-wide monitoring and usage summary  | CPU usage of entire node (e.g. `127.0.0.1`)        |
| systemd-exporter | Systemd unit monitoring and resource usage | The state of each service (e.g. `mongodb.service`) |
| process-exporter | Focus is on individual processes           | CPU of specific process ID (e.g. `1127`)           |
| cAdvisor         | Metrics per cgroup (systemd uses cgroups)  | CPU usage of each cgroup (e.g. `system.slice/mongodb.service`

Systemd groups processes, threads, and other resources (PIDs, memory, etc) into logical containers 
called units. Systemd-exporter will read the 11 different types of systemd units (e.g. service, slice, etc)
and give you metrics about the health and resource consumption of each unit. This allows an application
specific view of your system, allowing you to determine resource usage of an application such as 
`mysql.service` independently from the resources used by other processes on your system.

This clearly allows more granular monitoring than machine-level metrics. However, we do not export 
metrics for specific processes or threads. Said another way, the granularity of systemd-exporter is 
limited by the size of the systemd unit. If you've chosen to pack 400 threads and 20 processes inside
the `mysql.service`, we will only export systemd provided metrics on the service unit, not on the
individual tasks. For that level of detail (and numerous other "very fine grained") metrics, you
should look into process-exporter.

There is overlap between these three exporters, so make sure to read the documents if you use multiple. 

For example, if you are using systemd-exporter, then you should *not* enable these flags in node-exporter 
as we already expose identical metrics by default: `--systemd.collector.enable-task-metrics --systemd.collector.enable-restarts-metrics
 --systemd.collector.enable-start-time-metrics`. process-exporter has a concept of logically grouping
processes according to the process names. This is a bottom-up variant of logical process grouping, while 
systemd's approach is top-down (e.g. groups are named and then processes are launched in them). The systemd
approach provides much stronger guarantees that no processes/threads are "missing" from your group, but 
it does also require that you are using systemd as your init system whereas the bottom-up approach works
on all systems.

# Systemd versions

There is varying support for different metrics based on systemd version. 
Flags that come from newer systemd versions are disabled by default to avoid breaking things for users using older systemd versions. Try enabling different flags, to see what works on your system.

Optional Flags:

Name     | Description | 
---------|-------------|
--systemd.collector.enable-restart-count | Enables service restart count metrics. This feature only works with systemd 235 and above.
--systemd.collector.enable-file-descriptor-size | Enables file descriptor size metrics. Systemd Exporter needs access to /proc/X/fd files.
--systemd.collector.enable-ip-accounting | Enables service ip accounting metrics. This feature only works with systemd 235 and above.

Of note, there is no customized support for `.snapshot` (removed in systemd v228), `.busname` (only present on systems using kdbus), `generated` (created via generators), `transient` (created during systemd-run) have no special support. 

# Deployment

Take a look at `examples` for daemonset manifests for Kubernetes.

# User privilleges

User needs to access systemd dbus, typically exporter needs to see node's `/proc` to work.

# Metrics

All metrics have `name` label, which contains systemd unit name. For example 
`name="bluetooth.service"` or `name="systemd-coredump.socket"`. Metrics that 
are present for all units (e.g. those named `unit_*`) additionally have a 
label type e.g. (`type="socket"` or `type="service"`) to allow usage in 
PromQL grouping queries (e.g. `count(systemd_unit_state) by (type)`)

Note that a number of unit types are filtered by default

| Metric name                               | Metric type | Status   | Cardinality                                                        |
| ----------------------------------------- | ----------- | -------- | ------------------------------------------------------------------ |
| systemd_exporter_build_info               | Gauge       | UNSTABLE | 1 per systemd-exporter                                             |
| systemd_unit_info                         | Gauge       | UNSTABLE | 1 per service + 1 per mount                                        |
| systemd_unit_state                        | Gauge       | UNSTABLE | 5 per unit {state="activating/active/deactivating/failed/inactive} |
| systemd_unit_tasks_current                | Gauge       | UNSTABLE | 1 per service                                                      |
| systemd_unit_tasks_max                    | Gauge       | UNSTABLE | 1 per service                                                      |
| systemd_unit_start_time_seconds           | Gauge       | UNSTABLE | 1 per service                                                      |
| systemd_service_restart_total             | Gauge       | UNSTABLE | 1 per service                                                      |
| systemd_service_ip_ingress_bytes          | Counter     | UNSTABLE | 1 per service                                                      |
| systemd_service_ip_egress_bytes           | Counter     | UNSTABLE | 1 per service                                                      |
| systemd_service_ip_ingress_packets_total  | Counter     | UNSTABLE | 1 per service                                                      |
| systemd_service_ip_egress_packets_total   | Counter     | UNSTABLE | 1 per service                                                      |
| systemd_socket_accepted_connections_total | Counter     | UNSTABLE | 1 per socket                                                       |
| systemd_socket_current_connections        | Gauge       | UNSTABLE | 1 per socket                                                       |
| systemd_socket_refused_connections_total  | Gauge       | UNSTABLE | 1 per socket                                                       |
| systemd_timer_last_trigger_seconds        | Gauge       | UNSTABLE | 1 per timer                                                        |

## Configuration

systemd_exporter allows you to include/exclude some systemd units. You can use `--systemd.collector.unit-include` and `--systemd.collector.unit-exclude` to select wanted units. Both of these options are in [RE2](https://github.com/google/re2/wiki/Syntax) syntax. For example:

```
args:
  - --systemd.collector.unit-include=.*ceph.*\.service|ceph.*\.timer|kubelet.service|docker.service
  - --systemd.collector.unit-exclude=ceph-volume.*\.service
```

## TLS and basic authentication

The systemd Exporter supports TLS and basic authentication.

To use TLS and/or basic authentication, you need to pass a configuration file
using the `--web.config.file` parameter. The format of the file is described
[in the exporter-toolkit repository](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).
