## main / unreleased

* read cpu statistics from the cpu controller instead of the cpuacct controller

## 0.5.0 / 2022-07-20

Now released under the Prometheus Community

* [CHANGE] systemd_service_restart_total changed label name from `type` to `name` #32
* [CHANGE] Remove prommod metrics #36
* [CHANGE] Rename collector flags #53
* [FEATURE] Add TLS and Basic Auth #54

## 0.4.0 / 2020-04-23

* New option `--collector.user`, which allows users to connect to the user systemd instance. Thanks @pelov :)
* New feature `--collector.enable-ip-accounting`, enables service ip accounting metrics. This feature only works with systemd 235 and above. thanks @jwhited :)

## 0.3.0 / 2020-03-28

### **Breaking changes**

* `systemd_unit_state` label `type` has new meaning
   Now shows Unit type (`service`, `scope`, etc), not Service Unit types (`simple`, `forking`, etc)
   or mount unit types(`aufs`,`ext3`, etc). Service and mount types have been moved to `systemd_unit_info` 

### Changes
- [CHANGE] Important! Docker images are now published to `povilasv/systemd-exporter` and `quay.io/povilasv/systemd-exporter` registry.
- [FEATURE] Add support for amd64, 386, arm, arm64, mips, mipsle, mips64, mips64le, ppc64, ppc64le, s390x docker images.
- [FEATURE] Read unit CPU usage from cgroup. Added `systemd_unit_cpu_seconds_total` metric. **Note** - Untested on unified hierarchy
- [FEATURE] Add `systemd_unit_info` with metainformation about units incl. subtype specific info
- [ENHANCEMENT] Added `type` label to all metrics named `systemd_unit-*` to support PromQL grouping
* [ENHANCEMENT] `systemd_unit_state` works for all unit types, not just service and mount units
* [ENHANCEMENT] Scrapes are approx 80% faster. If needed, set GOMAXPROCS to limit max concurrency
* [CHANGE] Start tracking metric cardinality in readme
* [CHANGE] Expanded default set of unit types monitored. Only device unit types are not enabled by default
* [BUGFIX] `timer_last_trigger_seconds` metric is now exported as expected for all timers

## 0.2.0 / 2019-03-20

* [CLEANUP] Introduced changelog. From now on, changes will be reported in this file.
