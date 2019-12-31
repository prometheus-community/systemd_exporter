## master / unreleased

### **Breaking changes**

* `systemd_unit_state` label `type` has new meaning
   Now shows Unit type (`service`, `scope`, etc), not Service Unit types (`simple`, `forking`, etc)
   or mount unit types(`aufs`,`ext3`, etc). Service and mount types have been moved to `systemd_unit_info` 

### Changes

* [ENHANCEMENT] Read unit CPU usage from cgroup, add `systemd_unit_cpu_seconds_total` metric
* [ENHANCEMENT] Add `type` label to all metrics named `systemd_unit-*` 
* [ENHANCEMENT] `systemd_unit_state` works for all unit types, just service and mount units
* [FEATURE] Add `systemd_unit_info` with metainformation about units incl. subtype specific info
* [CHANGE] Expanded default set of unit types monitored. Only device unit types are not enabled by default

## 0.2.0 / 2019-03-20

* [CLEANUP] Introduced changelog. From now on, changes will be reported in this file.
