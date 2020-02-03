## master / unreleased

### **Breaking changes**

* `systemd_unit_state` label `type` has new meaning. Previously `type` contained service unit type (`simple`, `forking`, etc) or mount unit types (`aufs`, `ext3`, etc). Now `systemd_unit_state{type}` contains overall unit type (`service`, `scope`, etc) to allow easy PromQL group by clauses. Service and mount types have been moved to `systemd_unit_info` 

### Changes

- [FEATURE] Read unit CPU usage from cgroup. Added `systemd_unit_cpu_seconds_total` metric. **Note** - Untested on unified hierarchy
- [FEATURE] Add `systemd_unit_info` with metainformation about units incl. subtype specific info
- [ENHANCEMENT] Added `type` label to all metrics named `systemd_unit-*` to support PromQL grouping
- [ENHANCEMENT] `systemd_unit_state` works for all unit types, not just service and mount units
- [ENHANCEMENT] Scrapes are approx 80% faster. If needed, set GOMAXPROCS to limit max concurrency
- [CHANGE] Start tracking metric cardinality in readme
- [CHANGE] Expanded default set of unit types monitored. Only device unit types are not enabled by default
- [BUGFIX] `timer_last_trigger_seconds` metric is now exported as expected for all timers

## 0.2.0 / 2019-03-20

* [CLEANUP] Introduced changelog. From now on, changes will be reported in this file.
