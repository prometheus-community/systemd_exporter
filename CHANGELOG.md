## master / unreleased

### **Breaking changes**

* `systemd_unit_state` no longer returns a `type` label

### Changes

* [ENHANCEMENT] `systemd_unit_state` works for all unit types, just service and mount units
* [FEATURE] Add `systemd_unit_info` with metainformation about units incl. subtype specific info
* [CHANGE] Expanded default set of unit types monitored. Only device unit types are not enabled by default

## 0.2.0 / 2019-03-20

* [CLEANUP] Introduced changelog. From now on, changes will be reported in this file.
