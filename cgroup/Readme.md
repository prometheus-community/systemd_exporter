
This package provides functions to retrieve control group metrics from the pseudo-filesystem `/sys/cgroup/`.

**WARNING:** This package is a work in progress. Its API may still break in backwards-incompatible ways without warnings. Use it at your own risk.

The Linux kernel supports two APIs for userspace to interact with control groups, the v1 API and the v2 API. See 
[this LWN Article](https://lwn.net/Articles/679786/) or 
[this kernel documentation](https://www.kernel.org/doc/html/latest/admin-guide/cgroup-v2.html#deprecated-v1-core-features) 
for background on the two APIs. This package will interact with both v1 and v2 APIs.


### Focus on Systemd

This package is initially focused on reading metrics for systemd units. Therefore, 
the following systemd documentation is relevant. 

#### Systemd cgroup mount mode

The kernel can mount the cgroupfs in any manner it chooses. However, anyone wanting to use that cgroupfs must know 
where/how it is mounted. When there was only one cgroup API, it was always mounted at `/sys/fs/cgroup`. With the 
transition from v1 to v2, the mounting approach differs per-distro, with some mounting only v2, some mounting only 
v1(all hierarchies), and some mounting a combination. For simplicity, this package initially focuses on the three 
mount "modes" supported by systemd: 

via [systemd.io](https://systemd.io/CGROUP_DELEGATION/#three-different-tree-setups-)

1. Unified — this is the simplest mode, and exposes a pure cgroup v2 logic
2. Legacy — this is the traditional cgroup v1 mode. In this mode the various controllers each get their own cgroup 
   file system mounted to `/sys/fs/cgroup/<controller>/`
3. Hybrid — this is a hybrid between the unified and legacy mode. It’s set up mostly like legacy

#### Systemd Supported Controllers
 
The initial target controllers this package aims to read from are the controllers supported by systemd. Reading from 
other controllers may be supported in the future. Systemd guarantees that all v1 hierarchies are kept in sync. 

Via [systemd.io](https://systemd.io/CGROUP_DELEGATION/#controller-support):

Systemd supports a number of controllers (but not all). Specifically, supported are:

on cgroup v1: cpu, cpuacct, blkio, memory, devices, pids
on cgroup v2: cpu, io, memory, pids

It is our intention to natively support all cgroup v2 controllers as they are added 
to the kernel. However, regarding cgroup v1: at this point we will not add support 
for any other controllers anymore. This means systemd currently does not and will 
never manage the following controllers on cgroup v1: freezer, cpuset, net_cls, 
perf_event, net_prio, hugetlb

