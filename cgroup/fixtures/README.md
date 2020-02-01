Contains fixed state used as a baseline for running tests. The purpose of these test fixtures
is to ensure that there is a well known and fixed environment in which tests are run so that
results are repeatable

Note: including symlinks into fixtures is important for testing. However this can break 
community toolchains and OS'es in unexpected ways. prometheus/procfs addressed this 
issue by using ttar to flatten their fixtures directory into a single standard file, and 
only folks who are running testing will unflatten this file. This prevents symlinks from
appearing on disk for anyone only doing a git checkout. May be something to consider if 
we get problem reports. See https://github.com/prometheus/procfs/pull/79

