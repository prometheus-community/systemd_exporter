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

import (
	"bufio"
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/go-kit/log"
	"github.com/go-kit/log/level"
	"github.com/pkg/errors"
	"golang.org/x/sys/unix"
)

// cgUnifiedMountMode constant values describe how cgroup filesystems (aka hierarchies) are
// mounted underneath /sys/fs/cgroup. In cgroups-v1 there are many mounts,
// one per controller (cpu, blkio, etc) and one for systemd itself. In
// cgroups-v2 there is only one mount managed entirely by systemd and
// internally exposing all controller syscalls. As kernel+distros migrate towards
// cgroups-v2, systemd has a hybrid mode where it mounts v2 and uses
// that for process management but also mounts all the v1 filesystem
// hierarchies and uses them for resource accounting and control
type cgUnifiedMountMode int8

const (
	// unifModeUnknown indicates that we do not know if/how any
	// cgroup filesystems are mounted underneath /sys/fs/cgroup
	unifModeUnknown cgUnifiedMountMode = iota
	// unifModeNone indicates that both systemd and the controllers
	// are using v1 legacy mounts and there is no usage of the v2
	// unified hierarchy. a.k.a "legacy hierarchy"
	unifModeNone cgUnifiedMountMode = iota
	// unifModeSystemd indicates that systemd is using a v2 unified
	// hierarchy for organizing processes into control groups, but all
	// controller interaction is using v1 per-controller hierarchies.
	// a.k.a. "hybrid hierarchy"
	unifModeSystemd cgUnifiedMountMode = iota
	// unifModeAll indicates that v2 API is in full usage and there
	// are no v1 hierarchies exported. Programs (mainly container orchestrators
	// such as docker,runc,etc) that rely on v1 APIs will be broken.
	// a.k.a. "unified hierarchy"
	unifModeAll cgUnifiedMountMode = iota
)

// WARNING: We only read this data once at process start, systemd updates
// may require restarting systemd-exporter
var cgroupUnified cgUnifiedMountMode = unifModeUnknown

// Values copied from https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h
const (
	tmpFsMagic        = 0x01021994
	cgroupSuperMagic  = 0x27e0eb
	cgroup2SuperMagic = 0x63677270
)

// cgUnifiedCached checks the filesystem types mounted under /sys/fs/cgroup to determine
// which systemd layout (legacy/hybrid/unified) is in use.
// We do not bother to track unified_systemd_v232 as our usage does not
// depend on reading the systemd hierarchy directly, we only focus on reading
// the controllers. If you care if /sys/fs/cgroup/systemd is v1 or v2 you need
// to track this
// WARNING: We cache this data once at process start. Systemd updates
// may require restarting systemd-exporter
func cgUnifiedCached(logger log.Logger) (cgUnifiedMountMode, error) {
	if cgroupUnified != unifModeUnknown {
		return cgroupUnified, nil
	}

	var fs unix.Statfs_t
	err := unix.Statfs("/sys/fs/cgroup/", &fs)
	if err != nil {
		return unifModeUnknown, errors.Wrapf(err, "failed statfs(/sys/fs/cgroup)")
	}

	switch fs.Type {
	case cgroup2SuperMagic:
		level.Debug(logger).Log("msg", "Found cgroup2 on /sys/fs/cgroup, full unified hierarchy")
		cgroupUnified = unifModeAll
	case tmpFsMagic:
		err := unix.Statfs("/sys/fs/cgroup/unified", &fs)

		// Ignore err, we expect path to be missing on v232
		if err == nil && fs.Type == cgroup2SuperMagic {
			level.Debug(logger).Log("msg", "Found cgroup2 on /sys/fs/cgroup/unified, unified hierarchy for systemd controller")
			cgroupUnified = unifModeSystemd
		} else {
			err := unix.Statfs("/sys/fs/cgroup/systemd", &fs)
			if err != nil {
				return unifModeUnknown, errors.Wrapf(err, "failed statfs(/sys/fs/cgroup/systemd)")
			}
			switch fs.Type {
			case cgroup2SuperMagic:
				level.Debug(logger).Log("msg", "Found cgroup2 on /sys/fs/cgroup/systemd, unified hierarchy for systemd controller (v232 variant)")
				cgroupUnified = unifModeSystemd
			case cgroupSuperMagic:
				level.Debug(logger).Log("msg", "Found cgroup on /sys/fs/cgroup/systemd, legacy hierarchy")
				cgroupUnified = unifModeNone
			default:
				return unifModeUnknown, errors.Errorf("unknown magic number %x for fstype returned by statfs(/sys/fs/cgroup/systemd)", fs.Type)
			}
		}
	default:
		return unifModeUnknown, errors.Errorf("unknown magic number %x for fstype returned by statfs(/sys/fs/cgroup)", fs.Type)
	}

	return cgroupUnified, nil
}

// cgGetPath returns the absolute path for a specific file in a specific controller
// in the specific cgroup denoted by the passed subpath.
// Input examples: ("cpu", "/system.slice", "cpuacct.usage_all)
func cgGetPath(controller string, subpath string, suffix string, logger log.Logger) (string, error) {
	// relevant systemd source code in cgroup-util.[h|c] specifically cg_get_path
	//  2. Joins controller name with base path

	unified, err := cgUnifiedCached(logger)
	if err != nil {
		return "", errors.Wrapf(err, "failed to determine cgroup mounting hierarchy")
	}

	// TODO Ensure controller name is valid
	// TODO Convert controller name into guaranteed valid directory name
	dn := controller

	joined := ""
	switch unified {
	case unifModeNone:
		joined = filepath.Join("/sys/fs/cgroup", dn, subpath, suffix)
	case unifModeSystemd:
		joined = filepath.Join("/sys/fs/cgroup/unified", subpath, suffix)
	case unifModeAll:
		joined = filepath.Join("/sys/fs/cgroup", subpath, suffix)
	default:
		return "", errors.Errorf("unknown cgroup mount mode (e.g. unified mode) %d", unified)
	}
	return joined, nil
}

// CPUUsage stores one core's worth of CPU usage for a control group
// (aka cgroup) of tasks (e.g. both processes and threads).
// Equivalent to cpuacct.usage_percpu_user and cpuacct.usage_percpu_system
type CPUUsage struct {
	SystemMicrosec uint64
	UserMicrosec   uint64
}

// ReadFileNoStat uses io.ReadAll to read contents of entire file.
// This is similar to os.ReadFile but without the call to os.Stat, because
// many files in /proc and /sys report incorrect file sizes (either 0 or 4096).
// Reads a max file size of 512kB.  For files larger than this, a scanner
// should be used.
// COPIED FROM prometheus/procfs WHICH ALSO USES APACHE 2.0
func ReadFileNoStat(filename string) ([]byte, error) {
	const maxBufferSize = 1024 * 512

	f, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	reader := io.LimitReader(f, maxBufferSize)
	return io.ReadAll(reader)
}

// NewCPUUsage will locate and read the kernel's cpu accounting info for
// the provided systemd cgroup subpath.
func NewCPUUsage(cgSubpath string, logger log.Logger) (*CPUUsage, error) {
	cgPath, err := cgGetPath("cpu", cgSubpath, "cpu.stat", logger)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get cpu controller path")
	}

	// Example cpu.stat
	// usage_usec 291912970
	// user_usec 238552676
	// system_usec 53360293
	b, err := ReadFileNoStat(cgPath)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read file %s", cgPath)
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))
	if ok := scanner.Scan(); !ok {
		return nil, errors.Errorf("unable to scan file %s", cgPath)
	}
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrapf(err, "unable to scan file %s", cgPath)
	}
	var user, sys uint64
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, errors.Wrapf(err, "unable to scan file %s", cgPath)
		}
		text := scanner.Text()
		vals := strings.Split(text, " ")
		if len(vals) != 2 {
			return nil, errors.Errorf("unable to parse contents of file %s", cgPath)
		}
		val, err := strconv.ParseUint(vals[1], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse %s as uint64 (from %s)", vals[1], cgPath)
		}
		if vals[0] == "user_usec" {
			user = val
		}
		if vals[0] == "system_usec" {
			sys = val
		}
	}
	if user == 0 && sys == 0 {
		return nil, nil
	}
	onecpu := CPUUsage{
		UserMicrosec:   user,
		SystemMicrosec: sys,
	}

	return &onecpu, nil
}
