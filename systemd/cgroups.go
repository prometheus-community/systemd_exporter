package systemd

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/prometheus/common/log"
	"golang.org/x/sys/unix"
)

// CgroupUnified constant values describe how cgroup filesystems (aka hierarchies) are
// mounted underneath /sys/fs/cgroup. In cgroups-v1 there are many mounts,
// one per controller (cpu, blkio, etc) and one for systemd itself. In
// cgroups-v2 there is only one mount managed entirely by systemd and
// internally exposing all controller syscalls. As kernel+distros migrate towards
// cgroups-v2, systemd has a hybrid mode where it mounts v2 and uses
// that for process management but also mounts all the v1 filesystem
// hierarchies and uses them for resource accounting and control
type CgroupUnified int8

const (
	// CgroupUnifiedNone indicates that both systemd and the controllers
	// are using v1 legacy mounts and there is no usage of the v2
	// unified hierarchy. a.k.a "legacy hierarchy"
	CgroupUnifiedNone CgroupUnified = iota
	// CgroupUnifiedSystemd indicates that systemd is using a v2 unified
	// hierarcy for organizing processes into control groups, but all
	// controller interaction is using v1 per-controller hierarchies.
	// a.k.a. "hybrid hierarchy"
	CgroupUnifiedSystemd CgroupUnified = iota
	// CgroupUnifiedAll indicates that v2 API is in full usage and there
	// are no v1 hierarchies exported. Programs (mainly container orchestrators
	// such as docker,runc,etc) that rely on v1 APIs will be broken.
	// a.k.a. "unified hierarchy"
	CgroupUnifiedAll CgroupUnified = iota
)

// WARNING: We only read this data once at process start, systemd updates
// may require restarting systemd-exporter
var cgroupUnified *CgroupUnified = nil

// Values copied from https://github.com/torvalds/linux/blob/master/include/uapi/linux/magic.h
const (
	TMPFS_MAGIC         = 0x01021994
	CGROUP_SUPER_MAGIC  = 0x27e0eb
	CGROUP2_SUPER_MAGIC = 0x63677270
)

// cgUnifiedCached checks the filesystem types mounted under /sys/fs/cgroup to determine
// which systemd layout (legacy/hybrid/unified) is in use.
// We do not bother to track unified_systemd_v232 as our usage does not
// depend on reading the systemd hierarchy directly, we only focus on reading
// the controllers. If you care if /sys/fs/cgroup/systemd is v1 or v2 you need
// to track this
// WARNING: We cache this data once at process start. Systemd updates
// may require restarting systemd-exporter
func cgUnifiedCached() (*CgroupUnified, error) {
	if cgroupUnified != nil {
		return cgroupUnified, nil
	}

	var fs unix.Statfs_t
	err := unix.Statfs("/sys/fs/cgroup/", &fs)
	if err != nil {
		return nil, errors.Wrapf(err, "failed statfs(/sys/fs/cgroup)")
	}

	none, systemd, all := CgroupUnifiedNone, CgroupUnifiedSystemd, CgroupUnifiedAll
	switch fs.Type {
	case CGROUP2_SUPER_MAGIC:
		log.Debugf("Found cgroup2 on /sys/fs/cgroup, full unified hierarchy")
		cgroupUnified = &all
	case TMPFS_MAGIC:
		err := unix.Statfs("/sys/fs/cgroup/unified", &fs)

		// Ignore err, we expect path to be missing on v232
		if err == nil && fs.Type == CGROUP2_SUPER_MAGIC {
			log.Debugf("Found cgroup2 on /sys/fs/cgroup/systemd, unified hierarchy for systemd controller")
			cgroupUnified = &systemd
		} else {
			err := unix.Statfs("/sys/fs/cgroup/systemd", &fs)
			if err != nil {
				return nil, errors.Wrapf(err, "failed statfs(/sys/fs/cgroup/systemd)")
			}
			switch fs.Type {
			case CGROUP2_SUPER_MAGIC:
				log.Debugf("Found cgroup2 on /sys/fs/cgroup/systemd, unified hierarchy for systemd controller (v232 variant)")
				cgroupUnified = &systemd
			case CGROUP_SUPER_MAGIC:
				log.Debugf("Found cgroup on /sys/fs/cgroup/systemd, legacy hierarchy")
				cgroupUnified = &none
			default:
				return nil, errors.Errorf("unknown magic number %x for fstype returned by statfs(/sys/fs/cgroup/systemd)", fs.Type)
			}
		}
	default:
		return nil, errors.Errorf("unknown magic number %x for fstype returned by statfs(/sys/fs/cgroup)", fs.Type)
	}

	return cgroupUnified, nil
}

// cgGetPath returns the absolute path for a specific file in a specific controller
// in the specific cgroup denoted by the passed subpath.
// Input examples: ("cpu", "/system.slice", "cpuacct.usage_all)
func cgGetPath(controller string, subpath string, suffix string) (*string, error) {
	// relevant systemd source code in cgroup-util.[h|c] specifically cg_get_path
	//  2. Joins controller name with base path

	unified, err := cgUnifiedCached()
	if err != nil {
		return nil, errors.Wrapf(err, "failed to determine cgroup mounting hierarchy")
	}

	// TODO Ensure controller name is valid
	// TODO Convert controller name into guaranteed valid directory name
	dn := controller

	joined := ""
	switch *unified {
	case CgroupUnifiedNone, CgroupUnifiedSystemd:
		joined = filepath.Join("/sys/fs/cgroup", dn, subpath, suffix)
	case CgroupUnifiedAll:
		joined = filepath.Join("/sys/fs/cgroup", subpath, suffix)
	}
	return &joined, nil
}

// CPUUsage stores one core's worth of CPU usage for a control group
// (aka cgroup) of tasks (e.g. both processes and threads).
// Equivalent to cpuacct.usage_percpu_user and cpuacct.usage_percpu_system
type CPUUsage struct {
	CPUId         uint32
	SystemNanosec uint64
	UserNanosec   uint64
}

// CPUAcct stores CPU accounting information (e.g. cpu usage) for a control
// group (cgroup) of tasks. Equivalent to cpuacct.usage_all
type CPUAcct struct {
	CPUs []CPUUsage
}

// UsageUserNanosecs returns user (e.g. non-kernel) cpu consumption in nanoseconds, across all available cpu
// cores, from the point that CPU accounting was enabled for this control group.
func (c *CPUAcct) UsageUserNanosecs() uint64 {
	var nanoseconds uint64
	for _, cpu := range c.CPUs {
		nanoseconds += cpu.UserNanosec
	}
	return nanoseconds
}

// UsageSystemNanosecs returns system (e.g. kernel) cpu consumption in nanoseconds, across all available cpu
// cores, from the point that CPU accounting was enabled for this control group.
func (c *CPUAcct) UsageSystemNanosecs() uint64 {
	var nanoseconds uint64
	for _, cpu := range c.CPUs {
		nanoseconds += cpu.SystemNanosec
	}
	return nanoseconds
}

// UsageAllNanosecs returns total cpu consumption in nanoseconds, across all available cpu
// cores, from the point that CPU accounting was enabled for this control group.
func (c *CPUAcct) UsageAllNanosecs() uint64 {
	var nanoseconds uint64
	for _, cpu := range c.CPUs {
		nanoseconds += cpu.SystemNanosec + cpu.UserNanosec
	}
	return nanoseconds
}

// ReadFileNoStat uses ioutil.ReadAll to read contents of entire file.
// This is similar to ioutil.ReadFile but without the call to os.Stat, because
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
	return ioutil.ReadAll(reader)
}

// NewCPUAcct will locate and read the kernel's cpu accounting info for
// the provided systemd cgroup subpath.
func NewCPUAcct(cgSubpath string) (*CPUAcct, error) {
	var cpuUsage CPUAcct

	cgPathPtr, err := cgGetPath("cpu", cgSubpath, "cpuacct.usage_all")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get cpu controller path")
	}
	cgPath := *cgPathPtr

	// Example cpuacct.usage_all
	// cpu user system
	// 0 21165924 0
	// 1 13334251 0
	b, err := ReadFileNoStat(cgPath)
	if err != nil {
		return nil, errors.Wrapf(err, "unable to read file %s", cgPath)
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Scan()
	if err := scanner.Err(); err != nil {
		return nil, errors.Wrapf(err, "unable to scan file %s", cgPath)
	}
	for scanner.Scan() {
		if err := scanner.Err(); err != nil {
			return nil, errors.Wrapf(err, "unable to scan file %s", cgPath)
		}
		text := scanner.Text()
		vals := strings.Split(text, " ")
		if len(vals) != 3 {
			return nil, errors.Errorf("unable to parse contents of file %s", cgPath)
		}
		cpu, err := strconv.ParseUint(vals[0], 10, 32)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse %s as uint32 (from %s)", vals[0], cgPath)
		}
		user, err := strconv.ParseUint(vals[1], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse %s as uint64 (from %s)", vals[1], cgPath)
		}
		sys, err := strconv.ParseUint(vals[2], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "unable to parse %s as an in (from %s)", vals[2], cgPath)
		}
		onecpu := CPUUsage{
			CPUId:         uint32(cpu),
			UserNanosec:   user,
			SystemNanosec: sys,
		}
		cpuUsage.CPUs = append(cpuUsage.CPUs, onecpu)
	}
	if len(cpuUsage.CPUs) < 1 {
		return nil, errors.Errorf("no CPU/core info extracted from %s", cgPath)
	}

	return &cpuUsage, nil
}
