package cgroup

import (
	"bufio"
	"bytes"
	"github.com/pkg/errors"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"
)

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

// NewCPUAcct will locate and read the kernel's cpu accounting info for
// the provided systemd cgroup subpath.
func NewCPUAcct(cgSubpath string) (*CPUAcct, error) {
	fs, err := NewDefaultFS()
	if err != nil {
		return nil, err
	}
	return fs.NewCPUAcct(cgSubpath)
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
func (fs FS) NewCPUAcct(cgSubpath string) (*CPUAcct, error) {
	var cpuUsage CPUAcct

	cgPath, err := fs.cgGetPath("cpu", cgSubpath, "cpuacct.usage_all")
	if err != nil {
		return nil, errors.Wrapf(err, "unable to get cpu controller path")
	}

	// Example cpuacct.usage_all
	// cpu user system
	// 0 21165924 0
	// 1 13334251 0
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
