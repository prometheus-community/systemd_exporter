package systemd

import (
	"bufio"
	"bytes"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/pkg/errors"
	"github.com/prometheus/common/log"
)

type CPUUsageOne struct {
	cpu_id             uint32
	usage_sys_nanosec  uint64
	usage_user_nanosec uint64
}

// Holds contents of /sys/fs/cgroup/..../cpuacct.usage_all
type CPUAcct struct {
	cpu []CPUUsageOne
}

func (c *CPUAcct) usage_user_nanosec() uint64 {
	var all uint64
	for _, cpu := range c.cpu {
		all += cpu.usage_user_nanosec
	}
	return all
}

func (c *CPUAcct) usage_sys_nanosec() uint64 {
	var all uint64
	for _, cpu := range c.cpu {
		all += cpu.usage_sys_nanosec
	}
	return all
}

func (c *CPUAcct) usage_all_nanosec() uint64 {
	var all uint64
	for _, cpu := range c.cpu {
		all += cpu.usage_sys_nanosec + cpu.usage_user_nanosec
	}
	return all
}

// COPIED FROM prometheus/procfs WHICH ALSO USES APACHE 2.0
// ReadFileNoStat uses ioutil.ReadAll to read contents of entire file.
// This is similar to ioutil.ReadFile but without the call to os.Stat, because
// many files in /proc and /sys report incorrect file sizes (either 0 or 4096).
// Reads a max file size of 512kB.  For files larger than this, a scanner
// should be used.
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

func cg_NewCPUAcct(cg_sub_path string) (*CPUAcct, error) {

	var cpuUsage CPUAcct
	var cpuTest CPUUsageOne

	var cg_path = "/sys/fs/cgroup/cpu" + cg_sub_path + "/cpuacct.usage_all"
	log.Debugf("CPU hierarchy path %s", cg_path)

	cpuTest.cpu_id = 0

	// Example cpuacct.usage_all
	// cpu user system
	// 0 21165924 0
	// 1 13334251 0
	b, err := ReadFileNoStat(cg_path)
	if err != nil {
		return nil, errors.Wrapf(err, "Unable to read file %s", cg_path)
	}

	scanner := bufio.NewScanner(bytes.NewReader(b))
	scanner.Scan()
	for scanner.Scan() {
		text := scanner.Text()
		vals := strings.Split(text, " ")
		if len(vals) != 3 {
			return nil, errors.Wrapf(err, "Unable to parse contents of file %s", cg_path)
		}
		cpu, err := strconv.ParseUint(vals[0], 10, 32)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to parse %s as uint32 (from %s)", vals[0], cg_path)
		}
		user, err := strconv.ParseUint(vals[1], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to parse %s as uint64 (from %s)", vals[1], cg_path)
		}
		sys, err := strconv.ParseUint(vals[2], 10, 64)
		if err != nil {
			return nil, errors.Wrapf(err, "Unable to parse %s as an in (from %s)", vals[2], cg_path)
		}
		var onecpu CPUUsageOne
		onecpu.cpu_id = uint32(cpu)
		onecpu.usage_user_nanosec = user
		onecpu.usage_sys_nanosec = sys
		cpuUsage.cpu = append(cpuUsage.cpu, onecpu)
	}
	if len(cpuUsage.cpu) < 1 {
		return nil, errors.Wrapf(err, "Found no CPUs information inside %s", cg_path)
	}

	return &cpuUsage, nil
}
