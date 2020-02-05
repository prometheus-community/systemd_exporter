package cgroup

import (
	"fmt"
	"github.com/pkg/errors"
	"github.com/prometheus/common/log"
	"golang.org/x/sys/unix"
	"os"
	"path/filepath"
)

// FS is the pseudo-filesystem cgroupfs, which provides an interface to
// kernel data structures
type FS struct {
	mountPoint string

	// WARNING: We only read this data once at process start, systemd updates
	// may require restarting systemd-exporter
	cgroupUnified cgUnifiedMountMode
}

// DefaultMountPoint is the common mount point of the cgroupfs filesystem
const DefaultMountPoint = "/sys/fs/cgroup"

// NewDefaultFS returns a new cgroup FS mounted under the default mountPoint.
// It will error if cgroup hierarchies are not laid out in a manner understood
// by systemd.
func NewDefaultFS() (FS, error) {

	mode, err := cgUnifiedCached()
	if err != nil || mode == unifModeUnknown {
		return FS{}, fmt.Errorf("could not determine cgroupfs mount mode: %s", err)
	}

	return newFS(DefaultMountPoint, mode)
}

// newFS returns a new cgroup FS mounted under the given mountPoint. It does not check
// the provided mount mode
func newFS(mountPoint string, mountMode cgUnifiedMountMode) (FS, error) {
	info, err := os.Stat(mountPoint)
	if err != nil {
		return FS{}, fmt.Errorf("could not read %s: %s", mountPoint, err)
	}
	if !info.IsDir() {
		return FS{}, fmt.Errorf("mount point %s is not a directory", mountPoint)
	}
	return FS{mountPoint, mountMode}, nil
}

// path appends the given path elements to the filesystem path, adding separators
// as necessary.
func (fs FS) path(p ...string) string {
	return filepath.Join(append([]string{string(fs.mountPoint)}, p...)...)
}

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
	// hierarcy for organizing processes into control groups, but all
	// controller interaction is using v1 per-controller hierarchies.
	// a.k.a. "hybrid hierarchy"
	unifModeSystemd cgUnifiedMountMode = iota
	// unifModeAll indicates that v2 API is in full usage and there
	// are no v1 hierarchies exported. Programs (mainly container orchestrators
	// such as docker,runc,etc) that rely on v1 APIs will be broken.
	// a.k.a. "unified hierarchy"
	unifModeAll cgUnifiedMountMode = iota
)
func (c cgUnifiedMountMode) String() string {
	return [...]string{"unknown", "none", "systemd", "all"}[c]
}


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
// Equivalent to systemd cgroup-util.c#cg_unified_cached
var statfsFunc = unix.Statfs
func cgUnifiedCached() (cgUnifiedMountMode, error) {
	// if cgroupUnified != unifModeUnknown {
	// 	return cgroupUnified, nil
	// }

	var fs unix.Statfs_t
	err := statfsFunc("/sys/fs/cgroup/", &fs)
	if err != nil {
		return unifModeUnknown, errors.Wrapf(err, "failed statfs(/sys/fs/cgroup/)")
	}

	switch fs.Type {
	case cgroup2SuperMagic:
		log.Debugf("Found cgroup2 on /sys/fs/cgroup/, full unified hierarchy")
		return unifModeAll, nil
	case tmpFsMagic:
		err := statfsFunc("/sys/fs/cgroup/unified/", &fs)

		// Ignore err, we expect path to be missing on v232
		if err == nil && fs.Type == cgroup2SuperMagic {
			log.Debugf("Found cgroup2 on /sys/fs/cgroup/unified, unified hierarchy for systemd controller")
			return unifModeSystemd, nil
		}

		err = statfsFunc("/sys/fs/cgroup/systemd/", &fs)
		if err != nil {
			return unifModeUnknown, errors.Wrapf(err, "failed statfs(/sys/fs/cgroup/systemd)")
		}

		switch fs.Type {
		case cgroup2SuperMagic:
			log.Debugf("Found cgroup2 on /sys/fs/cgroup/systemd, unified hierarchy for systemd controller (v232 variant)")
			return unifModeSystemd, nil
		case cgroupSuperMagic:
			log.Debugf("Found cgroup on /sys/fs/cgroup/systemd, legacy hierarchy")
			return unifModeNone, nil
		default:
			return unifModeUnknown, errors.Errorf("unknown magic number %x for fstype returned by statfs(/sys/fs/cgroup/systemd)", fs.Type)
		}

	default:
		return unifModeUnknown, errors.Errorf("unknown magic number %x for fstype returned by statfs(/sys/fs/cgroup)", fs.Type)
	}
}

// cgGetPath returns the absolute path for a specific file in a specific controller
// in the specific cgroup denoted by the passed subpath.
// Input examples: ("cpu", "/system.slice", "cpuacct.usage_all")
func (fs FS) cgGetPath(controller string, subpath string, suffix string) (string, error) {
	// relevant systemd source code in cgroup-util.[h|c] specifically cg_get_path
	//  2. Joins controller name with base path

	if fs.cgroupUnified == unifModeUnknown {
		return "", errors.Errorf("Cannot determine path with unknown mounting hierarchy")
	}

	// TODO Ensure controller name is valid
	// TODO Convert controller name into guaranteed valid directory name
	dn := controller

	joined := ""
	switch fs.cgroupUnified {
	case unifModeNone, unifModeSystemd:
		joined = fs.path(dn, subpath, suffix)
	case unifModeAll:
		joined = fs.path(subpath, suffix)
	default:
		return "", errors.Errorf("unknown cgroup mount mode (e.g. unified mode) %d", fs.cgroupUnified)
	}
	return joined, nil
}
