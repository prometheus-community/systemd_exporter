package cgroup

import (
	"errors"
	"golang.org/x/sys/unix"
	"os"
	"testing"
)

const (
	testFixturesHybrid = "fixtures/cgroup-hybrid"
)

func TestMountModeParsing(t *testing.T) {
	// This test cannot (easily) use test fixtures, because it relies on being
	// able to call Statfs on mounted filesystems. So we only run inside
	// system where we expect to find cgroupfs mounted in a mode systemd expects.
	// For now, that's only inside TravisCI, but in future we may expand to run
	// this by default on certain Linux systems
	if _, inTravisCI := os.LookupEnv("TRAVIS"); inTravisCI == false {
		return
	}

	if _, err := NewDefaultFS(); err != nil {
		t.Errorf("expected success determining mount type inside of travis CI: %s", err)
	}
}


func TestCgUnifiedCached(t *testing.T) {
	// Build some functions we will use to simulate various cgroup mounting scenarios
	noCgroupMount := func(path string, stat *unix.Statfs_t) error {
		// No fs present on /sys/fs/cgroup/
		return errors.New("boo")
	}
	unknownCgroupMount := func(path string, stat *unix.Statfs_t) error {
		// Unknown fs type present on /sys/fs/cgroup/
		stat.Type = 0x0
		return nil
	}
	unifiedMount := func(path string, stat *unix.Statfs_t) error {
		// unified fs present
		switch path {
			case "/sys/fs/cgroup/":
				stat.Type = cgroup2SuperMagic
				return nil
			default:
				return errors.New("pretend path not found")
		}
	}
	hybridMountSystemdV232 := func(path string, stat *unix.Statfs_t) error {
		switch path {
		case "/sys/fs/cgroup/":
			stat.Type = tmpFsMagic
		case "/sys/fs/cgroup/systemd/":
			stat.Type = cgroup2SuperMagic
		}
		return nil
	}
	hybridMountSystemdV233 := func(path string, stat *unix.Statfs_t) error {
		switch path {
		case "/sys/fs/cgroup/":
			stat.Type = tmpFsMagic
		case "/sys/fs/cgroup/unified/":
			stat.Type = cgroup2SuperMagic
		case "/sys/fs/cgroup/systemd/":
			stat.Type = cgroupSuperMagic
		}
		return nil
	}
	legacyMount := func(path string, stat *unix.Statfs_t) error {
		switch path {
		case "/sys/fs/cgroup/":
			stat.Type = tmpFsMagic
		case "/sys/fs/cgroup/unified/":
			return errors.New("pretend unified path not found")
		case "/sys/fs/cgroup/systemd/":
			stat.Type = cgroupSuperMagic
		}
		return nil
	}
	missingSystemdFolder := func(path string, stat *unix.Statfs_t) error {
		switch path {
		case "/sys/fs/cgroup/":
			stat.Type = tmpFsMagic
		case "/sys/fs/cgroup/unified/":
			return errors.New("pretend unified path not found")
		case "/sys/fs/cgroup/systemd/":
			return errors.New("pretend we cannot stat systemd dir")
		}
		return nil
	}
	unknownSystemdFolderMountType := func(path string, stat *unix.Statfs_t) error {
		switch path {
		case "/sys/fs/cgroup/":
			stat.Type = tmpFsMagic
		case "/sys/fs/cgroup/unified/":
			return errors.New("pretend unified path not found")
		case "/sys/fs/cgroup/systemd/":
			stat.Type = 0x0
		}
		return nil
	}

	tables := []struct {
		name         string
		statFn       func(string,*unix.Statfs_t) error
		expectedMode cgUnifiedMountMode
		errExpected  bool
	}{
		{"NoCgroupMount", noCgroupMount, unifModeUnknown, true},
		{"UnknownCgroupMountType", unknownCgroupMount, unifModeUnknown, true},
		{"LegacyMount", legacyMount, unifModeNone, false},
		{"HybridMount, v232", hybridMountSystemdV232, unifModeSystemd, false},
		{"HybridMount, v233+", hybridMountSystemdV233, unifModeSystemd, false},
		{"MissingSystemdFolder", missingSystemdFolder, unifModeUnknown, true},
		{"UnknownSystemdFolderType", unknownSystemdFolderMountType, unifModeUnknown, true},
		{"UnifiedMount", unifiedMount, unifModeAll, false},
	}

	for _, table := range tables {
		statfsFunc = table.statFn
		mode, err := cgUnifiedCached()
		if table.errExpected && err == nil {
			t.Errorf("%s: expected an err, but got mode %s with no error", table.name, mode)
		}
		if !table.errExpected && err != nil {
			t.Errorf("%s: expected no error, but got mode %s with err: %s", table.name, mode, err)
		}
		if mode != table.expectedMode {
			t.Errorf("%s: expected mode %s but got mode %s", table.name, table.expectedMode, mode)
		}
	}



}

func TestNewFS(t *testing.T) {
	if _, err := newFS("foobar", unifModeUnknown); err == nil {
		t.Error("newFS should have failed with non-existing path")
	}

	if _, err := newFS("cgroups_test.go", unifModeUnknown); err == nil {
		t.Error("want newFS to fail if mount point is not a dir")
	}

	if _, err := newFS(testFixturesHybrid, unifModeUnknown); err != nil {
		t.Error("want newFS to succeed if mount point exists")
	}
}

func getHybridFixtures(t *testing.T) FS {
	fs, err := newFS(testFixturesHybrid, unifModeSystemd)
	if err != nil {
		t.Fatal("Unable to create hybrid text fixtures")
	}
	return fs
}

func TestCgSubpath(t *testing.T) {
	fs := getHybridFixtures(t)

	fs.cgroupUnified = unifModeUnknown
	if _, err := fs.cgGetPath("cpu", "/system.slice", "cpuacct.usage_all"); err == nil {
		t.Error("should not be able to determine path with unknown mount mode")
	}
	fs.cgroupUnified = unifModeSystemd
	path, err := fs.cgGetPath("cpu", "/system.slice", "cpuacct.usage_all")
	if err != nil {
		t.Error("should be able to determine path with systemd mount mode")
	}
	want := testFixturesHybrid + "/cpu/system.slice/cpuacct.usage_all"
	if path != want {
		t.Errorf("bad response. Wanted %s, got %s", want, path)
	}
}
