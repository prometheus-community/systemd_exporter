package cgroup

import "testing"

const (
	testFixturesHybrid = "fixtures/cgroup-hybrid"
)

func TestNewFS(t *testing.T) {
	if _, err := newFS("foobar", unifModeUnknown); err == nil {
		t.Error("want newFS to fail for non-existing path")
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
	if _,err := fs.cgGetPath("cpu", "/system.slice", "cpuacct.usage_all"); err == nil {
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

func TestRootCPUAcct(t *testing.T) {
	fs := getHybridFixtures(t)
	cpu, err := fs.NewCPUAcct("/")
	if err != nil {
		t.Error("want NewCPUAcct('/') to succeed")
	}

	if len(cpu.CPUs) != 4 {
		t.Errorf("Wrong number of CPUs. Wanted %d got %d", 4, len(cpu.CPUs))
	}

	var expectedUser uint64 = 29531441016368
	if cpu.UsageUserNanosecs() != expectedUser {
		t.Errorf("Wrong user nanoseconds. Wanted %d got %d", expectedUser, cpu.UsageUserNanosecs())
	}

	var expectedSys uint64 = 619186701953
	if cpu.UsageSystemNanosecs() != expectedSys {
		t.Errorf("Wrong sys nanoseconds. Wanted %d got %d",expectedSys, cpu.UsageSystemNanosecs())
	}

	expectedTotal := expectedSys + expectedUser
	if cpu.UsageAllNanosecs() != expectedTotal {
		t.Errorf("Wrong total nanoseconds. Wanted %d got %d",expectedTotal, cpu.UsageAllNanosecs())
	}
}
