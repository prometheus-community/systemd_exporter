package cgroup

import (
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


