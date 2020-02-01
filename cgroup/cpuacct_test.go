package cgroup

import "testing"


func TestNewCPUAcct(t *testing.T) {
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

	if _, err := fs.NewCPUAcct("foobar"); err == nil {
		t.Errorf("expected error getting cpu accounting info for bogus cgroup")
	}
}


