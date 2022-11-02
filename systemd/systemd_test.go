package systemd

import (
	"github.com/coreos/go-systemd/dbus"
	"testing"
)

func TestParseUnitType(t *testing.T) {
	x := dbus.UnitStatus{
		Name:        "test.service",
		Description: "",
		LoadState:   "",
		ActiveState: "",
		SubState:    "",
		Followed:    "",
		Path:        "",
		JobId:       0,
		JobType:     "",
		JobPath:     "",
	}
	found := parseUnitType(x)
	if found != "service" {
		t.Errorf("Bad unit name parsing. Wanted %s got %s", "service", found)
	}

}
