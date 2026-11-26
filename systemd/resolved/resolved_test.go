// Copyright The Prometheus Authors
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

package resolved

import (
	"errors"
	"strings"
	"testing"

	"github.com/godbus/dbus/v5"
	"github.com/prometheus/client_golang/prometheus"
)

type fakeResolved struct {
	dbus.BusObject
	missing string
}

func (f fakeResolved) GetProperty(name string) (dbus.Variant, error) {
	if strings.HasSuffix(name, f.missing) {
		return dbus.Variant{}, errors.New("unknown property")
	}
	return dbus.MakeVariant([]any{uint64(1), uint64(2), uint64(3), uint64(4)}), nil
}

func TestCollectStatisticsReturnsPropertyErrors(t *testing.T) {
	for _, missing := range []string{"CacheStatistics", "TransactionStatistics", "DNSSECStatistics"} {
		t.Run(missing, func(t *testing.T) {
			ch := make(chan prometheus.Metric, 16)

			if err := collectStatistics(fakeResolved{missing: missing}, ch); err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}
