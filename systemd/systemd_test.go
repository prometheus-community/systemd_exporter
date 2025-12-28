// Copyright 2022 The Prometheus Authors
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

package systemd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"sync"
	"testing"

	"github.com/coreos/go-systemd/v22/dbus"
	godbus "github.com/godbus/dbus/v5"
)

// Mock dbus connection for testing
type mockDbusConn struct {
	sliceMap map[string]string // unit name -> slice name
}

func (m *mockDbusConn) GetUnitPropertyContext(ctx context.Context, unit string, prop string) (*dbus.Property, error) {
	if prop == "Slice" {
		if slice, ok := m.sliceMap[unit]; ok {
			return &dbus.Property{
				Name:  "Slice",
				Value: godbus.MakeVariant(slice),
			}, nil
		}
		return nil, fmt.Errorf("unit %s not found in mock", unit)
	}
	return nil, fmt.Errorf("property %s not mocked", prop)
}

func (m *mockDbusConn) GetUnitTypePropertiesContext(ctx context.Context, unit string, unitType string) (map[string]interface{}, error) {
	if slice, ok := m.sliceMap[unit]; ok {
		return map[string]interface{}{
			"Slice": slice,
		}, nil
	}
	// Return empty map for units not in sliceMap (they might not have a Slice property)
	return map[string]interface{}{}, nil
}

// Test fixtures
var (
	testUnits = []dbus.UnitStatus{
		{Name: "example.service", LoadState: "loaded"},
		{Name: "other.service", LoadState: "loaded"},
		{Name: "foo.service", LoadState: "loaded"},
		{Name: "bar.timer", LoadState: "loaded"},
		{Name: "baz.service", LoadState: "loaded"},
		{Name: "unloaded.service", LoadState: "not-found"},
	}
)

// Helper to create a Collector with specific filter rules
func createTestCollector(filterRules []FilterRule) *Collector {
	// Create a test logger that discards output
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))

	return &Collector{
		ctx:          context.Background(),
		logger:       logger,
		filterRules:  filterRules,
		sliceCache:   make(map[string]string),
		sliceCacheMu: sync.RWMutex{},
	}
}

// Helper to create a mock dbus connection with slice mappings
func createMockConn(sliceMap map[string]string) *mockDbusConn {
	return &mockDbusConn{sliceMap: sliceMap}
}

// Test slice-include filtering
func TestFilterUnits_SliceInclude(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
		"foo.service":     "system.slice",
		"bar.timer":       "system.slice",
		"baz.service":     "system.slice",
	}
	mockConn := createMockConn(sliceMap)

	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "example"},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// Should only include example.service
	if len(filtered) != 1 {
		t.Errorf("Expected 1 unit, got %d", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Name != "example.service" {
		t.Errorf("Expected example.service, got %s", filtered[0].Name)
	}
}

// Test slice-exclude filtering
func TestFilterUnits_SliceExclude(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
		"foo.service":     "system.slice",
		"bar.timer":       "system.slice",
		"baz.service":     "system.slice",
	}
	mockConn := createMockConn(sliceMap)

	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionExclude, Pattern: "system"},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// Should only include example.service (not in system.slice)
	if len(filtered) != 1 {
		t.Errorf("Expected 1 unit, got %d", len(filtered))
	}
	if len(filtered) > 0 && filtered[0].Name != "example.service" {
		t.Errorf("Expected example.service, got %s", filtered[0].Name)
	}
}

// Test multiple slice-include filters
func TestFilterUnits_SliceIncludeMultiple(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
		"foo.service":     "custom.slice",
		"bar.timer":       "system.slice",
		"baz.service":     "system.slice",
	}
	mockConn := createMockConn(sliceMap)

	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "example"},
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "custom"},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// Should include example.service and foo.service
	if len(filtered) != 2 {
		t.Errorf("Expected 2 units, got %d", len(filtered))
	}

	names := make(map[string]bool)
	for _, unit := range filtered {
		names[unit.Name] = true
	}

	if !names["example.service"] || !names["foo.service"] {
		t.Errorf("Expected example.service and foo.service, got %v", names)
	}
}

// Test slice name format matching (with and without .slice suffix)
func TestFilterUnits_SliceNameFormats(t *testing.T) {
	tests := []struct {
		name          string
		sliceMap      map[string]string
		filterPattern string
		expectedUnits []string
	}{
		{
			name: "Match without .slice suffix",
			sliceMap: map[string]string{
				"example.service": "example.slice",
				"other.service":   "system.slice",
			},
			filterPattern: "example",
			expectedUnits: []string{"example.service"},
		},
		{
			name: "Match with .slice suffix in filter",
			sliceMap: map[string]string{
				"example.service": "example.slice",
				"other.service":   "system.slice",
			},
			filterPattern: "example.slice",
			expectedUnits: []string{"example.service"},
		},
		{
			name: "Match when systemd returns name without suffix",
			sliceMap: map[string]string{
				"example.service": "example",
				"other.service":   "system",
			},
			filterPattern: "example",
			expectedUnits: []string{"example.service"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockConn := createMockConn(tt.sliceMap)
			filterRules := []FilterRule{
				{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: tt.filterPattern},
			}

			collector := createTestCollector(filterRules)
			filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

			if len(filtered) != len(tt.expectedUnits) {
				t.Errorf("Expected %d units, got %d", len(tt.expectedUnits), len(filtered))
			}

			for i, expectedName := range tt.expectedUnits {
				if i >= len(filtered) || filtered[i].Name != expectedName {
					t.Errorf("Expected unit %s, got %v", expectedName, filtered)
				}
			}
		})
	}
}

// CRITICAL: Test order precedence - slice-exclude then unit-include
func TestFilterUnits_SliceExcludeThenUnitInclude(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
		"foo.service":     "example.slice",
		"bar.timer":       "system.slice",
		"baz.service":     "system.slice",
	}
	mockConn := createMockConn(sliceMap)

	// First exclude example slice, then include example.service specifically
	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionExclude, Pattern: "example"},
		{Type: FilterTypeUnit, Action: FilterActionInclude, Pattern: regexp.MustCompile("^(?:example\\.service)$")},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// example.service should be INCLUDED (unit-include overrides slice-exclude)
	// other.service should be INCLUDED (in system.slice, not excluded)
	// foo.service should be EXCLUDED (in example.slice, not specifically included)
	// bar.timer should be INCLUDED (in system.slice, not excluded)
	// baz.service should be INCLUDED (in system.slice, not excluded)

	expectedUnits := map[string]bool{
		"example.service": true,
		"other.service":   true,
		"bar.timer":       true,
		"baz.service":     true,
	}

	if len(filtered) != len(expectedUnits) {
		t.Errorf("Expected %d units, got %d: %v", len(expectedUnits), len(filtered), filtered)
	}

	for _, unit := range filtered {
		if !expectedUnits[unit.Name] {
			t.Errorf("Unexpected unit in result: %s", unit.Name)
		}
	}
}

// CRITICAL: Test order precedence - slice-include then unit-exclude
func TestFilterUnits_SliceIncludeThenUnitExclude(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
		"foo.service":     "example.slice",
		"bar.timer":       "system.slice",
		"baz.service":     "example.slice",
	}
	mockConn := createMockConn(sliceMap)

	// First include example slice, then exclude example.service specifically
	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "example"},
		{Type: FilterTypeUnit, Action: FilterActionExclude, Pattern: regexp.MustCompile("^(?:example\\.service)$")},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// example.service should be EXCLUDED (unit-exclude overrides slice-include)
	// foo.service should be INCLUDED (in example.slice, included by first rule)
	// baz.service should be INCLUDED (in example.slice, included by first rule)

	expectedUnits := map[string]bool{
		"foo.service": true,
		"baz.service": true,
	}

	if len(filtered) != len(expectedUnits) {
		t.Errorf("Expected %d units, got %d: %v", len(expectedUnits), len(filtered), filtered)
	}

	for _, unit := range filtered {
		if !expectedUnits[unit.Name] {
			t.Errorf("Unexpected unit in result: %s", unit.Name)
		}
	}
}

// CRITICAL: Test order precedence - unit-include then slice-exclude
func TestFilterUnits_UnitIncludeThenSliceExclude(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
		"foo.service":     "example.slice",
		"bar.timer":       "system.slice",
		"baz.service":     "example.slice",
	}
	mockConn := createMockConn(sliceMap)

	// First include example.service, then exclude example slice
	filterRules := []FilterRule{
		{Type: FilterTypeUnit, Action: FilterActionInclude, Pattern: regexp.MustCompile("^(?:example\\.service)$")},
		{Type: FilterTypeSlice, Action: FilterActionExclude, Pattern: "example"},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// example.service should be EXCLUDED (slice-exclude is later)
	// other.service should be INCLUDED (default, not in example.slice)
	// foo.service should be EXCLUDED (in example.slice)
	// bar.timer should be INCLUDED (in system.slice, not excluded)
	// baz.service should be EXCLUDED (in example.slice)

	expectedUnits := map[string]bool{
		"other.service": true,
		"bar.timer":     true,
	}

	if len(filtered) != len(expectedUnits) {
		t.Errorf("Expected %d units, got %d: %v", len(expectedUnits), len(filtered), filtered)
	}

	for _, unit := range filtered {
		if !expectedUnits[unit.Name] {
			t.Errorf("Unexpected unit in result: %s", unit.Name)
		}
	}
}

// CRITICAL: Test complex multi-rule scenario
func TestFilterUnits_MultipleRulesComplex(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
		"foo.service":     "custom.slice",
		"bar.timer":       "system.slice",
		"baz.service":     "example.slice",
	}
	mockConn := createMockConn(sliceMap)

	// Complex scenario:
	// 1. Include example slice
	// 2. Exclude *.timer units
	// 3. Exclude system slice
	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "example"},
		{Type: FilterTypeUnit, Action: FilterActionExclude, Pattern: regexp.MustCompile("^(?:.*\\.timer)$")},
		{Type: FilterTypeSlice, Action: FilterActionExclude, Pattern: "system"},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// example.service: in example.slice (included by rule 1) -> INCLUDED
	// baz.service: in example.slice (included by rule 1) -> INCLUDED
	// other.service: in system.slice (excluded by rule 3) -> EXCLUDED
	// bar.timer: matches *.timer (excluded by rule 2) -> EXCLUDED
	// foo.service: in custom.slice (default include, not affected by rules) -> INCLUDED

	expectedUnits := map[string]bool{
		"example.service": true,
		"baz.service":     true,
		"foo.service":     true,
	}

	if len(filtered) != len(expectedUnits) {
		t.Errorf("Expected %d units, got %d: %v", len(expectedUnits), len(filtered), filtered)
	}

	for _, unit := range filtered {
		if !expectedUnits[unit.Name] {
			t.Errorf("Unexpected unit in result: %s", unit.Name)
		}
	}
}

// Edge case: Units without Slice property
func TestFilterUnits_NoSliceProperty(t *testing.T) {
	// Mock returns error for units without slice
	sliceMap := map[string]string{
		// example.service has no slice property (will error)
		"other.service": "system.slice",
	}
	mockConn := createMockConn(sliceMap)

	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "example"},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// Units without slice property should not match slice filters
	// Since we're including only "example" slice, and example.service has no slice,
	// it should not be included
	for _, unit := range filtered {
		if unit.Name == "example.service" {
			t.Errorf("example.service should not be included (no slice property)")
		}
	}
}

// Edge case: Empty filter rules (default behavior)
func TestFilterUnits_EmptyFilterRules(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
	}
	mockConn := createMockConn(sliceMap)

	filterRules := []FilterRule{} // Empty rules

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// With no filter rules, all loaded units should be included
	expectedCount := 0
	for _, unit := range testUnits {
		if unit.LoadState == "loaded" {
			expectedCount++
		}
	}

	if len(filtered) != expectedCount {
		t.Errorf("Expected %d units (all loaded), got %d", expectedCount, len(filtered))
	}
}

// Edge case: Unloaded units should always be excluded
func TestFilterUnits_UnloadedUnits(t *testing.T) {
	sliceMap := map[string]string{
		"unloaded.service": "example.slice",
		"example.service":  "example.slice",
	}
	mockConn := createMockConn(sliceMap)

	// Include example slice - but unloaded.service should still be excluded
	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "example"},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// unloaded.service should NOT appear in results
	for _, unit := range filtered {
		if unit.Name == "unloaded.service" {
			t.Errorf("unloaded.service should never be included")
		}
		if unit.LoadState != "loaded" {
			t.Errorf("Unit %s with LoadState=%s should not be included", unit.Name, unit.LoadState)
		}
	}
}

// Edge case: Same slice included and excluded
func TestFilterUnits_SliceIncludeAndExcludeSameSlice(t *testing.T) {
	sliceMap := map[string]string{
		"example.service": "example.slice",
		"other.service":   "system.slice",
	}
	mockConn := createMockConn(sliceMap)

	// Include then exclude same slice - exclude should win (it's later)
	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "example"},
		{Type: FilterTypeSlice, Action: FilterActionExclude, Pattern: "example"},
	}

	collector := createTestCollector(filterRules)
	filtered := collector.filterUnitsOrderAware(testUnits, mockConn)

	// example.service should be EXCLUDED (last rule wins)
	for _, unit := range filtered {
		if unit.Name == "example.service" {
			t.Errorf("example.service should be excluded (exclude is later)")
		}
	}
}

// Test slice cache functionality
func TestSliceCache_Caching(t *testing.T) {
	callCount := 0
	sliceMap := map[string]string{
		"example.service": "example.slice",
	}

	// We can't easily mock the call count with current structure,
	// but we can verify cache is populated
	mockConn := createMockConn(sliceMap)
	filterRules := []FilterRule{
		{Type: FilterTypeSlice, Action: FilterActionInclude, Pattern: "example"},
	}

	collector := createTestCollector(filterRules)

	// First call - should populate cache
	_ = collector.getUnitSlice(testUnits[0], mockConn)

	// Verify cache contains the entry
	collector.sliceCacheMu.RLock()
	cachedSlice, exists := collector.sliceCache["example.service"]
	collector.sliceCacheMu.RUnlock()

	if !exists {
		t.Errorf("Expected cache to contain example.service")
	}

	if cachedSlice != "example.slice" {
		t.Errorf("Expected cached slice to be 'example.slice', got '%s'", cachedSlice)
	}

	// Second call - should use cache
	slice := collector.getUnitSlice(testUnits[0], mockConn)
	if slice != "example.slice" {
		t.Errorf("Expected slice from cache to be 'example.slice', got '%s'", slice)
	}

	_ = callCount // Suppress unused variable warning
}

// Test backward compatibility - legacy filtering should still work
func TestFilterUnits_LegacyFiltering(t *testing.T) {
	// Test the original filterUnits function still works
	unitIncludePattern := regexp.MustCompile("^(?:.+)$")
	unitExcludePattern := regexp.MustCompile("^(?:.+\\.(device))$")

	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
	collector := &Collector{logger: logger}

	testUnitsLegacy := []dbus.UnitStatus{
		{Name: "example.service", LoadState: "loaded"},
		{Name: "other.device", LoadState: "loaded"},
		{Name: "foo.service", LoadState: "loaded"},
	}

	filtered := collector.filterUnits(testUnitsLegacy, unitIncludePattern, unitExcludePattern)

	// Should exclude *.device units
	for _, unit := range filtered {
		if unit.Name == "other.device" {
			t.Errorf("Legacy filtering should exclude *.device units")
		}
	}

	// Should include .service units
	expectedUnits := map[string]bool{
		"example.service": true,
		"foo.service":     true,
	}

	if len(filtered) != len(expectedUnits) {
		t.Errorf("Expected %d units, got %d", len(expectedUnits), len(filtered))
	}
}
