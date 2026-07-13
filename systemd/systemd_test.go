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

package systemd

import "testing"

func TestParseSystemdVersion(t *testing.T) {
	cases := []struct {
		name        string
		raw         string
		wantNum     float64
		wantVersion string
	}{
		{"plain quoted", `"255"`, 255, "255"},
		{"minor version", `"255.4"`, 255.4, "255.4"},
		{"distro suffix", `"255.4-1ubuntu8.6"`, 255.4, "255.4-1ubuntu8.6"},
		{"parenthesised full string", `"249 (249.11-0ubuntu3.12)"`, 249, "249 (249.11-0ubuntu3.12)"},
		{"unquoted", "252", 252, "252"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			num, version, err := parseSystemdVersion(tc.raw)
			if err != nil {
				t.Fatalf("parseSystemdVersion(%q) unexpected error: %v", tc.raw, err)
			}
			if num != tc.wantNum {
				t.Errorf("num = %v, want %v", num, tc.wantNum)
			}
			if version != tc.wantVersion {
				t.Errorf("version = %q, want %q", version, tc.wantVersion)
			}
		})
	}
}

func TestParseSystemdVersionErrors(t *testing.T) {
	// No 3+ digit version number to parse -> error rather than a bogus 0 metric.
	for _, raw := range []string{`""`, `"unknown"`, "", "v42"} {
		t.Run(raw, func(t *testing.T) {
			if _, _, err := parseSystemdVersion(raw); err == nil {
				t.Errorf("parseSystemdVersion(%q) expected error, got nil", raw)
			}
		})
	}
}
