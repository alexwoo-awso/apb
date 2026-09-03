package syncapi

import (
	"net/http"
	"testing"
)

// agentMatches is the gate that decides whether a router's request is even
// looked at. Getting it wrong takes an estate offline with a 401 that looks
// exactly like a bad token, so its exact behaviour is pinned here.
func TestAgentMatches(t *testing.T) {
	cases := []struct {
		name      string
		agents    []string
		dedicated string
		want      string
		ok        bool
	}{
		{"exact match", []string{"apb-router"}, "", "apb-router", true},
		{"different value", []string{"curl/8.5.0"}, "", "apb-router", false},
		{"no header at all", nil, "", "apb-router", false},
		{"empty header value", []string{""}, "", "apb-router", false},
		{"case differs", []string{"APB-Router"}, "", "apb-router", false},
		{"substring is not a match", []string{"apb-router/2"}, "", "apb-router", false},
		// A client may append its own identity alongside the one a script asked
		// for. Rejecting a header it did send would be wrong.
		{"present among several", []string{"MikroTik/6.49.20", "apb-router"}, "", "apb-router", true},
		{"absent among several", []string{"MikroTik/6.49.20", "something"}, "", "apb-router", false},
		// RouterOS sends its own User-Agent regardless of what a script asks
		// for, so the dedicated header is the channel that actually works.
		{"dedicated header carries it", []string{"Mikrotik/6.x Fetch"}, "apb-router", "apb-router", true},
		{"dedicated header wrong", []string{"Mikrotik/6.x Fetch"}, "something", "apb-router", false},
		{"dedicated header alone", nil, "apb-router", "apb-router", true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r, err := http.NewRequest(http.MethodGet, "http://example.org/", nil)
			if err != nil {
				t.Fatal(err)
			}
			r.Header.Del("User-Agent")
			for _, a := range tc.agents {
				r.Header.Add("User-Agent", a)
			}
			if tc.dedicated != "" {
				r.Header.Set(AgentHeader, tc.dedicated)
			}
			if got := agentMatches(r, tc.want); got != tc.ok {
				t.Errorf("agentMatches(%q, %q) = %v, want %v", tc.agents, tc.want, got, tc.ok)
			}
		})
	}
}
