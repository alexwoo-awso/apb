// Package version carries the build identity, stamped by -ldflags.
package version

import "runtime/debug"

var (
	// Version is the release tag, e.g. "2.0.0".
	Version = "2.0.6"
	// Commit is the git revision the binary was built from.
	Commit = ""
	// Date is the build timestamp in RFC3339.
	Date = ""
)

func init() {
	if Commit != "" {
		return
	}
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return
	}
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			if len(s.Value) >= 12 {
				Commit = s.Value[:12]
			} else {
				Commit = s.Value
			}
		case "vcs.time":
			Date = s.Value
		}
	}
}

// String renders a compact human readable build identity.
func String() string {
	s := Version
	if Commit != "" {
		s += " (" + Commit + ")"
	}
	return s
}
