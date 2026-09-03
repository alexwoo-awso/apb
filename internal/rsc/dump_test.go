package rsc

import (
	"os"
	"path/filepath"
	"testing"
)

// TestDumpBundle writes a sample bundle to APB_RSC_DUMP for eyeballing the
// generated RouterOS code. It is a no-op unless that variable is set.
func TestDumpBundle(t *testing.T) {
	dir := os.Getenv("APB_RSC_DUMP")
	if dir == "" {
		t.Skip("set APB_RSC_DUMP to a directory to write sample scripts")
	}
	for _, tc := range []struct {
		name   string
		branch string
		ipv6   bool
	}{{"v7", "v7", false}, {"v7-ipv6", "v7", true}, {"v6", "v6", false}} {
		d := testDevice()
		d.ROSBranch = tc.branch
		d.BlockTimeout = DefaultBlockTimeout(tc.branch)
		d.IPv6 = tc.ipv6
		if tc.branch == "v6" {
			d.VerifyCert = "no"
		}
		b, err := Generate(FromDevice(d, "https://apb.example.org", "APB", "apb_SAMPLETOKENONLY000000", "apb-router"))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		for part, body := range map[string]string{
			"install": b.Install, "scripts": b.Scripts, "scheduler": b.Scheduler,
			"uninstall": b.Uninstall, "firewall": b.Firewall,
		} {
			p := filepath.Join(dir, tc.name+"-"+part+".rsc")
			if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
				t.Fatal(err)
			}
		}
	}
}
