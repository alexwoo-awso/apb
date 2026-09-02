package netutil

import (
	"net/netip"
	"testing"
)

func TestParseBlockableAcceptsRoutableHosts(t *testing.T) {
	cases := map[string]string{
		"45.83.64.7":           "45.83.64.7",
		"  45.83.64.7  ":       "45.83.64.7",
		"45.83.64.7/32":        "45.83.64.7",
		"2001:4860:4860::8888": "2001:4860:4860::8888",
		"::ffff:45.83.64.7":    "45.83.64.7",
	}
	for in, want := range cases {
		a, err := ParseBlockable(in)
		if err != nil {
			t.Errorf("%q: %v", in, err)
			continue
		}
		if a.String() != want {
			t.Errorf("%q normalised to %q, want %q", in, a.String(), want)
		}
	}
}

func TestParseBlockableRejectsWhatMustNeverBeBlocked(t *testing.T) {
	// Blocking any of these on a router is at best useless and at worst locks
	// the operator out of their own network.
	for _, in := range []string{
		"10.0.0.1", "192.168.1.1", "172.16.5.5", "127.0.0.1", "169.254.1.1",
		"100.64.0.1", "224.0.0.1", "255.255.255.255", "0.0.0.0",
		"192.0.2.1", "198.51.100.1", "203.0.113.1", "198.18.0.1",
		"::1", "fe80::1", "fc00::1", "ff02::1", "2001:db8::1",
		"45.83.64.0/24", "not an address", "", "1.2.3.4.5",
	} {
		if a, err := ParseBlockable(in); err == nil {
			t.Errorf("%q was accepted as %s", in, a)
		}
	}
}

func TestBinIsAlwaysSixteenBytesAndOrders(t *testing.T) {
	lo := Bin(netip.MustParseAddr("45.83.64.7"))
	hi := Bin(netip.MustParseAddr("45.83.64.8"))
	if len(lo) != 16 || len(hi) != 16 {
		t.Fatal("binary form is not 16 bytes")
	}
	if string(lo) >= string(hi) {
		t.Error("binary form does not sort in address order")
	}
	back, ok := FromBin(lo)
	if !ok || back.String() != "45.83.64.7" {
		t.Errorf("round trip failed: %v %v", back, ok)
	}
}

func TestParsePrefixRanges(t *testing.T) {
	p, err := ParsePrefix("45.83.64.0/24")
	if err != nil {
		t.Fatal(err)
	}
	if p.CIDR != "45.83.64.0/24" || p.Bits != 24 || p.Family != 4 || p.One {
		t.Fatalf("unexpected prefix: %+v", p)
	}
	for _, in := range []string{"45.83.64.0", "45.83.64.7", "45.83.64.255"} {
		if !p.Contains(netip.MustParseAddr(in)) {
			t.Errorf("%s should be inside %s", in, p.CIDR)
		}
	}
	for _, out := range []string{"45.83.63.255", "45.83.65.0", "2001:db8::1"} {
		if p.Contains(netip.MustParseAddr(out)) {
			t.Errorf("%s should be outside %s", out, p.CIDR)
		}
	}

	// A host address becomes a single-address prefix.
	one, err := ParsePrefix("45.83.64.7")
	if err != nil {
		t.Fatal(err)
	}
	if !one.One || one.CIDR != "45.83.64.7/32" {
		t.Errorf("host prefix wrong: %+v", one)
	}

	// Host bits are masked off rather than rejected.
	masked, err := ParsePrefix("45.83.64.7/24")
	if err != nil || masked.CIDR != "45.83.64.0/24" {
		t.Errorf("prefix not canonicalised: %+v %v", masked, err)
	}

	v6, err := ParsePrefix("2001:db8::/32")
	if err != nil || v6.Family != 6 || v6.Bits != 32 {
		t.Fatalf("v6 prefix wrong: %+v %v", v6, err)
	}
	if !v6.Contains(netip.MustParseAddr("2001:db8:ffff::1")) {
		t.Error("v6 range does not cover its own addresses")
	}
	if v6.Contains(netip.MustParseAddr("2001:db9::1")) {
		t.Error("v6 range is too wide")
	}
}

func TestSplitListHandlesRouterOutput(t *testing.T) {
	got := SplitList("45.83.64.7,91.240.118.3\n 8.8.8.8\t1.1.1.1;9.9.9.9,,\r\n")
	want := []string{"45.83.64.7", "91.240.118.3", "8.8.8.8", "1.1.1.1", "9.9.9.9"}
	if len(got) != len(want) {
		t.Fatalf("got %d fields %v, want %d", len(got), got, len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("field %d: got %q want %q", i, got[i], want[i])
		}
	}
	if n := len(SplitList("   ,,\n\t")); n != 0 {
		t.Errorf("empty input produced %d fields", n)
	}
}
