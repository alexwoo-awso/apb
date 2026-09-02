// Package netutil holds the address parsing, normalisation and sanity checks
// that every ingest path in APB2 funnels through. Nothing anywhere else in the
// codebase is allowed to build an address row by hand.
package netutil

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

// ErrBogon is returned for addresses that must never reach a blocklist.
var ErrBogon = errors.New("address is private, reserved or otherwise unroutable")

// bogons are ranges we refuse to block under any circumstance. Blocking one of
// these on a router is at best useless and at worst locks the operator out.
var bogons = func() []netip.Prefix {
	raw := []string{
		// IPv4
		"0.0.0.0/8",       // this network
		"10.0.0.0/8",      // RFC1918
		"100.64.0.0/10",   // CGNAT
		"127.0.0.0/8",     // loopback
		"169.254.0.0/16",  // link local
		"172.16.0.0/12",   // RFC1918
		"192.0.0.0/24",    // IETF protocol assignments
		"192.0.2.0/24",    // TEST-NET-1
		"192.88.99.0/24",  // 6to4 relay anycast
		"192.168.0.0/16",  // RFC1918
		"198.18.0.0/15",   // benchmarking
		"198.51.100.0/24", // TEST-NET-2
		"203.0.113.0/24",  // TEST-NET-3
		"224.0.0.0/4",     // multicast
		"240.0.0.0/4",     // reserved (includes 255.255.255.255)
		// IPv6
		"::/128",        // unspecified
		"::1/128",       // loopback
		"64:ff9b::/96",  // NAT64
		"100::/64",      // discard-only
		"2001:db8::/32", // documentation
		"fc00::/7",      // unique local
		"fe80::/10",     // link local
		"ff00::/8",      // multicast
	}
	out := make([]netip.Prefix, 0, len(raw))
	for _, s := range raw {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}()

// ParseAddr accepts a textual address, trims the noise routers tend to add
// (whitespace, a trailing /32, a zone) and returns it in canonical form.
func ParseAddr(s string) (netip.Addr, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}, errors.New("empty address")
	}
	// RouterOS happily hands back "1.2.3.4/32"; treat a host prefix as a host.
	if i := strings.IndexByte(s, '/'); i >= 0 {
		host, bits := s[:i], s[i+1:]
		if bits != "32" && bits != "128" {
			return netip.Addr{}, fmt.Errorf("%q is a network, not a host address", s)
		}
		s = host
	}
	a, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, fmt.Errorf("invalid address %q", s)
	}
	return a.Unmap().WithZone(""), nil
}

// ParseBlockable parses an address and rejects anything unroutable.
func ParseBlockable(s string) (netip.Addr, error) {
	a, err := ParseAddr(s)
	if err != nil {
		return netip.Addr{}, err
	}
	if IsBogon(a) {
		return netip.Addr{}, fmt.Errorf("%s: %w", a, ErrBogon)
	}
	return a, nil
}

// IsBogon reports whether a must never be added to a blocklist.
func IsBogon(a netip.Addr) bool {
	if !a.IsValid() {
		return true
	}
	a = a.Unmap()
	for _, p := range bogons {
		if p.Addr().Is4() == a.Is4() && p.Contains(a) {
			return true
		}
	}
	return false
}

// Family returns 4 or 6.
func Family(a netip.Addr) int {
	if a.Is4() {
		return 4
	}
	return 6
}

// Bin renders an address as the fixed 16-byte key used by the database, so
// that v4 and v6 rows share one comparable, index-friendly ordering.
func Bin(a netip.Addr) []byte {
	b := a.Unmap().As16()
	return b[:]
}

// FromBin is the inverse of Bin.
func FromBin(b []byte) (netip.Addr, bool) {
	if len(b) != 16 {
		return netip.Addr{}, false
	}
	var arr [16]byte
	copy(arr[:], b)
	return netip.AddrFrom16(arr).Unmap(), true
}

// Prefix is a parsed, canonicalised CIDR ready to be stored or matched.
type Prefix struct {
	CIDR   string // canonical text, e.g. "203.0.113.0/24"
	Start  []byte // 16 bytes, inclusive
	End    []byte // 16 bytes, inclusive
	Bits   int    // prefix length in its own family
	Family int    // 4 or 6
	One    bool   // true when the prefix covers exactly one address
}

// ParsePrefix accepts either a bare address or a CIDR and returns its
// inclusive 16-byte range. A bare address becomes a /32 or /128.
func ParsePrefix(s string) (Prefix, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return Prefix{}, errors.New("empty network")
	}
	var p netip.Prefix
	if strings.ContainsRune(s, '/') {
		var err error
		p, err = netip.ParsePrefix(s)
		if err != nil {
			return Prefix{}, fmt.Errorf("invalid network %q", s)
		}
		p = p.Masked()
	} else {
		a, err := netip.ParseAddr(s)
		if err != nil {
			return Prefix{}, fmt.Errorf("invalid address %q", s)
		}
		a = a.Unmap().WithZone("")
		p = netip.PrefixFrom(a, a.BitLen())
	}
	addr := p.Addr().Unmap().WithZone("")
	p = netip.PrefixFrom(addr, p.Bits())

	start := addr.As16()
	end := start
	// The 16-byte form of a v4 prefix keeps the ::ffff: header intact, so the
	// host bits we need to flood always live in the trailing bytes.
	hostBits := addr.BitLen() - p.Bits()
	for i := 0; i < hostBits; i++ {
		byteIdx := 15 - i/8
		end[byteIdx] |= 1 << (i % 8)
	}
	return Prefix{
		CIDR:   p.String(),
		Start:  start[:],
		End:    end[:],
		Bits:   p.Bits(),
		Family: Family(addr),
		One:    p.Bits() == addr.BitLen(),
	}, nil
}

// Contains reports whether the prefix covers addr.
func (p Prefix) Contains(a netip.Addr) bool {
	b := Bin(a)
	return string(b) >= string(p.Start) && string(b) <= string(p.End)
}

// SplitList pulls addresses out of the compact wire format the routers speak:
// commas, whitespace and newlines are all accepted as separators, and empty
// fields are skipped. Duplicates are preserved; the caller dedupes.
func SplitList(body string) []string {
	fields := strings.FieldsFunc(body, func(r rune) bool {
		return r == ',' || r == '\n' || r == '\r' || r == ' ' || r == '\t' || r == ';'
	})
	out := fields[:0]
	for _, f := range fields {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}
