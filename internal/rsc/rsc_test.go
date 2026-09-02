package rsc

import (
	"strings"
	"testing"

	"github.com/alexwoo-awso/apb/internal/model"
)

func testDevice() model.Device {
	return model.Device{
		Name:           "edge-1",
		ROSBranch:      "v7",
		ListName:       "APB",
		DetectList:     "APB_detect",
		BlockTimeout:   "520w",
		VerifyCert:     "yes-without-crl",
		SyncInterval:   15,
		ReportInterval: 300,
	}
}

func TestGenerateProducesEveryFile(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	for name, body := range map[string]string{
		"scripts":   b.Scripts,
		"scheduler": b.Scheduler,
		"install":   b.Install,
		"uninstall": b.Uninstall,
		"firewall":  b.Firewall,
	} {
		if strings.TrimSpace(body) == "" {
			t.Errorf("%s is empty", name)
		}
	}
	for _, want := range []string{"apb-sync", "apb-bootstrap", "apb-report", "apb-purge"} {
		if !strings.Contains(b.Scripts, `name="`+want+`"`) {
			t.Errorf("scripts missing %s", want)
		}
	}
	if !strings.Contains(b.Scheduler, "interval=15s") {
		t.Error("scheduler does not use the device sync interval")
	}
	if !strings.Contains(b.Scheduler, "start-time=startup") {
		t.Error("scheduler does not arm the reboot rebuild")
	}
}

// The whole point of the rework: nothing the router adds may be written to
// flash, which in RouterOS means every address-list entry carries a timeout.
func TestEveryAddressListAddCarriesATimeout(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	body := b.Install
	for i := 0; ; {
		j := strings.Index(body[i:], "address-list add")
		if j < 0 {
			break
		}
		start := i + j
		end := start + strings.Index(body[start:], "on-error")
		if end < start {
			end = len(body)
		}
		if !strings.Contains(body[start:end], "timeout=") {
			t.Fatalf("address-list add without a timeout near: %.120s", body[start:])
		}
		i = start + len("address-list add")
	}
}

func TestGeneratedSourceIsBalanced(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	// Unescape the wrapped source back to the script body and check that the
	// RouterOS block structure is balanced, which is the failure mode a typo
	// in a template would produce.
	for _, line := range strings.Split(b.Scripts, "\n") {
		_ = line
	}
	body := unwrap(b.Scripts)
	if depth := braceDepth(body); depth != 0 {
		t.Errorf("unbalanced braces in generated scripts: depth %d", depth)
	}
}

func unwrap(s string) string {
	s = strings.ReplaceAll(s, "\\\n    ", "")
	s = strings.ReplaceAll(s, `\r\n`, "\n")
	s = strings.ReplaceAll(s, `\"`, `"`)
	s = strings.ReplaceAll(s, `\$`, `$`)
	s = strings.ReplaceAll(s, `\?`, `?`)
	return s
}

func braceDepth(s string) int {
	depth, inString := 0, false
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			i++
		case '"':
			inString = !inString
		case '{':
			if !inString {
				depth++
			}
		case '}':
			if !inString {
				depth--
			}
		}
	}
	return depth
}

func TestValidationRejectsUnsafeInput(t *testing.T) {
	base := testDevice()
	cases := map[string]func(*model.Device){
		"list name with a quote":  func(d *model.Device) { d.ListName = `A"; /system reboot; "` },
		"list name with a space":  func(d *model.Device) { d.ListName = "my list" },
		"nonsense block timeout":  func(d *model.Device) { d.BlockTimeout = "forever" },
		"unknown verify mode":     func(d *model.Device) { d.VerifyCert = "maybe" },
		"sync interval too small": func(d *model.Device) { d.SyncInterval = 1 },
	}
	for name, mutate := range cases {
		d := base
		mutate(&d)
		if _, err := Generate(FromDevice(d, "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")); err == nil {
			t.Errorf("%s: expected rejection", name)
		}
	}
	if _, err := Generate(FromDevice(base, "http://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")); err == nil {
		t.Error("plain http base URL: expected rejection")
	}
	if _, err := Generate(FromDevice(base, "https://apb.example.org", "APB", "bad token!", "apb-router")); err == nil {
		t.Error("malformed token: expected rejection")
	}
}

func TestV4OnlyDeviceGetsNoIPv6Commands(t *testing.T) {
	p := FromDevice(testDevice(), "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router")
	b, err := Generate(p)
	if err != nil {
		t.Fatalf("generate: %v", err)
	}
	if strings.Contains(unwrap(b.Scripts), "/ipv6 firewall") {
		t.Error("v4-only device received IPv6 commands")
	}

	d := testDevice()
	d.IPv6 = true
	b6, err := Generate(FromDevice(d, "https://apb.example.org", "APB", "apb_abcdefghijklmnop", "apb-router"))
	if err != nil {
		t.Fatalf("generate v6: %v", err)
	}
	if !strings.Contains(unwrap(b6.Scripts), "/ipv6 firewall address-list add") {
		t.Error("IPv6 device did not receive IPv6 commands")
	}
}
