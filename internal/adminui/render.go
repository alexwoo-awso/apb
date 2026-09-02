package adminui

import (
	"fmt"
	"html/template"
	"math"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/alexwoo-awso/apb/internal/model"
)

// funcs are the helpers available to every template. Charts are rendered as
// plain SVG by these functions rather than by a client-side charting library,
// which keeps the console dependency-free and the content security policy
// tight.
var funcs = template.FuncMap{
	"stamp": model.Stamp,
	"age":   model.Age,
	"date": func(ts int64) string {
		if ts <= 0 {
			return "—"
		}
		return time.Unix(ts, 0).UTC().Format("2006-01-02")
	},
	"clock": func(ts int64) string {
		if ts <= 0 {
			return "—"
		}
		return time.Unix(ts, 0).UTC().Format("15:04")
	},
	"comma":    comma,
	"bytes":    humanBytes,
	"duration": humanDuration,
	"flag":     countryFlag,
	"pct": func(n, total int64) string {
		if total == 0 {
			return "0%"
		}
		return fmt.Sprintf("%.0f%%", float64(n)*100/float64(total))
	},
	"pctf": func(n, total int64) float64 {
		if total == 0 {
			return 0
		}
		return float64(n) * 100 / float64(total)
	},
	"add":       func(a, b int) int { return a + b },
	"sub":       func(a, b int) int { return a - b },
	"mul":       func(a, b int) int { return a * b },
	"seq":       seq,
	"lower":     strings.ToLower,
	"title":     strings.Title, //nolint:staticcheck // ASCII headings only
	"trunc":     trunc,
	"join":      strings.Join,
	"hasSuf":    strings.HasSuffix,
	"contains":  strings.Contains,
	"dict":      dict,
	"qs":        queryString,
	"asnLabel":  asnLabel,
	"sparkline": sparkline,
	"bars":      bars,
	"level":     level,
	"hint":      hintFor,
	"subi":      func(a, b int64) int64 { return a - b },
	"pctclass":  pctClass,
}

func comma(n int64) string {
	s := strconv.FormatInt(n, 10)
	neg := strings.HasPrefix(s, "-")
	if neg {
		s = s[1:]
	}
	var out []string
	for len(s) > 3 {
		out = append([]string{s[len(s)-3:]}, out...)
		s = s[:len(s)-3]
	}
	out = append([]string{s}, out...)
	j := strings.Join(out, ",")
	if neg {
		return "-" + j
	}
	return j
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func humanDuration(seconds int) string {
	switch {
	case seconds <= 0:
		return "—"
	case seconds < 60:
		return fmt.Sprintf("%ds", seconds)
	case seconds < 3600:
		if seconds%60 == 0 {
			return fmt.Sprintf("%dm", seconds/60)
		}
		return fmt.Sprintf("%dm %ds", seconds/60, seconds%60)
	case seconds < 86400:
		return fmt.Sprintf("%dh", seconds/3600)
	default:
		return fmt.Sprintf("%dd", seconds/86400)
	}
}

// countryFlag turns an ISO 3166-1 alpha-2 code into its regional indicator
// emoji, so the console shows flags without shipping any images.
func countryFlag(code string) string {
	code = strings.ToUpper(strings.TrimSpace(code))
	if len(code) != 2 || code[0] < 'A' || code[0] > 'Z' || code[1] < 'A' || code[1] > 'Z' {
		return "🏳"
	}
	return string(rune(0x1F1E6+rune(code[0]-'A'))) + string(rune(0x1F1E6+rune(code[1]-'A')))
}

func seq(n int) []int {
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

func trunc(n int, s string) string {
	if len([]rune(s)) <= n {
		return s
	}
	return string([]rune(s)[:n-1]) + "…"
}

// dict builds a map inline, so partials can take named arguments.
func dict(kv ...any) (map[string]any, error) {
	if len(kv)%2 != 0 {
		return nil, fmt.Errorf("dict needs an even number of arguments")
	}
	m := make(map[string]any, len(kv)/2)
	for i := 0; i < len(kv); i += 2 {
		k, ok := kv[i].(string)
		if !ok {
			return nil, fmt.Errorf("dict keys must be strings")
		}
		m[k] = kv[i+1]
	}
	return m, nil
}

// queryString rewrites the current query with the given overrides, which is
// how the table headers build their sort and page links.
func queryString(base string, kv ...any) template.URL {
	v, err := url.ParseQuery(strings.TrimPrefix(base, "?"))
	if err != nil {
		v = url.Values{}
	}
	for i := 0; i+1 < len(kv); i += 2 {
		key := fmt.Sprint(kv[i])
		val := fmt.Sprint(kv[i+1])
		if val == "" {
			v.Del(key)
		} else {
			v.Set(key, val)
		}
	}
	if len(v) == 0 {
		return template.URL("?")
	}
	return template.URL("?" + v.Encode())
}

func asnLabel(asn int64, org string) string {
	if asn == 0 {
		return "—"
	}
	if org == "" {
		return fmt.Sprintf("AS%d", asn)
	}
	return fmt.Sprintf("AS%d %s", asn, org)
}

// sparkline renders a series as an SVG polyline path inside a 100x30 box.
func sparkline(points []model.HourPoint, field string) template.HTMLAttr {
	if len(points) == 0 {
		return template.HTMLAttr("M0 30 L100 30")
	}
	vals := make([]float64, len(points))
	var maxV float64
	for i, p := range points {
		switch field {
		case "reports":
			vals[i] = float64(p.Reports)
		case "removals":
			vals[i] = float64(p.Removals)
		default:
			vals[i] = float64(p.Additions)
		}
		maxV = math.Max(maxV, vals[i])
	}
	if maxV == 0 {
		maxV = 1
	}
	var b strings.Builder
	step := 100.0
	if len(vals) > 1 {
		step = 100.0 / float64(len(vals)-1)
	}
	for i, v := range vals {
		x := float64(i) * step
		y := 30 - (v/maxV)*28
		if i == 0 {
			fmt.Fprintf(&b, "M%.2f %.2f", x, y)
		} else {
			fmt.Fprintf(&b, "L%.2f %.2f", x, y)
		}
	}
	return template.HTMLAttr(b.String())
}

// Bar is one column of the activity chart.
type Bar struct {
	X       float64
	Y       float64
	H       float64
	W       float64
	Label   string
	Value   int64
	Removed int64
	RY      float64
	RH      float64
}

// bars lays out the dashboard activity chart: additions above the axis,
// removals shaded underneath, in a 100x40 user-space box.
func bars(points []model.HourPoint) []Bar {
	if len(points) == 0 {
		return nil
	}
	var maxV int64 = 1
	for _, p := range points {
		if p.Additions > maxV {
			maxV = p.Additions
		}
		if p.Removals > maxV {
			maxV = p.Removals
		}
	}
	w := 100.0 / float64(len(points))
	out := make([]Bar, 0, len(points))
	for i, p := range points {
		addH := float64(p.Additions) / float64(maxV) * 28
		remH := float64(p.Removals) / float64(maxV) * 10
		out = append(out, Bar{
			X:       float64(i) * w,
			W:       math.Max(w-0.25, 0.35),
			Y:       28 - addH,
			H:       addH,
			RY:      29,
			RH:      remH,
			Value:   p.Additions,
			Removed: p.Removals,
			Label:   time.Unix(p.Hour, 0).UTC().Format("Jan 2 15:04"),
		})
	}
	return out
}

// pctClass maps a proportion onto one of the fixed width classes defined in
// the stylesheet. Bar widths cannot be set with an inline style attribute
// because the content security policy forbids them, so the width comes from a
// class instead.
func pctClass(n, max int64) string {
	if max <= 0 || n <= 0 {
		return "p0"
	}
	p := int(float64(n) / float64(max) * 100)
	p = (p + 2) / 5 * 5
	if p > 100 {
		p = 100
	}
	return fmt.Sprintf("p%d", p)
}

// level buckets a count into one of six choropleth shades.
func level(n, max int64) int {
	if n <= 0 || max <= 0 {
		return 0
	}
	switch r := float64(n) / float64(max); {
	case r > 0.6:
		return 5
	case r > 0.35:
		return 4
	case r > 0.18:
		return 3
	case r > 0.07:
		return 2
	default:
		return 1
	}
}
