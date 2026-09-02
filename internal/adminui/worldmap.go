package adminui

import (
	"html/template"
	"regexp"
	"sync"

	"github.com/alexwoo-awso/apb/internal/model"
)

// MapPath is one country outline, ready to be emitted with a shade class.
type MapPath struct {
	Code  string
	Name  string
	D     template.HTMLAttr
	Count int64
	Level int
}

var (
	mapOnce  sync.Once
	mapPaths []MapPath
)

var rePath = regexp.MustCompile(`<path class="cc"(?: id="[^"]*")?(?: data-cc="([A-Z]{2})")?(?: data-name="([^"]*)")? d="([^"]+)"`)

// worldPaths parses the generated map once. The SVG is produced by
// tools/worldmap from public-domain Natural Earth geometry and committed, so
// the console needs no map service and no network access to draw it.
func worldPaths() []MapPath {
	mapOnce.Do(func() {
		for _, m := range rePath.FindAllStringSubmatch(string(worldSVG), -1) {
			mapPaths = append(mapPaths, MapPath{
				Code: m[1],
				Name: m[2],
				D:    template.HTMLAttr(m[3]),
			})
		}
	})
	return mapPaths
}

// choropleth returns the country outlines shaded by blocked-address count.
func choropleth(stats []model.CountryStat) []MapPath {
	counts := make(map[string]int64, len(stats))
	var max int64
	for _, s := range stats {
		counts[s.Code] = s.Count
		if s.Count > max {
			max = s.Count
		}
	}
	base := worldPaths()
	out := make([]MapPath, len(base))
	copy(out, base)
	for i := range out {
		if out[i].Code == "" {
			continue
		}
		out[i].Count = counts[out[i].Code]
		out[i].Level = level(out[i].Count, max)
	}
	return out
}
