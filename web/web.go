// Package web carries the console's templates and static assets. They are
// embedded in the binary so the container ships as a single file and cannot
// serve anything the build did not include.
package web

import (
	"embed"
	_ "embed"
)

// Templates holds the HTML templates.
//
//go:embed templates/*.html
var Templates embed.FS

// Static holds the stylesheet, the small progressive-enhancement script and
// the generated world map.
//
//go:embed static
var Static embed.FS

// WorldSVG is the generated base map, parsed once at startup so the dashboard
// can shade it per country.
//
//go:embed static/world.svg
var WorldSVG []byte
