package geo

import "testing"

func TestCountryRecordDecodesBothShapes(t *testing.T) {
	// The compact ip-location-db databases carry only a flat code.
	var flat countryRecord
	flat.CountryCode = "us"
	code, name, _ := flat.resolve()
	if code != "US" {
		t.Errorf("flat shape: got code %q, want US", code)
	}
	if name != "United States of America" {
		t.Errorf("flat shape: got name %q, want the name table fallback", name)
	}

	// GeoLite2 and full DB-IP nest the code and carry localised names.
	var nested countryRecord
	nested.Country.ISOCode = "DE"
	nested.Country.Names = map[string]string{"en": "Germany"}
	nested.Continent.Code = "EU"
	code, name, continent := nested.resolve()
	if code != "DE" || name != "Germany" || continent != "EU" {
		t.Errorf("nested shape: got %q %q %q", code, name, continent)
	}

	// Some records only identify the registered country.
	var registered countryRecord
	registered.RegisteredCountry.ISOCode = "NL"
	code, name, _ = registered.resolve()
	if code != "NL" || name != "Netherlands" {
		t.Errorf("registered fallback: got %q %q", code, name)
	}

	// An empty record must not invent anything.
	var empty countryRecord
	if code, name, _ = empty.resolve(); code != "" || name != "" {
		t.Errorf("empty record produced %q %q", code, name)
	}
}

func TestCountryNameFallsBackToTheCode(t *testing.T) {
	if got := CountryName("PL"); got != "Poland" {
		t.Errorf("PL: got %q", got)
	}
	if got := CountryName("ZZ"); got != "ZZ" {
		t.Errorf("unknown code should pass through, got %q", got)
	}
}
