// Package geo resolves addresses to a country and a network operator using
// local MaxMind-format databases. Lookups never leave the machine: no address
// APB2 handles is ever sent to a third party.
package geo

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	maxminddb "github.com/oschwald/maxminddb-golang/v2"
)

// File names expected inside the geo directory.
const (
	CountryFile = "country.mmdb"
	ASNFile     = "asn.mmdb"
)

// Info is what a lookup yields.
type Info struct {
	Country     string // ISO 3166-1 alpha-2
	CountryName string
	Continent   string
	ASN         int64
	ASNOrg      string
}

// Resolver holds the open databases. It is safe for concurrent use and can be
// reloaded underneath live traffic.
type Resolver struct {
	dir string
	log *slog.Logger

	mu      sync.RWMutex
	country *maxminddb.Reader
	asn     *maxminddb.Reader
	loaded  time.Time
}

// New opens whatever databases are present in dir. A missing database is not
// an error: geolocation simply stays empty until one is installed.
func New(dir string, log *slog.Logger) *Resolver {
	if log == nil {
		log = slog.Default()
	}
	r := &Resolver{dir: dir, log: log}
	if err := r.Reload(); err != nil {
		log.Warn("geolocation databases unavailable", "err", err)
	}
	return r
}

// Reload re-opens the databases from disk.
func (r *Resolver) Reload() error {
	country, errC := openIfPresent(filepath.Join(r.dir, CountryFile))
	asn, errA := openIfPresent(filepath.Join(r.dir, ASNFile))

	r.mu.Lock()
	old := []*maxminddb.Reader{r.country, r.asn}
	r.country, r.asn = country, asn
	r.loaded = time.Now()
	r.mu.Unlock()

	for _, o := range old {
		if o != nil {
			_ = o.Close()
		}
	}
	return errors.Join(errC, errA)
}

func openIfPresent(path string) (*maxminddb.Reader, error) {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	rd, err := maxminddb.Open(path)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Base(path), err)
	}
	return rd, nil
}

// Close releases the databases.
func (r *Resolver) Close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.country != nil {
		_ = r.country.Close()
		r.country = nil
	}
	if r.asn != nil {
		_ = r.asn.Close()
		r.asn = nil
	}
}

// Ready reports which databases are currently loaded.
func (r *Resolver) Ready() (country, asn bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.country != nil, r.asn != nil
}

// Status describes the installed databases for the settings page.
type Status struct {
	CountryPresent bool
	CountrySize    int64
	CountryBuilt   time.Time
	ASNPresent     bool
	ASNSize        int64
	ASNBuilt       time.Time
	Dir            string
}

// Status inspects the geo directory.
func (r *Resolver) Status() Status {
	s := Status{Dir: r.dir}
	if fi, err := os.Stat(filepath.Join(r.dir, CountryFile)); err == nil {
		s.CountryPresent, s.CountrySize, s.CountryBuilt = true, fi.Size(), fi.ModTime()
	}
	if fi, err := os.Stat(filepath.Join(r.dir, ASNFile)); err == nil {
		s.ASNPresent, s.ASNSize, s.ASNBuilt = true, fi.Size(), fi.ModTime()
	}
	return s
}

// countryRecord covers both shapes an operator is likely to install.
//
// GeoLite2 and the full DB-IP databases nest the code under "country" with
// localised names alongside it. The compact country-only databases published by
// the ip-location-db project store a single flat "country_code" and no names at
// all, which is why the name table in countries.go exists. Decoding both means
// either file works without the operator having to know the difference.
type countryRecord struct {
	CountryCode string `maxminddb:"country_code"`
	Country     struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"country"`
	RegisteredCountry struct {
		ISOCode string            `maxminddb:"iso_code"`
		Names   map[string]string `maxminddb:"names"`
	} `maxminddb:"registered_country"`
	Continent struct {
		Code  string            `maxminddb:"code"`
		Names map[string]string `maxminddb:"names"`
	} `maxminddb:"continent"`
}

// resolve picks the best code and name available in whichever shape decoded.
func (r countryRecord) resolve() (code, name, continent string) {
	switch {
	case r.Country.ISOCode != "":
		code, name = r.Country.ISOCode, r.Country.Names["en"]
	case r.CountryCode != "":
		code = r.CountryCode
	case r.RegisteredCountry.ISOCode != "":
		code, name = r.RegisteredCountry.ISOCode, r.RegisteredCountry.Names["en"]
	}
	code = strings.ToUpper(code)
	if name == "" && code != "" {
		name = CountryName(code)
	}
	return code, name, r.Continent.Code
}

type asnRecord struct {
	Number uint   `maxminddb:"autonomous_system_number"`
	Org    string `maxminddb:"autonomous_system_organization"`
}

// Lookup resolves one address. Missing data yields zero values rather than an
// error: an unresolvable address is still a perfectly good blocklist entry.
func (r *Resolver) Lookup(addr netip.Addr) Info {
	var info Info
	r.mu.RLock()
	country, asn := r.country, r.asn
	r.mu.RUnlock()

	if country != nil {
		var rec countryRecord
		if res := country.Lookup(addr); res.Found() {
			if err := res.Decode(&rec); err == nil {
				info.Country, info.CountryName, info.Continent = rec.resolve()
			}
		}
	}
	if asn != nil {
		var rec asnRecord
		if res := asn.Lookup(addr); res.Found() {
			if err := res.Decode(&rec); err == nil {
				info.ASN = int64(rec.Number)
				info.ASNOrg = strings.TrimSpace(rec.Org)
			}
		}
	}
	return info
}

// Download fetches a database to the geo directory. The file is written to a
// temporary name and renamed into place, so a failed or partial download can
// never replace a working database.
func (r *Resolver) Download(ctx context.Context, url, name string) error {
	if url == "" {
		return errors.New("no source URL configured")
	}
	if name != CountryFile && name != ASNFile {
		return fmt.Errorf("refusing to write %q", name)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", "apb2-geo-updater")
	client := &http.Client{Timeout: 10 * time.Minute}
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%s: %s", url, resp.Status)
	}

	tmp, err := os.CreateTemp(r.dir, name+".*.part")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	// 512 MiB is far above any legitimate country or ASN database and stops a
	// hostile or misconfigured source from filling the disk.
	if _, err := io.Copy(tmp, io.LimitReader(resp.Body, 512<<20)); err != nil {
		return err
	}
	if err := tmp.Sync(); err != nil {
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	// Validate before publishing: a truncated or HTML error page must not
	// replace a working database.
	probe, err := maxminddb.Open(tmpName)
	if err != nil {
		return fmt.Errorf("downloaded file is not a valid MMDB: %w", err)
	}
	_ = probe.Close()

	dst := filepath.Join(r.dir, name)
	if err := os.Rename(tmpName, dst); err != nil {
		return err
	}
	r.log.Info("installed geo database", "file", name, "bytes", resp.ContentLength)
	return r.Reload()
}
