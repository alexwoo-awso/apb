package geo

import (
	"context"
	"time"

	"github.com/alexwoo-awso/apb/internal/netutil"
	"github.com/alexwoo-awso/apb/internal/store"
)

// Enrich resolves a batch of addresses that have never been located, or whose
// location predates refreshAfter, and writes the results back. It is called on
// a timer so that ingest stays a pure database write and a slow or missing geo
// database can never delay a router's report.
func Enrich(ctx context.Context, db *store.DB, r *Resolver, batch int, refreshAfter time.Duration) (int, error) {
	if country, asn := r.Ready(); !country && !asn {
		return 0, nil
	}
	now := time.Now()
	before := now.Add(-refreshAfter).Unix()
	if refreshAfter <= 0 {
		before = now.Unix()
	}
	pending, err := db.PendingGeo(ctx, before, batch)
	if err != nil {
		return 0, err
	}
	if len(pending) == 0 {
		return 0, nil
	}
	updates := make([]store.GeoUpdate, 0, len(pending))
	for _, a := range pending {
		addr, err := netutil.ParseAddr(a.IP)
		if err != nil {
			// Still stamp it so a malformed row cannot hold up the queue.
			updates = append(updates, store.GeoUpdate{ID: a.ID})
			continue
		}
		info := r.Lookup(addr)
		updates = append(updates, store.GeoUpdate{
			ID:          a.ID,
			Country:     info.Country,
			CountryName: info.CountryName,
			Continent:   info.Continent,
			ASN:         info.ASN,
			ASNOrg:      info.ASNOrg,
		})
	}
	if err := db.ApplyGeo(ctx, updates, now.Unix()); err != nil {
		return 0, err
	}
	return len(updates), nil
}
