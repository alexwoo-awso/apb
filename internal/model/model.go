// Package model holds the plain data types shared by the store, the API and
// the admin UI. They deliberately carry no behaviour beyond small display
// helpers so that every layer agrees on one shape.
package model

import (
	"fmt"
	"strings"
	"time"
)

// Roles, in descending order of privilege.
const (
	RoleOwner  = "owner"  // everything, including deleting other owners
	RoleAdmin  = "admin"  // everything except managing owners
	RoleViewer = "viewer" // read-only
)

// Address states.
const (
	StateBlocked  = "blocked"
	StateReleased = "released"
)

// Changelog operations.
const (
	OpAdd    = "A"
	OpRemove = "R"
)

// Admin is a web console account.
type Admin struct {
	ID                 int64
	Username           string
	DisplayName        string
	Email              string
	PassHash           string
	Role               string
	TOTPSecret         []byte
	TOTPEnrolled       bool
	Disabled           bool
	MustChangePassword bool
	FailedAttempts     int
	LockedUntil        int64
	CreatedAt          int64
	CreatedBy          string
	LastLoginAt        int64
	LastLoginIP        string
}

// CanWrite reports whether the account may mutate state.
func (a Admin) CanWrite() bool { return a.Role == RoleOwner || a.Role == RoleAdmin }

// IsOwner reports whether the account holds the highest privilege.
func (a Admin) IsOwner() bool { return a.Role == RoleOwner }

// Session is a logged-in browser session.
type Session struct {
	ID          []byte
	AdminID     int64
	CSRF        string
	PendingTOTP bool
	CreatedAt   int64
	LastSeenAt  int64
	ExpiresAt   int64
	IP          string
	UserAgent   string
}

// Device is one MikroTik router participating in the exchange.
type Device struct {
	ID          int64
	Name        string
	Identity    string
	Description string
	ROSBranch   string
	ROSVersion  string
	Model       string
	Enabled     bool

	ListName       string
	DetectList     string
	BlockTimeout   string
	VerifyCert     string
	SyncInterval   int
	ReportInterval int
	Contribute     bool
	Consume        bool
	IPv6           bool

	Cursor       int64
	Applied      int64
	LastSyncAt   int64
	LastReportAt int64
	LastBootAt   int64
	LastIP       string
	ReportsTotal int64

	Tags      string
	Notes     string
	CreatedAt int64
	CreatedBy string

	// Populated by list queries, not stored.
	TokenCount int
}

// Health classifies a device by how recently it synchronised, relative to its
// own configured interval.
func (d Device) Health(now int64) string {
	if !d.Enabled {
		return "disabled"
	}
	if d.LastSyncAt == 0 {
		return "never"
	}
	grace := int64(d.SyncInterval) * 4
	if grace < 60 {
		grace = 60
	}
	switch age := now - d.LastSyncAt; {
	case age <= grace:
		return "online"
	case age <= grace*10:
		return "lagging"
	default:
		return "offline"
	}
}

// TagList splits the comma separated tag field.
func (d Device) TagList() []string {
	var out []string
	for _, t := range strings.Split(d.Tags, ",") {
		if t = strings.TrimSpace(t); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// DeviceToken is an issued API credential. Secret is only ever non-empty in
// the response that creates it.
type DeviceToken struct {
	ID         int64
	DeviceID   int64
	Label      string
	Prefix     string
	CreatedAt  int64
	CreatedBy  string
	ExpiresAt  int64
	RevokedAt  int64
	LastUsedAt int64
	UseCount   int64
	Secret     string
}

// Active reports whether the token may still authenticate.
func (t DeviceToken) Active(now int64) bool {
	if t.RevokedAt != 0 {
		return false
	}
	return t.ExpiresAt == 0 || t.ExpiresAt > now
}

// Address is a single tracked IP.
type Address struct {
	ID            int64
	IP            string
	Family        int
	State         string
	FirstSeen     int64
	LastSeen      int64
	ReportCount   int64
	DeviceCount   int64
	ExpiresAt     int64
	Country       string
	CountryName   string
	Continent     string
	ASN           int64
	ASNOrg        string
	GeoAt         int64
	Source        string
	Notes         string
	CreatedBy     string
	BlockedAt     int64
	ReleasedAt    int64
	ReleaseReason string
}

// Report is one device's view of one address.
type Report struct {
	AddressID  int64
	DeviceID   int64
	DeviceName string
	FirstAt    int64
	LastAt     int64
	Count      int64
}

// ReportEvent is a row of the raw activity stream.
type ReportEvent struct {
	ID         int64
	At         int64
	DeviceID   int64
	DeviceName string
	AddressID  int64
	IP         string
	Fresh      bool
}

// WhitelistEntry protects an address or network from ever being blocked.
type WhitelistEntry struct {
	ID        int64
	CIDR      string
	PrefixLen int
	Family    int
	Reason    string
	ExpiresAt int64
	CreatedAt int64
	CreatedBy string
	Hits      int64
}

// Change is one replication log record.
type Change struct {
	Seq    int64
	Op     string
	IP     string
	Family int
	At     int64
}

// AuditEntry records a state-changing action.
type AuditEntry struct {
	ID        int64
	At        int64
	Actor     string
	ActorType string
	Action    string
	Target    string
	Detail    string
	IP        string
	OK        bool
}

// CountryStat aggregates addresses by country for the map and the top lists.
type CountryStat struct {
	Code    string
	Name    string
	Count   int64
	Reports int64
}

// ASNStat aggregates addresses by autonomous system.
type ASNStat struct {
	ASN     int64
	Org     string
	Count   int64
	Reports int64
}

// HourPoint is a single bucket of the activity time series.
type HourPoint struct {
	Hour      int64
	Reports   int64
	Additions int64
	Removals  int64
}

// Dashboard is the aggregate shown on the landing page.
type Dashboard struct {
	Blocked        int64
	Whitelisted    int64
	AddedDay       int64
	RemovedDay     int64
	AddedWeek      int64
	ReportsDay     int64
	Devices        int64
	DevicesOnline  int64
	DevicesLagging int64
	DevicesOffline int64
	MultiDevice    int64 // addresses confirmed by more than one router
	Cursor         int64
	CursorFloor    int64
	DBBytes        int64
	Series         []HourPoint
	TopCountries   []CountryStat
	TopASNs        []ASNStat
	TopAddresses   []Address
	RecentDevices  []Device
}

// Age renders a compact "3m ago" style duration.
func Age(ts, now int64) string {
	if ts <= 0 {
		return "never"
	}
	d := now - ts
	if d < 0 {
		d = 0
	}
	switch {
	case d < 60:
		return fmt.Sprintf("%ds ago", d)
	case d < 3600:
		return fmt.Sprintf("%dm ago", d/60)
	case d < 86400:
		return fmt.Sprintf("%dh ago", d/3600)
	default:
		return fmt.Sprintf("%dd ago", d/86400)
	}
}

// Stamp renders a timestamp in UTC, or an em dash when unset.
func Stamp(ts int64) string {
	if ts <= 0 {
		return "—"
	}
	return time.Unix(ts, 0).UTC().Format("2006-01-02 15:04:05Z")
}
