// Package zonetable holds the mapping from zone to zone gateway VIP.
//
// The data comes from the config file, the entry count is on the order of the
// number of zones (a few dozen), and it never changes after startup — so the
// table is read-only and needs no locking. Reloading config builds a new Table
// that replaces the old one.
package zonetable

import "net/netip"

// Table is a read-only mapping from zone to gateway VIP.
type Table struct {
	gw map[string]netip.Addr
}

// New builds a Table. The input map is copied, so later changes by the caller
// do not affect the Table that was built.
func New(entries map[string]netip.Addr) *Table {
	gw := make(map[string]netip.Addr, len(entries))
	for z, a := range entries {
		gw[z] = a
	}
	return &Table{gw: gw}
}

// Gateway returns the gateway VIP for a zone.
//
// A miss returns ok=false. The caller must treat that as a configuration error
// (SERVFAIL) and must not fall back to an ordinary answer — see spec §6.4,
// fourth row.
func (t *Table) Gateway(zone string) (netip.Addr, bool) {
	a, ok := t.gw[zone]
	return a, ok
}

// Len returns the number of configured zones.
func (t *Table) Len() int { return len(t.gw) }
