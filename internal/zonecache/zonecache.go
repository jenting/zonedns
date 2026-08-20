// Package zonecache is the node-side DNS answer cache, keyed in part by zone.
//
// Why CoreDNS's built-in cache plugin will not do: its key is (qname, qtype) and
// does not include the asking workload's zone. One name has different correct
// answers for clients in different zones — the service address within a zone,
// the gateway VIP across zones — so a zone-blind cache hands one zone's answer
// to a pod in another. And it hands it over convincingly, with no error at
// all.
package zonecache

import (
	"errors"
	"strings"
	"sync"
	"time"

	lru "github.com/hashicorp/golang-lru/v2"
	"github.com/miekg/dns"
)

// maxTTL bounds how long any cache entry actually lives, however long a TTL the
// upstream answer declares for itself.
//
// Spec §6.6 argues that the 30-second TTL on central's cross-zone answers is
// deliberate: it bounds the propagation delay for a topology change such as a
// service moving zone or a zone GW VIP changing, from the moment it happens to
// the moment every node sees the new answer. But that argument covers only the
// cross-zone branch. Same-zone answers are the upstream answer forwarded
// untouched, with whatever TTL upstream chose — possibly hours. Without this
// bound, once a name is registered in the registry or changes zone, this node
// keeps returning the direct address until that long TTL runs out; the zones are
// network-isolated, so throughout that window the answer is wrong, and the
// consequence is a failure to connect rather than any hint of what happened.
//
// The value chosen here is the same order of magnitude as central's defaultTTL
// (plugin/zonedns/setup.go), so the propagation bound the spec promises holds
// for both branches, not just the cross-zone half.
const maxTTL = 30 * time.Second

// Cache is a size-bounded, zone-aware answer cache, safe for concurrent use.
type Cache struct {
	mu sync.Mutex
	l  *lru.Cache[key, entry]
}

type key struct {
	qname string
	qtype uint16
	zone  string
}

type entry struct {
	msg    *dns.Msg
	expiry time.Time
}

// New builds a cache holding up to maxEntries entries.
func New(maxEntries int) (*Cache, error) {
	if maxEntries <= 0 {
		return nil, errors.New("zonecache: maxEntries must be positive")
	}
	l, err := lru.New[key, entry](maxEntries)
	if err != nil {
		return nil, err
	}
	return &Cache{l: l}, nil
}

// makeKey normalises qname. DNS names are case-insensitive, and without
// normalisation each spelling of one name would occupy its own entry, looking
// downstream like a cache that keeps missing.
func makeKey(qname string, qtype uint16, zone string) key {
	return key{qname: strings.ToLower(qname), qtype: qtype, zone: zone}
}

// Put takes in one answer.
//
// A response with no answers is not cached: there is no TTL to follow, and
// negative caching off the SOA minimum is a separate decision outside this
// package's scope. What is stored is a copy, so later changes by the caller to
// the original message do not reach the cache.
func (c *Cache) Put(qname string, qtype uint16, zone string, m *dns.Msg, now time.Time) {
	if m == nil || len(m.Answer) == 0 {
		return
	}

	minTTL := m.Answer[0].Header().Ttl
	for _, rr := range m.Answer[1:] {
		if t := rr.Header().Ttl; t < minTTL {
			minTTL = t
		}
	}
	if minTTL == 0 {
		return
	}

	ttl := time.Duration(minTTL) * time.Second
	if ttl > maxTTL {
		ttl = maxTTL
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	c.l.Add(makeKey(qname, qtype, zone), entry{
		msg:    m.Copy(),
		expiry: now.Add(ttl),
	})
}

// Get returns an answer that has not expired, with the elapsed time subtracted
// from every record's TTL.
//
// Subtracting is not cosmetic: returned at their original values, a downstream
// resolver would restart the clock the moment it received them, and the answer
// would live longer than intended.
func (c *Cache) Get(qname string, qtype uint16, zone string, now time.Time) (*dns.Msg, bool) {
	c.mu.Lock()
	e, ok := c.l.Get(makeKey(qname, qtype, zone))
	c.mu.Unlock()
	if !ok {
		return nil, false
	}

	remaining := e.expiry.Sub(now)
	if remaining <= 0 {
		return nil, false
	}

	out := e.msg.Copy()
	ttl := uint32(remaining / time.Second)
	for _, rr := range out.Answer {
		rr.Header().Ttl = ttl
	}
	for _, rr := range out.Ns {
		rr.Header().Ttl = ttl
	}
	for _, rr := range out.Extra {
		if rr.Header().Rrtype != dns.TypeOPT {
			rr.Header().Ttl = ttl
		}
	}
	return out, true
}

// Len returns the current entry count.
func (c *Cache) Len() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.l.Len()
}
