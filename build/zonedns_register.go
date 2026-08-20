//go:build ignore

// This file is copied into the cmd/node-cache/ package of
// sigs.k8s.io/node-local-dns.
//
// Why add a file rather than patch upstream's main.go: patching means sed-ing
// string replacements into somebody else's source, which breaks the moment
// upstream reformats — and it breaks by way of "the patch did not apply but the
// build succeeded", producing a binary that looks fine and has no zonedns_agent
// in it. An extra file is settled at compile time instead: the file is there, so
// the plugin is there.
//
// The ignore tag keeps it out of this repo's build (it is package main with no
// main function). The Dockerfile strips that line as it copies the file in.
package main

import (
	"github.com/coredns/coredns/core/dnsserver"

	// The blank import lets the plugin register itself with CoreDNS.
	_ "github.com/jenting/zonedns/plugin/zonedns_agent"
)

func init() {
	insertBeforeCache("zonedns_agent")
}

// insertBeforeCache places a directive ahead of cache in dnsserver.Directives.
//
// The order is not a preference: node-local-dns's built-in cache plugin keys on
// (qname, qtype) and does not include the asking workload's zone. If it sorts
// first, a pod in one zone receives an answer cached for another, with no sign of
// it at runtime. The plugin's setup() checks this order at startup and refuses to
// start, so getting it wrong here will not pass silently — but placing it
// correctly here is what makes it right in the first place.
func insertBeforeCache(name string) {
	for _, d := range dnsserver.Directives {
		if d == name {
			return
		}
	}
	out := make([]string, 0, len(dnsserver.Directives)+1)
	for _, d := range dnsserver.Directives {
		if d == "cache" {
			out = append(out, name)
		}
		out = append(out, d)
	}
	dnsserver.Directives = out
}
