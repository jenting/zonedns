package zonedns_agent

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/jenting/zonedns/internal/dohupstream"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCheckDirectiveOrder(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns_agent", "cache", "forward"}); err != nil {
		t.Fatalf("valid order rejected: %v", err)
	}
}

// A wrong order must fail startup: with cache first, a zone-blind cache hands one
// zone's answer to a pod in another, and nothing looks amiss at runtime.
func TestCheckDirectiveOrderRejectsCacheFirst(t *testing.T) {
	err := CheckDirectiveOrder([]string{"cache", "zonedns_agent", "forward"})
	if err == nil {
		t.Fatal("expected an error when cache precedes zonedns_agent")
	}
	if !strings.Contains(err.Error(), "cache") {
		t.Fatalf("error should name the offending directive: %v", err)
	}
}

func TestCheckDirectiveOrderMissingPlugin(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"cache", "forward"}); err == nil {
		t.Fatal("expected an error when zonedns_agent is absent")
	}
}

// It must also succeed when cache does not appear in plugin.cfg at all — with no
// cache there is no zone-blind caching to risk, and this should not be refused.
func TestCheckDirectiveOrderNoCache(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns_agent", "forward"}); err != nil {
		t.Fatalf("valid order without cache rejected: %v", err)
	}
}

func TestParseVMMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		cache_size 4096
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.mode != modeVM {
		t.Fatalf("mode = %v, want vm", cfg.mode)
	}
	if cfg.zone != "zone-c" {
		t.Fatalf("zone = %q, want zone-c", cfg.zone)
	}
	if cfg.cacheSize != 4096 {
		t.Fatalf("cacheSize = %d, want 4096", cfg.cacheSize)
	}
}

func TestParseK8sMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		node_name node-1
		zone_label zone
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.mode != modeK8s {
		t.Fatalf("mode = %v, want k8s", cfg.mode)
	}
	if cfg.nodeName != "node-1" {
		t.Fatalf("nodeName = %q, want node-1", cfg.nodeName)
	}
	if cfg.zoneLabel != "zone" {
		t.Fatalf("zoneLabel = %q, want zone", cfg.zoneLabel)
	}
}

// central_spiffe_id has no safe default: without it only chain verification
// remains, and any SVID in the trust domain could impersonate central.
func TestParseRequiresCentralSPIFFEID(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when central_spiffe_id is missing")
	}
}

func TestParseVMModeRequiresZone(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when vm mode has no zone")
	}
}

func TestParseVMModeRejectsMalformedZone(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone.c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for a zone name that the wire format cannot carry")
	}
}

func TestParseK8sModeRequiresNodeName(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when k8s mode has no node_name")
	}
}

func TestParseRejectsUnknownMode(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode kubernetes
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for an unrecognised mode")
	}
}

func TestParseRejectsNonPositiveCacheSize(t *testing.T) {
	for _, v := range []string{"0", "-1"} {
		c := caddy.NewTestController("dns", `zonedns_agent {
			mode vm
			zone zone-c
			upstream https://central.example.org
			central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
			workload_api unix:///run/spire/sockets/agent.sock
			cache_size `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("cache_size %s was accepted", v)
		}
	}
}

func TestParseRejectsMalformedCacheSize(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		cache_size 4096abc
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("trailing garbage in cache_size was accepted")
	}
}

// An http:// upstream sends DoH queries in plaintext, and NewMTLS's
// TLSClientConfig — and with it the SPIFFE AuthorizeID pin on central's identity —
// is never consulted. It has to be stopped at config parse time rather than left
// to degrade quietly at runtime into a connection that verifies no identity at
// all.
func TestParseRejectsHTTPUpstream(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream http://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	err := parseConfigErr(t, c)
	if !strings.Contains(err.Error(), "https") {
		t.Fatalf("error should explain that https is required: %v", err)
	}
}

func TestParseRejectsMalformedUpstreamURL(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream ://missing-scheme
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	parseConfigErr(t, c)
}

// An upstream carrying a path must be stopped at startup. CoreDNS's doh package
// appends "/dns-query" itself, so such a value becomes "/dns-query/dns-query" and
// earns an HTTP 404 — an error that points at nothing whatsoever at runtime. This
// case was found the first time the project ran in a real environment.
func TestParseRejectsUpstreamWithPath(t *testing.T) {
	for _, u := range []string{
		"https://central.example.org/dns-query",
		"https://central.example.org:8443/dns-query",
		"https://central.example.org/anything",
	} {
		c := caddy.NewTestController("dns", `zonedns_agent {
			mode vm
			zone zone-c
			upstream `+u+`
			central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
			workload_api unix:///run/spire/sockets/agent.sock
		}`)
		_, err := parseConfig(c)
		if err == nil {
			t.Fatalf("upstream %q with a path was accepted", u)
		}
		if !strings.Contains(err.Error(), "dns-query") {
			t.Fatalf("upstream %q: error should explain the fixed DoH path, got: %v", u, err)
		}
	}
}

// A lone slash is not a path — that is how URLs are ordinarily written, and it
// must not be refused.
func TestParseAcceptsUpstreamWithTrailingSlash(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org/
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err != nil {
		t.Fatalf("a bare trailing slash should be accepted: %v", err)
	}
}

func TestParseAcceptsHTTPSUpstream(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err != nil {
		t.Fatalf("valid https upstream rejected: %v", err)
	}
}

// parseConfigErr is a shared helper: it calls parseConfig, requires an error, and
// returns that error so the caller can inspect the message.
func parseConfigErr(t *testing.T, c *caddy.Controller) error {
	t.Helper()
	_, err := parseConfig(c)
	if err == nil {
		t.Fatal("expected parseConfig to return an error")
	}
	return err
}

// A NODE_IP that is set but unparseable must make parseConfig fail rather than be
// quietly treated as unset — otherwise masquerade detection, the only signal that
// tells an operator this node has collapsed into a single zone, is disabled by one
// typo in the DaemonSet manifest, with nothing recorded.
func TestParseNodeIPEnvRejectsMalformed(t *testing.T) {
	t.Setenv("NODE_IP", "not-an-ip")
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for a malformed NODE_IP environment variable")
	}
}

// With NODE_IP unset everything must stay as it was: cfg.nodeIP keeps its zero
// value, and the previous check must not push it onto the "set but wrong" path.
func TestParseNodeIPEnvAbsentLeavesNodeIPUnset(t *testing.T) {
	t.Setenv("NODE_IP", "")
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.nodeIP.IsValid() {
		t.Fatalf("nodeIP = %v, want zero value when NODE_IP is absent", cfg.nodeIP)
	}
}

func TestParseMissingModeArgument(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when mode has no argument")
	}
}

func TestParseMissingZoneArgument(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error when zone has no argument")
	}
}

// edns0_code must be settable on the agent side, with validation identical to
// central's in plugin/zonedns/setup.go — the two ends must carry the same value
// (spec §6.6), and a value accepted at one end while refused at the other would
// have an operator believe both ends are in sync when one will never accept it.
func TestParseEdns0Code(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		edns0_code 65002
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.edns0Code != 65002 {
		t.Fatalf("edns0Code = %d, want 65002", cfg.edns0Code)
	}
}

func TestParseEdns0CodeDefault(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.edns0Code != ednszone.DefaultCode {
		t.Fatalf("edns0Code = %d, want the default %d", cfg.edns0Code, ednszone.DefaultCode)
	}
}

func TestParseRejectsOutOfRangeEdns0Code(t *testing.T) {
	for _, v := range []string{"65000", "65535"} {
		c := caddy.NewTestController("dns", `zonedns_agent {
			mode vm
			zone zone-c
			upstream https://central.example.org
			central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
			workload_api unix:///run/spire/sockets/agent.sock
			edns0_code `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("edns0_code %s outside 65001-65534 was accepted", v)
		}
	}
}

func TestParseRejectsMalformedEdns0Code(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		edns0_code 65002abc
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("trailing garbage in edns0_code was accepted")
	}
}

// Under vm mode node_name does nothing at all — this machine's zone is settled
// once by the zone option, not read per query from a pod label. Accepting and
// discarding it quietly would leave the Corefile's stated intent and the actual
// behaviour disagreeing.
func TestParseVMModeRejectsNodeName(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		node_name node-1
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	err := parseConfigErr(t, c)
	if !strings.Contains(err.Error(), "node_name") || !strings.Contains(err.Error(), "vm mode") {
		t.Fatalf("error should name the offending option and mode: %v", err)
	}
}

// Symmetrically, under k8s mode zone does nothing at all — this node's zone is
// settled per query by the pod label, and hard-coding a zone option would have an
// operator believe the node serves that one zone alone.
func TestParseK8sModeRejectsZone(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		node_name node-1
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)
	err := parseConfigErr(t, c)
	if !strings.Contains(err.Error(), "zone") || !strings.Contains(err.Error(), "k8s mode") {
		t.Fatalf("error should name the offending option and mode: %v", err)
	}
}

func TestParseRejectsUnknownProperty(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns_agent {
		mode vm
		zone zone-c
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
		bogus_property yes
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected an error for an unknown property")
	}
}

// During a reload the lifetimes of the old and new k8s watchers overlap:
// coredns/caddy brings the new instance fully up, its OnReady included, before
// shutting the old one down. Once a newer generation has marked resolverReady
// ready, the zeroing an older generation triggers on its own cancelled ctx must
// not overwrite it — otherwise the gauge sticks at 0 and stays wrong until the
// next reload, however long the new instance has been working normally.
func TestResolverReadyGuardIgnoresStaleShutdown(t *testing.T) {
	resolverGeneration.Store(0)
	resetResolverReadyGeneration(t)
	resolverReady.Set(0)
	defer func() {
		resolverGeneration.Store(0)
		resetResolverReadyGeneration(t)
		resolverReady.Set(0)
	}()

	gen1 := resolverGeneration.Add(1)
	markResolverReady(gen1)
	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v after gen1 ready, want 1", got)
	}

	gen2 := resolverGeneration.Add(1)
	markResolverReady(gen2)
	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v after gen2 ready, want 1", got)
	}

	// gen1's shutdown arrives late, after gen2 has already taken over — it
	// must not stomp gen2's readiness.
	markResolverStopped(gen1)
	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("stale generation's shutdown zeroed the gauge: got %v, want 1", got)
	}

	// gen2's own shutdown, with nothing newer having taken over, legitimately
	// zeroes it.
	markResolverStopped(gen2)
	if got := testutil.ToFloat64(resolverReady); got != 0 {
		t.Fatalf("resolverReady = %v after gen2 stopped, want 0", got)
	}
}

// resetResolverReadyGeneration zeroes resolverReadyGeneration, taking
// resolverReadyMu directly in white-box fashion rather than going through
// markResolverReady/markResolverStopped — this is only cleanup around a test, not
// an attempt to reproduce any interleaving.
func resetResolverReadyGeneration(t *testing.T) {
	t.Helper()
	resolverReadyMu.Lock()
	resolverReadyGeneration = 0
	resolverReadyMu.Unlock()
}

// TestResolverReadyGuardTOCTOU reproduces a check-then-act race: gen1 reads "I am
// still the latest generation" and then, before it can act on that conclusion by
// writing the gauge, gen2 gets in first through markResolverReady and replaces it
// as the latest — after which gen1 carries out the action it had already decided
// on, now out of date.
//
// This is the situation TestResolverReadyGuardIgnoresStaleShutdown does not cover.
// That test calls markResolverReady(gen1), markResolverReady(gen2) and
// markResolverStopped(gen1) in sequence, with no overlap between the three, so it
// verifies the outcome of each read and each write without verifying whether a
// window exists between them. This one uses resolverStoppedTestHook to force a
// complete markResolverReady(gen2) call in after markResolverStopped(gen1) has
// read "still the latest" and before it actually writes the gauge — and if read,
// compare and write are not one indivisible critical section, gen1 then overwrites
// the readiness gen2 just wrote, with no later event to put it right until the
// next reload. The same "stuck at 0" fault this whole mechanism exists to prevent,
// with the window narrowed from a whole reload to this one check-then-act instant.
//
// The hook calls markResolverReady(gen2) from its own goroutine rather than
// synchronously: once fixed, markResolverReady needs the same resolverReadyMu that
// markResolverStopped(gen1) is holding, and a synchronous call would deadlock the
// caller on a non-reentrant lock. A goroutine goes after the lock instead, a
// channel confirms it has at least started, and a little scheduling slack gives it
// a real chance to get its write in first on the unfixed version — time that costs
// the fixed version nothing: it simply blocks in Lock() until gen1 lets go.
func TestResolverReadyGuardTOCTOU(t *testing.T) {
	resolverReady.Set(0)
	resetResolverReadyGeneration(t)
	defer func() {
		resolverStoppedTestHook = nil
		resetResolverReadyGeneration(t)
		resolverReady.Set(0)
	}()

	gen1 := resolverGeneration.Add(1)
	markResolverReady(gen1)

	gen2 := resolverGeneration.Add(1)

	started := make(chan struct{})
	done := make(chan struct{})
	resolverStoppedTestHook = func() {
		go func() {
			close(started)
			markResolverReady(gen2)
			close(done)
		}()
		<-started
		runtime.Gosched()
		time.Sleep(10 * time.Millisecond)
	}

	markResolverStopped(gen1)
	// gen2's markResolverReady is guaranteed to eventually complete once
	// markResolverStopped(gen1) has returned and released resolverReadyMu, so
	// this cannot hang even if the guard is broken.
	<-done

	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v after gen2 superseded gen1's in-flight stop, want 1 "+
			"(gen2 is newer and reported ready; gen1's stale decision must not win)", got)
	}
	resolverReadyMu.Lock()
	gotGen := resolverReadyGeneration
	resolverReadyMu.Unlock()
	if gotGen != gen2 {
		t.Fatalf("resolverReadyGeneration = %d, want %d (gen2)", gotGen, gen2)
	}
}

// wireResolverReadyLifecycle is the function vm mode actually calls inside
// setup(): mark ready at once, clear when ctx ends. Before Task 8 this path ran
// only under k8s mode, while vm mode called resolverReady.Set(1) directly and
// never cleared it — leaving the gauge stuck at 1 after the node shut down, long
// after anything was answering queries. This tests the function itself rather than
// going the long way round through a full setup(): it is the generation guard
// shared by vm and k8s modes, the guard's own correctness is already covered by
// TestResolverReadyGuardIgnoresStaleShutdown and TestResolverReadyGuardTOCTOU, and
// all that is needed here is confirmation that the function vm mode really calls
// is wired to both ends, ready and cleared.
func TestWireResolverReadyLifecycleClearsOnCancel(t *testing.T) {
	resolverGeneration.Store(0)
	resetResolverReadyGeneration(t)
	resolverReady.Set(0)
	defer func() {
		resolverGeneration.Store(0)
		resetResolverReadyGeneration(t)
		resolverReady.Set(0)
	}()

	ctx, cancel := context.WithCancel(context.Background())
	wireResolverReadyLifecycle(ctx)

	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v immediately after wiring, want 1", got)
	}

	cancel()

	deadline := time.Now().Add(2 * time.Second)
	for testutil.ToFloat64(resolverReady) != 0 {
		if time.Now().After(deadline) {
			t.Fatal("resolverReady never cleared after ctx cancellation")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// fakeUpstreamConstructor builds a newUpstream stand-in: it never touches a real
// SPIRE Workload API, and returns a zero-value *dohupstream.Client (none of these
// tests actually send a query through it) together with a cleanup that counts its
// calls and lets the test observe the ctx setup() passed in.
func fakeUpstreamConstructor(cleanupCalls *int, capturedCtx *context.Context) func(context.Context, dohupstream.Config) (*dohupstream.Client, func(), error) {
	return func(ctx context.Context, _ dohupstream.Config) (*dohupstream.Client, func(), error) {
		*capturedCtx = ctx
		return &dohupstream.Client{}, func() { *cleanupCalls++ }, nil
	}
}

// vmModeConfig is the smallest valid vm-mode configuration that can be fed
// straight to setup().
const vmModeConfig = `zonedns_agent {
	mode vm
	zone zone-c
	upstream https://central.example.org
	central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
	workload_api unix:///run/spire/sockets/agent.sock
}`

// TestSetupRejectsBadDirectiveOrder covers setup()'s only logic that runs ahead of
// parseConfig: a wrong dnsserver.Directives must refuse startup outright, rather
// than the order being discovered only after the config has been parsed.
func TestSetupRejectsBadDirectiveOrder(t *testing.T) {
	origDirectives := dnsserver.Directives
	dnsserver.Directives = []string{"cache", "zonedns_agent"}
	defer func() { dnsserver.Directives = origDirectives }()

	c := caddy.NewTestController("dns", vmModeConfig)
	err := setup(c)
	if err == nil {
		t.Fatal("expected an error when cache precedes zonedns_agent in dnsserver.Directives")
	}
	if !strings.Contains(err.Error(), "cache") {
		t.Fatalf("error should name the offending directive: %v", err)
	}
}

// TestSetupVMModeSuccess runs vm mode end to end through setup(): the
// resolver_ready gauge must reach 1 (see wireResolverReadyLifecycle) and
// newUpstream must be called exactly once.
func TestSetupVMModeSuccess(t *testing.T) {
	origDirectives := dnsserver.Directives
	dnsserver.Directives = []string{"zonedns_agent", "cache"}
	defer func() { dnsserver.Directives = origDirectives }()

	resolverGeneration.Store(0)
	resetResolverReadyGeneration(t)
	resolverReady.Set(0)
	defer func() {
		resolverGeneration.Store(0)
		resetResolverReadyGeneration(t)
		resolverReady.Set(0)
	}()

	origNewUpstream := newUpstream
	var cleanupCalls int
	var capturedCtx context.Context
	newUpstream = fakeUpstreamConstructor(&cleanupCalls, &capturedCtx)
	defer func() { newUpstream = origNewUpstream }()

	c := caddy.NewTestController("dns", vmModeConfig)
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if got := testutil.ToFloat64(resolverReady); got != 1 {
		t.Fatalf("resolverReady = %v after successful vm-mode setup, want 1", got)
	}
	if capturedCtx == nil {
		t.Fatal("newUpstream was never called")
	}
	if capturedCtx.Err() != nil {
		t.Fatal("ctx passed to newUpstream was already cancelled on the success path")
	}
	if cleanupCalls != 0 {
		t.Fatalf("cleanup called %d times on the success path before shutdown, want 0", cleanupCalls)
	}
}

// TestSetupK8sModeFailurePathRunsCleanup checks that every error path tidies up
// the resources already created. After newUpstream succeeds,
// rest.InClusterConfig() is guaranteed to fail (outside a cluster there is no
// KUBERNETES_SERVICE_HOST/PORT), and setup() must call cancel() and cleanup()
// before returning the error — otherwise the X509Source it built, along with the
// file descriptors and background goroutines it holds, leaks. And it leaks only
// under a particular combination of failures, which makes it hard to notice after
// the fact.
func TestSetupK8sModeFailurePathRunsCleanup(t *testing.T) {
	origDirectives := dnsserver.Directives
	dnsserver.Directives = []string{"zonedns_agent", "cache"}
	defer func() { dnsserver.Directives = origDirectives }()

	t.Setenv("KUBERNETES_SERVICE_HOST", "")
	t.Setenv("KUBERNETES_SERVICE_PORT", "")

	origNewUpstream := newUpstream
	var cleanupCalls int
	var capturedCtx context.Context
	newUpstream = fakeUpstreamConstructor(&cleanupCalls, &capturedCtx)
	defer func() { newUpstream = origNewUpstream }()

	c := caddy.NewTestController("dns", `zonedns_agent {
		mode k8s
		node_name node-1
		upstream https://central.example.org
		central_spiffe_id spiffe://example.org/zone/mgmt/service/zonedns-central
		workload_api unix:///run/spire/sockets/agent.sock
	}`)

	if err := setup(c); err == nil {
		t.Fatal("expected an error from rest.InClusterConfig() outside a cluster")
	}
	if capturedCtx == nil {
		t.Fatal("newUpstream was never called")
	}
	if capturedCtx.Err() == nil {
		t.Fatal("ctx passed to newUpstream was not cancelled on the k8s in-cluster-config failure path")
	}
	if cleanupCalls != 1 {
		t.Fatalf("cleanup called %d times on the failure path, want 1", cleanupCalls)
	}
}
