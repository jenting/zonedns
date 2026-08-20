package zonedns

import (
	"strings"
	"testing"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/prometheus/client_golang/prometheus/testutil"
)

func TestCheckDirectiveOrder(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns", "cache", "forward"}); err != nil {
		t.Fatalf("valid order rejected: %v", err)
	}
}

// A wrong order must fail startup, not merely warn — with cache first, a
// cross-zone client receives a same-zone answer cached for somebody else, and
// there is no sign of it at runtime.
func TestCheckDirectiveOrderRejectsCacheFirst(t *testing.T) {
	err := CheckDirectiveOrder([]string{"cache", "zonedns", "forward"})
	if err == nil {
		t.Fatal("expected error when cache precedes zonedns")
	}
	if !strings.Contains(err.Error(), "cache") {
		t.Fatalf("error should name the offending directive: %v", err)
	}
}

func TestCheckDirectiveOrderMissingZonedns(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"cache", "forward"}); err == nil {
		t.Fatal("expected error when zonedns is absent from Directives")
	}
}

// Without cache present the order does not matter.
func TestCheckDirectiveOrderWithoutCache(t *testing.T) {
	if err := CheckDirectiveOrder([]string{"zonedns", "forward"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseCorefile(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		poll_interval 30s
		authorized_agent spiffe://example.org/node/n1
		authorized_agent spiffe://example.org/node/n2
		edns0_code 65001
		ttl 30
		gateway zone-a 203.0.113.10
		gateway zone-b 203.0.113.11
	}`)

	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if len(cfg.authorizedAgents) != 2 {
		t.Fatalf("authorizedAgents = %d, want 2", len(cfg.authorizedAgents))
	}
	if cfg.ttl != 30 {
		t.Fatalf("ttl = %d, want 30", cfg.ttl)
	}
	if cfg.zones.Len() != 2 {
		t.Fatalf("zones = %d, want 2", cfg.zones.Len())
	}
	if got, ok := cfg.zones.Gateway("zone-a"); !ok || got.String() != "203.0.113.10" {
		t.Fatalf("gateway zone-a = (%s,%v)", got, ok)
	}
}

// No authorized agent means this plugin can never be zone-aware: a
// misconfiguration, not a legitimate setup.
func TestParseCorefileRequiresAuthorizedAgent(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		gateway zone-a 203.0.113.10
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error when no authorized_agent is configured")
	}
}

func TestParseCorefileRejectsBadGatewayAddress(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		gateway zone-a not-an-ip
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error for malformed gateway address")
	}
}

// Declaring a gateway for one zone twice would silently let the later entry
// overwrite the earlier, redirecting cross-zone traffic to a different address
// without anyone knowing — the config file must be refused outright rather than
// accepting last-one-wins.
func TestParseCorefileRejectsDuplicateGateway(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		gateway zone-a 203.0.113.10
		gateway zone-a 198.51.100.9
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error for a zone with two gateway declarations")
	}
}

// A Kubernetes label value permits a dot, but ednszone.Valid — the same rule
// identity uses to validate the source zone an agent declares — rejects it.
// Without a check on the gateway side, a zone name with a dot would work fine as
// a dest zone while every workload inside it had its source zone declaration
// judged invalid and discarded, degrading silently to zone-blind. It must be
// refused at config parse time.
func TestParseCorefileRejectsNonConformingGatewayZoneName(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		gateway zone.a 203.0.113.10
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error for a gateway zone name that ednszone.Valid rejects")
	}
}

// A poll_interval of zero or less makes the time.NewTicker inside the OnStartup
// goroutine panic and takes the process down with it — it has to be stopped while
// the config file is being parsed.
func TestParseCorefileRejectsNonPositivePollInterval(t *testing.T) {
	for _, v := range []string{"0s", "-5s"} {
		c := caddy.NewTestController("dns", `zonedns {
			spire_server unix:///tmp/spire-server/private/api.sock
			authorized_agent spiffe://example.org/node/n1
			poll_interval `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("poll_interval %q: expected error", v)
		}
	}
}

// fmt.Sscanf("%d") stops at the first non-digit and reports no error, so "5m" in
// duration form is read as 5, "30.5" as 30, and "65001abc" as 65001. With
// strconv.ParseUint these inputs must be refused whole, rather than truncated to
// the digits at the front.
func TestParseCorefileRejectsMalformedTTL(t *testing.T) {
	for _, v := range []string{"5m", "30.5", "30abc"} {
		c := caddy.NewTestController("dns", `zonedns {
			spire_server unix:///tmp/spire-server/private/api.sock
			authorized_agent spiffe://example.org/node/n1
			ttl `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("ttl %q: expected error", v)
		}
	}
}

// edns0_code must fall in 65001-65534, the range IANA reserves for
// local/experimental use, and input with trailing junk is not accepted (the same
// strconv fix handles both).
func TestParseCorefileRejectsMalformedEdns0Code(t *testing.T) {
	for _, v := range []string{"65000", "65535", "65001abc"} {
		c := caddy.NewTestController("dns", `zonedns {
			spire_server unix:///tmp/spire-server/private/api.sock
			authorized_agent spiffe://example.org/node/n1
			edns0_code `+v+`
		}`)
		if _, err := parseConfig(c); err == nil {
			t.Fatalf("edns0_code %q: expected error", v)
		}
	}
}

func TestParseCorefileAcceptsEdns0CodeUpperBound(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
		edns0_code 65534
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.edns0Code != 65534 {
		t.Fatalf("edns0Code = %d, want 65534", cfg.edns0Code)
	}
}

// A network address for spire_server means mTLS: without spire_server_id, all
// that can be verified is "some member of the trust domain", and any attacker
// holding an SVID from the same trust domain could intercept the connection,
// impersonate SPIRE Server and feed a forged registry. This must fail closed, and
// be refused while the config file is parsed.
func TestParseCorefileRequiresSpireServerIDForNetworkAddress(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server spire-server.example.org:8443
		workload_api unix:///tmp/agent/public/api.sock
		authorized_agent spiffe://example.org/node/n1
	}`)
	if _, err := parseConfig(c); err == nil {
		t.Fatal("expected error when spire_server is a network address without spire_server_id")
	}
}

// unix:// uses the local admin socket, is unaffected by mTLS authentication, and
// needs no spire_server_id.
func TestParseCorefileUnixSocketDoesNotRequireSpireServerID(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
	}`)
	if _, err := parseConfig(c); err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
}

func TestParseCorefileAcceptsSpireServerIDForNetworkAddress(t *testing.T) {
	c := caddy.NewTestController("dns", `zonedns {
		spire_server spire-server.example.org:8443
		spire_server_id spiffe://example.org/spire/server
		workload_api unix:///tmp/agent/public/api.sock
		authorized_agent spiffe://example.org/node/n1
	}`)
	cfg, err := parseConfig(c)
	if err != nil {
		t.Fatalf("parseConfig: %v", err)
	}
	if cfg.spireServerID != "spiffe://example.org/spire/server" {
		t.Fatalf("spireServerID = %q, want spiffe://example.org/spire/server", cfg.spireServerID)
	}
}

// registryReady is a package-level gauge shared across Corefile reloads (see
// setup.go). Unless setup() resets it, after a reload it would keep reporting the
// previous instance's readiness while the new, empty Store silently sent every
// query down the non-zone-aware path — the metric lying at exactly the moment
// accuracy matters most.
//
// setup()'s first step calls CheckDirectiveOrder(dnsserver.Directives), the
// vendored, compile-time-fixed list of CoreDNS's built-in directives, which does
// not contain "zonedns" (containing it requires a build where downstream
// regenerated zdirectives.go from its own plugin.cfg). Every other test in this
// file calls only parseConfig; this one needs setup() to run all the way through
// to verify when registryReady is reset, so for the duration of the test
// "zonedns" is inserted before "cache" to satisfy CheckDirectiveOrder and
// restored immediately afterwards. No test in this package uses t.Parallel(), so
// this temporary global change cannot race with another test.
func TestSetupResetsRegistryReadyGauge(t *testing.T) {
	registryReady.Set(1)      // as if a previous instance had become ready.
	registryPollErrors.Set(3) // as if a previous instance had failed several polls in a row.

	origDirectives := dnsserver.Directives
	extended := make([]string, 0, len(origDirectives)+1)
	inserted := false
	for _, d := range origDirectives {
		if d == "cache" && !inserted {
			extended = append(extended, "zonedns")
			inserted = true
		}
		extended = append(extended, d)
	}
	if !inserted {
		extended = append(extended, "zonedns")
	}
	dnsserver.Directives = extended
	defer func() { dnsserver.Directives = origDirectives }()

	c := caddy.NewTestController("dns", `zonedns {
		spire_server unix:///tmp/spire-server/private/api.sock
		authorized_agent spiffe://example.org/node/n1
	}`)

	// dialSPIRE's unix:// branch uses grpc.NewClient, which is lazy and does
	// not dial or block — no live SPIRE Server socket is required for setup()
	// to return, and OnStartup/OnShutdown callbacks registered here are never
	// invoked by NewTestController, so no goroutine or network I/O actually
	// starts during this test.
	if err := setup(c); err != nil {
		t.Fatalf("setup: %v", err)
	}

	if got := testutil.ToFloat64(registryReady); got != 0 {
		t.Fatalf("registryReady = %v, want 0", got)
	}
	// Same reasoning as registryReady above: a fresh Poller starts with zero
	// consecutive failures, so a stale non-zero reading left over from a
	// previous instance would misreport a healthy reload as still degraded.
	if got := testutil.ToFloat64(registryPollErrors); got != 0 {
		t.Fatalf("registryPollErrors = %v, want 0", got)
	}
}

// go-spiffe documents plainly that NewX509Source blocks until the first Workload
// API update arrives, with no timeout of its own — so were dialSPIRE to call it
// with context.Background(), an agent socket that is not up would stall setup()
// forever: hanging startup outright, or hanging the reload itself. This test
// shortens workloadAPIDialTimeout to something a test can wait for, points it at
// a unix socket that certainly does not exist, and checks that dialSPIRE returns
// an error within that window rather than waiting indefinitely — and that the
// error names workload_api, so an operator knows what to look at.
func TestDialSPIRETimesOutWhenWorkloadAPIUnavailable(t *testing.T) {
	origTimeout := workloadAPIDialTimeout
	workloadAPIDialTimeout = 200 * time.Millisecond
	defer func() { workloadAPIDialTimeout = origTimeout }()

	cfg := &config{
		spireServer:   "spire-server.example.org:8443",
		spireServerID: "spiffe://example.org/spire/server",
		workloadAPI:   "unix:///tmp/zonedns-test-nonexistent-agent.sock",
	}

	start := time.Now()
	_, _, err := dialSPIRE(cfg)
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error when the workload_api socket does not exist")
	}
	if !strings.Contains(err.Error(), "workload_api") {
		t.Fatalf("error should name the workload_api option so the operator knows what to check: %v", err)
	}
	// Generous upper bound: this must be well under NewX509Source's unbounded
	// default, not exactly workloadAPIDialTimeout to the millisecond.
	if elapsed > 5*time.Second {
		t.Fatalf("dialSPIRE took %s, want bounded by workloadAPIDialTimeout (%s)", elapsed, workloadAPIDialTimeout)
	}
}

// warnIfDoT must return the warning text only when the transport is tls, and the
// empty string for every other transport.
//
// The reason: identity extraction differs between DoT and DoH. DoH takes the
// *http.Request out of the context, which keeps working after another plugin
// wraps the ResponseWriter. DoT type-asserts the ResponseWriter to
// dns.ConnectionStater, and CoreDNS's built-in metrics plugin wraps the writer in
// a Recorder that stores dns.ResponseWriter as an interface field, making that
// assertion fail. The consequence is that every query on a DoT listener quietly
// reports "no certificate", zone routing switches off entirely, and the
// unauthorized-agent alert never fires — all without a single error along the
// way.
func TestWarnIfDoT(t *testing.T) {
	msg := warnIfDoT(transport.TLS)
	if msg == "" {
		t.Fatal("expected a warning for the tls transport")
	}
	if !strings.Contains(msg, "DoH") && !strings.Contains(msg, "https://") {
		t.Fatalf("warning should recommend DoH: %q", msg)
	}

	for _, tr := range []string{transport.DNS, transport.GRPC, transport.HTTPS, transport.QUIC, transport.UNIX, ""} {
		if msg := warnIfDoT(tr); msg != "" {
			t.Fatalf("transport %q should not warn, got %q", tr, msg)
		}
	}
}
