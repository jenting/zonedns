package zonedns_agent

import (
	"context"
	"fmt"
	"net/netip"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/jenting/zonedns/internal/dohupstream"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/podzone"
	"github.com/jenting/zonedns/internal/zonecache"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
)

type mode int

const (
	modeUnset mode = iota
	modeK8s
	modeVM
)

const defaultCacheSize = 4096

func init() { plugin.Register("zonedns_agent", setup) }

type config struct {
	mode            mode
	zone            string // vm mode
	nodeName        string // k8s mode
	zoneLabel       string // k8s mode
	upstreamURL     string
	centralSPIFFEID string
	workloadAPI     string
	cacheSize       int
	edns0Code       uint16
	nodeIP          netip.Addr
}

// CheckDirectiveOrder confirms that zonedns_agent sorts before cache.
//
// This is a correctness requirement, not a preference: the existing cache plugin
// keys on (qname, qtype) and does not include the asking workload's zone. If it
// sorts first, then once a zone-a pod has asked, a zone-b pod receives that same
// answer — convincingly, with no sign of it at runtime. The order comes from
// plugin.cfg at compile time, making this a check on the build configuration.
func CheckDirectiveOrder(directives []string) error {
	agentAt, cacheAt := -1, -1
	for i, d := range directives {
		switch d {
		case "zonedns_agent":
			agentAt = i
		case "cache":
			cacheAt = i
		}
	}
	if agentAt < 0 {
		return fmt.Errorf("zonedns_agent is not registered in dnsserver.Directives; add it to plugin.cfg before cache")
	}
	if cacheAt >= 0 && cacheAt < agentAt {
		return fmt.Errorf("zonedns_agent must be ordered before cache in plugin.cfg, but cache is at %d and zonedns_agent at %d; "+
			"with cache first, a pod in one zone would receive an answer cached for another", cacheAt, agentAt)
	}
	return nil
}

// resolverGeneration hands each k8s watcher startup an increasing generation
// number. It is package-level state shared across setup() calls, and since it
// only ever increments it needs no further protection — an increment has no
// read-then-decide-whether-to-write step in it.
//
// Why it exists: during a reload the lifetimes of the old and new watchers
// overlap. coredns/caddy's Instance.Restart brings the new instance fully up,
// c.OnStartup here included, and only then calls the old instance's Stop and
// OnShutdown. So when the old watcher wants to zero resolverReady because its own
// ctx was cancelled, that zeroing can land after the new watcher has finished
// syncing and set the gauge to 1 — nothing orders the two goroutines — and the
// older generation's zero would overwrite the readiness the newer one already
// reported, with no later event to put it right (each watcher's OnReady fires
// once). The generation number lets the moment of zeroing ask itself "am I still
// the last generation that actually became ready?", and do nothing if not.
var resolverGeneration atomic.Uint64

// resolverReadyMu protects resolverReadyGeneration and binds it into the same
// indivisible critical section as writes to the resolverReady gauge.
//
// Reading the latest ready generation, comparing it with one's own, and deciding
// whether to write the gauge must be a single atomic operation and cannot be
// split into read-then-write. Making resolverReadyGeneration an atomic.Uint64
// would not suffice: atomics make a single Load or a single Store indivisible,
// not "a Store decided upon after a Load". Left a window, an older generation
// could read "I am still the latest" and then, before it manages to write 0, be
// overtaken by a newer generation marking itself ready; the older generation then
// carries out the action it had already decided on and overwrites the readiness
// the newer one just wrote — and again no later event puts it right until the
// next reload. That is the same "stuck at 0" fault this mechanism exists to
// prevent, with the window narrowed from a whole reload to this one
// check-then-act instant. TestResolverReadyGuardTOCTOU forces that window open
// with resolverStoppedTestHook.
var (
	resolverReadyMu         sync.Mutex
	resolverReadyGeneration uint64 // protected by resolverReadyMu
)

// When resolverStoppedTestHook is not nil it is called once inside
// markResolverStopped, after the current ready generation has been read and
// compared and before the gauge is actually written. Its only purpose is to let
// tests force the interleaving a check-then-act needs; in production it is always
// nil, and one extra nil check costs nothing. It follows the style of the timeNow
// variable in agent.go.
var resolverStoppedTestHook func()

// newUpstream builds the agent's connection to central. Overridable in tests,
// following the style of resolverStoppedTestHook above and the timeNow variable
// in agent.go. Central's SPIRE connection is lazy (see dialSPIRE in
// plugin/zonedns/setup.go) and can be tested directly; dohupstream.NewMTLS here
// is different — it always blocks waiting for a real Workload API to deliver the
// first SVID. Without this indirection no test of setup() could run at all:
// whether CheckDirectiveOrder is called, whether VM mode sets the readiness gauge
// correctly, and whether every error path tidies up its cancel and cleanup.
var newUpstream = dohupstream.NewMTLS

// wireResolverReadyLifecycle ties the resolverReady gauge's lifetime to ctx: it
// marks generation gen ready at once, and attempts to clear it when ctx ends
// (whether it really clears is decided by the generation comparison — see the
// docs above resolverGeneration and markResolverStopped).
//
// VM mode has no asynchronous loading phase and is ready the moment its resolver
// is built, but it still goes through the same generation guard as k8s mode, so
// the two modes' shutdowns cannot overwrite each other's gauge writes — as when a
// reload has one instance in k8s mode and the other in vm mode.
func wireResolverReadyLifecycle(ctx context.Context) {
	gen := resolverGeneration.Add(1)
	markResolverReady(gen)
	go func() {
		<-ctx.Done()
		markResolverStopped(gen)
	}()
}

// markResolverReady records that generation gen has finished syncing. Callers may
// always mark ready outright, because OnReady fires once and only on a real
// completed sync, so it always represents the latest known fact — there is nobody
// to compare against. It still takes resolverReadyMu, for the reason given above
// that mutex: this function and markResolverStopped write the same generation
// number and the same gauge, and they must share one lock to exclude each other,
// or a write here could itself land in the middle of markResolverStopped's
// check-then-act.
func markResolverReady(gen uint64) {
	resolverReadyMu.Lock()
	defer resolverReadyMu.Unlock()
	resolverReadyGeneration = gen
	resolverReady.Set(1)
}

// markResolverStopped records that generation gen's watcher has stopped. It zeroes
// the gauge only when no newer generation has become ready. Comparing generations
// and writing the gauge happen under one lock, for the reason given above
// resolverReadyMu.
func markResolverStopped(gen uint64) {
	resolverReadyMu.Lock()
	defer resolverReadyMu.Unlock()
	stillLatest := resolverReadyGeneration == gen
	if resolverStoppedTestHook != nil {
		resolverStoppedTestHook()
	}
	if stillLatest {
		resolverReady.Set(0)
	}
}

func setup(c *caddy.Controller) error {
	if err := CheckDirectiveOrder(dnsserver.Directives); err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	cache, err := zonecache.New(cfg.cacheSize)
	if err != nil {
		return plugin.Error("zonedns_agent", err)
	}

	ctx, cancel := context.WithCancel(context.Background())

	up, cleanup, err := newUpstream(ctx, dohupstream.Config{
		URL:             cfg.upstreamURL,
		WorkloadAPIAddr: cfg.workloadAPI,
		CentralSPIFFEID: cfg.centralSPIFFEID,
	})
	if err != nil {
		cancel()
		return plugin.Error("zonedns_agent", err)
	}

	var resolver ZoneResolver
	switch cfg.mode {
	case modeVM:
		resolver = NewStaticResolver(cfg.zone)
		// VM mode has no asynchronous loading phase and is ready the moment its
		// resolver is built. wireResolverReadyLifecycle marks it ready at once and,
		// on shutdown (ctx.Done()), clears the gauge exactly as k8s mode does —
		// without that step a VM-mode node would leave resolver_ready stuck at 1
		// after it shut down, contradicting the fact that it has stopped
		// answering.
		wireResolverReadyLifecycle(ctx)
	case modeK8s:
		restCfg, err := rest.InClusterConfig()
		if err != nil {
			cancel()
			cleanup()
			return plugin.Error("zonedns_agent", fmt.Errorf("in-cluster config: %w", err))
		}
		client, err := kubernetes.NewForConfig(restCfg)
		if err != nil {
			cancel()
			cleanup()
			return plugin.Error("zonedns_agent", fmt.Errorf("kubernetes client: %w", err))
		}
		w := podzone.New(client, cfg.nodeName, cfg.zoneLabel)
		resolver = w

		// resolverReady is deliberately not set to 0 here. All that is happening at
		// this moment is "a new configuration is being parsed", and the old instance
		// — if this is a reload — is still answering queries normally. Zeroing the
		// shared gauge early would manufacture a false "not ready" window and fire
		// the resolver_ready==0 alert on every reload, even with no interruption of
		// service at all. The gauge keeps whatever value it had — promauto's default
		// 0 on a cold start, the 1 left by the old instance on a reload — until one
		// of two things really happens: this watcher finishes syncing (OnReady) or
		// it is shut down (ctx.Done). For what the generation number is for, see the
		// doc above resolverGeneration.
		gen := resolverGeneration.Add(1)
		w.OnReady = func() { markResolverReady(gen) }
		c.OnStartup(func() error {
			go func() {
				if err := w.Run(ctx); err != nil {
					log.Errorf("pod watcher stopped: %v", err)
				}
			}()
			go func() {
				<-ctx.Done()
				markResolverStopped(gen)
			}()
			return nil
		})
	}

	c.OnShutdown(func() error {
		cancel()
		cleanup()
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return Agent{
			Resolver:  resolver,
			Cache:     cache,
			Upstream:  up,
			EDNS0Code: cfg.edns0Code,
			NodeIP:    cfg.nodeIP,
		}
	})
	return nil
}

func parseConfig(c *caddy.Controller) (*config, error) {
	cfg := &config{
		cacheSize: defaultCacheSize,
		edns0Code: ednszone.DefaultCode,
		zoneLabel: "zone",
	}
	// A NODE_IP that is set but unparseable must be an error rather than quietly
	// treated as unset. Masquerade detection — Agent.resolveZone comparing the
	// source address against the node's own IP — is the only signal that tells an
	// operator "something on this node is rewriting source addresses and it has
	// collapsed into a single zone". One mistyped character in the DaemonSet
	// manifest disabling it silently, with nothing recorded, is exactly the failure
	// mode this project has been eliminating throughout. The behaviour matches the
	// node_ip Corefile option below, where the same parse error fails startup.
	if v := os.Getenv("NODE_IP"); v != "" {
		addr, err := netip.ParseAddr(v)
		if err != nil {
			return nil, c.Errf("invalid NODE_IP environment variable %q: %v", v, err)
		}
		cfg.nodeIP = addr
	}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "mode":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				switch c.Val() {
				case "k8s":
					cfg.mode = modeK8s
				case "vm":
					cfg.mode = modeVM
				default:
					return nil, c.Errf("unknown mode %q; expected k8s or vm", c.Val())
				}

			case "zone":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.zone = c.Val()

			case "node_name":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.nodeName = c.Val()

			case "zone_label":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.zoneLabel = c.Val()

			case "upstream":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.upstreamURL = c.Val()

			case "central_spiffe_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.centralSPIFFEID = c.Val()

			case "workload_api":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.workloadAPI = c.Val()

			case "cache_size":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				n, err := strconv.Atoi(c.Val())
				if err != nil {
					return nil, c.Errf("invalid cache_size %q: %v", c.Val(), err)
				}
				if n <= 0 {
					return nil, c.Errf("cache_size must be positive, got %d", n)
				}
				cfg.cacheSize = n

			case "node_ip":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				addr, err := netip.ParseAddr(c.Val())
				if err != nil {
					return nil, c.Errf("invalid node_ip %q: %v", c.Val(), err)
				}
				cfg.nodeIP = addr

			case "edns0_code":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				// The validation is identical to edns0_code in
				// plugin/zonedns/setup.go — the two ends must carry the same value (see
				// spec §6.6), and letting either side's rule drift could have a value
				// accepted at one end and refused at the other, after which they never
				// agree again. strconv.ParseUint, unlike fmt.Sscanf's "%d", refuses
				// trailing junk outright instead of quietly stopping at the first
				// non-digit.
				code, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return nil, c.Errf("invalid edns0_code %q: %v", c.Val(), err)
				}
				if code < 65001 || code > 65534 {
					return nil, c.Errf("edns0_code %d is outside the local/experimental range 65001-65534", code)
				}
				cfg.edns0Code = uint16(code)

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if cfg.mode == modeUnset {
		return nil, c.Err("mode is required (k8s or vm)")
	}
	if cfg.upstreamURL == "" {
		return nil, c.Err("upstream is required")
	}
	// upstream must be https://. The entire reason the client built by NewMTLS
	// exists is to pin central's identity by SPIFFE ID; an http:// upstream sends
	// queries in plaintext and the http.Transport's TLSClientConfig — the
	// AuthorizeID pin — is never consulted at all. One character would render the
	// whole mTLS pinning moot, with no error and no warning, while queries go out
	// as usual.
	u, err := url.Parse(cfg.upstreamURL)
	if err != nil {
		return nil, c.Errf("invalid upstream %q: %v", cfg.upstreamURL, err)
	}
	if u.Scheme != "https" {
		return nil, c.Errf("upstream %q must use https; a plain %q upstream would send DoH queries in "+
			"cleartext, bypassing the SPIFFE server pinning NewMTLS exists to provide entirely",
			cfg.upstreamURL, u.Scheme)
	}
	// upstream must not carry a path. CoreDNS's doh.NewRequestWithContext appends
	// "/dns-query" itself, so "https://central/dns-query" becomes
	// "/dns-query/dns-query", central answers 404, and all that is visible here is
	// "upstream returned HTTP 404" — which points an operator at nothing.
	//
	// Refusing rather than stripping it automatically: a configuration value
	// silently rewritten is more dangerous than one that fails at startup, and that
	// is the failure shape this project keeps eliminating.
	if p := strings.TrimSuffix(u.Path, "/"); p != "" {
		return nil, c.Errf("upstream %q must not include a path; the DoH path is always %q and is "+
			"appended automatically, so %q would be requested as %q and answered with HTTP 404",
			cfg.upstreamURL, "/dns-query", u.Path, u.Path+"/dns-query")
	}
	// central_spiffe_id has no safe default: without it only chain verification
	// remains, and any SVID in the trust domain could impersonate central and return
	// whatever it liked.
	if cfg.centralSPIFFEID == "" {
		return nil, c.Err("central_spiffe_id is required; without it any SVID in the trust domain could impersonate the central server")
	}
	if cfg.workloadAPI == "" {
		return nil, c.Err("workload_api is required")
	}

	switch cfg.mode {
	case modeVM:
		if cfg.zone == "" {
			return nil, c.Err("vm mode requires zone")
		}
		// The zone name must be something the wire format can carry — otherwise
		// central silently ignores the declaration and this VM's queries receive
		// zone-blind answers forever.
		if !ednszone.Valid(cfg.zone) {
			return nil, c.Errf("zone %q is not a valid zone name (letters, digits, '-' and '_' only, at most %d bytes)",
				cfg.zone, ednszone.MaxLen)
		}
		// node_name is used only by k8s mode's podzone.Watcher. Letting it parse
		// quietly under vm mode while doing nothing at all would have an operator
		// believe the node_name in the Corefile means something, when this machine's
		// zone is settled entirely by the zone option — the Corefile's stated intent
		// and the actual behaviour would disagree, and that has to be said out loud
		// at startup.
		if cfg.nodeName != "" {
			return nil, c.Err("node_name is not valid in vm mode; vm mode declares the zone once via " +
				"the zone option, not per-query from pod labels")
		}
	case modeK8s:
		if cfg.nodeName == "" {
			return nil, c.Err("k8s mode requires node_name")
		}
		// Symmetrically, zone is used only by vm mode's StaticResolver. Under k8s
		// mode a node routinely mixes several zones, settled per query by the pod
		// label — so a Corefile saying `zone zone-c` could have an operator believe
		// this node serves zone-c alone, while the option is ignored entirely.
		if cfg.zone != "" {
			return nil, c.Err("zone is not valid in k8s mode; k8s mode determines the zone per-query " +
				"from pod labels, not from a fixed zone option")
		}
	}

	return cfg, nil
}
