package zonedns

import (
	"context"
	"fmt"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	clog "github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/jenting/zonedns/internal/ednszone"
	"github.com/jenting/zonedns/internal/identity"
	"github.com/jenting/zonedns/internal/registry"
	"github.com/jenting/zonedns/internal/zonetable"
	"github.com/spiffe/go-spiffe/v2/spiffegrpc/grpccredentials"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
	entryv1 "github.com/spiffe/spire-api-sdk/proto/spire/api/server/entry/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var log = clog.NewWithPlugin("zonedns")

const (
	defaultPollInterval = 30 * time.Second
	defaultTTL          = uint32(30)
)

// workloadAPIDialTimeout bounds how long dialSPIRE waits for the local SPIRE
// agent's Workload API to hand over the first X509 SVID update.
//
// go-spiffe's NewX509Source documents it plainly: it blocks until that first
// update arrives, with no timeout of its own. If the agent socket is not up — a
// mistyped path, an agent that has not started, an agent that died — setup()
// would stall the entire Corefile parse forever: at startup CoreDNS would never
// come up and say nothing about why, and on `reload` it would stall the reload
// itself while the old instance keeps serving, making the stall harder still to
// notice. It is a variable rather than a const so tests can shorten it instead of
// waiting the timeout out.
var workloadAPIDialTimeout = 10 * time.Second

func init() { plugin.Register("zonedns", setup) }

// config is the configuration parsed out of the Corefile.
type config struct {
	spireServer      string
	pollInterval     time.Duration
	authorizedAgents []string
	edns0Code        uint16
	ttl              uint32
	zones            *zonetable.Table
	workloadAPI      string // needed only when spire_server is a network address
	spireServerID    string // likewise: SPIRE Server's SPIFFE ID, required for a network address (validated below)
}

// CheckDirectiveOrder confirms that zonedns sorts before cache.
//
// The order is a correctness requirement, not a preference: were cache first, it
// would answer from a (qname, qtype) key that carries no zone, and a cross-zone
// client would receive an answer cached for another zone. That mistake leaves no
// sign at runtime, so it has to be stopped at startup.
//
// The order comes from plugin.cfg at compile time, making this a check on the
// build configuration rather than on the user's.
func CheckDirectiveOrder(directives []string) error {
	zonednsAt, cacheAt := -1, -1
	for i, d := range directives {
		switch d {
		case "zonedns":
			zonednsAt = i
		case "cache":
			cacheAt = i
		}
	}
	if zonednsAt < 0 {
		return fmt.Errorf("zonedns is not registered in dnsserver.Directives; add it to plugin.cfg before cache")
	}
	if cacheAt >= 0 && cacheAt < zonednsAt {
		return fmt.Errorf("zonedns must be ordered before cache in plugin.cfg, but cache is at %d and zonedns at %d; "+
			"with cache first, cross-zone clients would receive answers cached for another zone", cacheAt, zonednsAt)
	}
	return nil
}

// warnIfDoT returns the warning text to show when the transport is DNS-over-TLS,
// and the empty string for every other transport.
//
// Identity extraction differs between the two transports. DoH takes the
// *http.Request out of the context, which keeps working after another plugin
// wraps the ResponseWriter. DoT type-asserts the ResponseWriter to
// dns.ConnectionStater — and CoreDNS's built-in metrics plugin wraps the writer
// in a Recorder that stores dns.ResponseWriter as an interface field, making that
// assertion fail. The consequence is that every query on a DoT listener quietly
// reports "no certificate", zone routing switches off entirely, and the
// unauthorized-agent alert never fires — all without a single error along the
// way. The transport this project settled on is therefore DoH, and this only
// warns rather than refusing to start.
func warnIfDoT(tr string) string {
	if tr != transport.TLS {
		return ""
	}
	return "zonedns is configured on a DNS-over-TLS (tls://) listener; zone-aware answers are unreliable there " +
		"because CoreDNS plugins (e.g. metrics) can wrap the ResponseWriter and defeat the client certificate " +
		"extraction zonedns relies on, silently disabling zone routing. Use a DNS-over-HTTPS (https://) listener instead."
}

func setup(c *caddy.Controller) error {
	if err := CheckDirectiveOrder(dnsserver.Directives); err != nil {
		return plugin.Error("zonedns", err)
	}

	if msg := warnIfDoT(dnsserver.GetConfig(c).Transport); msg != "" {
		log.Warning(msg)
	}

	cfg, err := parseConfig(c)
	if err != nil {
		return plugin.Error("zonedns", err)
	}

	store := registry.NewStore()
	// registryReady and registryPollErrors are package-level gauges shared across
	// Corefile reloads. Without this reset registryReady would keep reporting the
	// *previous* instance's readiness (1) for up to a full poll_interval after a
	// reload, while the new (empty) Store silently takes the non-zone-aware path on
	// every query; registryPollErrors would similarly keep reporting the previous
	// instance's error streak against a brand new Poller that has not failed at
	// all yet — either way the metric would lie exactly when it matters most.
	registryReady.Set(0)
	registryPollErrors.Set(0)

	conn, cleanup, err := dialSPIRE(cfg)
	if err != nil {
		return plugin.Error("zonedns", err)
	}
	lister := registry.NewSPIRELister(entryv1.NewEntryClient(conn))
	poller := registry.NewPoller(lister, store, cfg.pollInterval)
	poller.OnSnapshot = func(s registry.Stats) {
		registryNames.Set(float64(s.Names))
		registryConflicts.Set(float64(s.Conflicts))
		registryReady.Set(1)
		if s.Conflicts > 0 {
			log.Warningf("%d DNS names have conflicting zone declarations and are unresolvable", s.Conflicts)
		}
	}
	// OnPollErrors fires after every poll attempt, success or failure alike —
	// unlike OnSnapshot it must run on both outcomes, otherwise this gauge can
	// only ever go up (never reset to 0 on recovery) or never move at all.
	poller.OnPollErrors = func(count int64) {
		registryPollErrors.Set(float64(count))
	}

	ctx, cancel := context.WithCancel(context.Background())
	c.OnStartup(func() error {
		go poller.Run(ctx)
		return nil
	})
	c.OnShutdown(func() error {
		cancel()
		cleanup()
		return conn.Close()
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		return ZoneDNS{
			Next:     next,
			Identity: identity.NewConfig(cfg.authorizedAgents, cfg.edns0Code),
			Registry: store,
			Zones:    cfg.zones,
			TTL:      cfg.ttl,
		}
	})
	return nil
}

// dialSPIRE connects to SPIRE Server's Entry API.
//
// Two deployment shapes:
//
//   - unix:// — central shares a machine with SPIRE Server and uses the local
//     admin socket. Access to that socket is governed by file permissions and
//     needs no SVID.
//   - anything else (host:port) — mTLS, with certificates from the local SPIRE
//     agent's Workload API. Central's own registration entry must then set
//     admin: true, or the Entry API refuses.
//
// Certificates come from an X509Source rather than static files, so SVID rotation
// needs no configuration reload.
func dialSPIRE(cfg *config) (*grpc.ClientConn, func(), error) {
	if strings.HasPrefix(cfg.spireServer, "unix://") {
		conn, err := grpc.NewClient(cfg.spireServer, grpc.WithTransportCredentials(insecure.NewCredentials()))
		if err != nil {
			return nil, nil, fmt.Errorf("dial spire server %q: %w", cfg.spireServer, err)
		}
		return conn, func() {}, nil
	}

	if cfg.workloadAPI == "" {
		return nil, nil, fmt.Errorf("spire_server %q is a network address, so workload_api must also be set "+
			"to obtain the admin SVID used to authenticate to the Entry API", cfg.spireServer)
	}
	// spire_server_id is required by parseConfig whenever spireServer is a network
	// address, so this should never actually fail — but dialSPIRE must not trust
	// that invariant blindly.
	serverID, err := spiffeid.FromString(cfg.spireServerID)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid spire_server_id %q: %w", cfg.spireServerID, err)
	}

	// NewX509Source blocks until the first Workload API update arrives, with
	// no timeout of its own — bound it here so a down or misconfigured agent
	// socket fails setup() loudly instead of hanging it forever (see
	// workloadAPIDialTimeout above).
	dialCtx, cancel := context.WithTimeout(context.Background(), workloadAPIDialTimeout)
	defer cancel()
	source, err := workloadapi.NewX509Source(dialCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.workloadAPI)))
	if err != nil {
		return nil, nil, fmt.Errorf("create X509Source from workload_api %q: waited %s for the SPIRE "+
			"Workload API to hand back the first SVID update and it did not arrive — check that the SPIRE "+
			"agent is running and its socket is reachable at that path: %w", cfg.workloadAPI, workloadAPIDialTimeout, err)
	}

	// AuthorizeID pins the exact SPIFFE ID that must present the server certificate.
	// AuthorizeMemberOf would instead accept *any* SVID in the trust domain as "the
	// SPIRE Server" — an attacker holding any workload SVID who can intercept this
	// connection could serve a forged registry and map arbitrary names to arbitrary
	// zones, compromising every routing decision the plugin makes.
	creds := grpccredentials.MTLSClientCredentials(source, source, tlsconfig.AuthorizeID(serverID))
	conn, err := grpc.NewClient(cfg.spireServer, grpc.WithTransportCredentials(creds))
	if err != nil {
		source.Close()
		return nil, nil, fmt.Errorf("dial spire server %q: %w", cfg.spireServer, err)
	}
	return conn, func() { source.Close() }, nil
}

func parseConfig(c *caddy.Controller) (*config, error) {
	cfg := &config{
		pollInterval: defaultPollInterval,
		edns0Code:    ednszone.DefaultCode,
		ttl:          defaultTTL,
	}
	gateways := map[string]netip.Addr{}

	for c.Next() {
		for c.NextBlock() {
			switch c.Val() {
			case "spire_server":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.spireServer = c.Val()

			case "poll_interval":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				d, err := time.ParseDuration(c.Val())
				if err != nil {
					return nil, c.Errf("invalid poll_interval %q: %v", c.Val(), err)
				}
				// A zero or negative interval reaches time.NewTicker inside the
				// OnStartup goroutine, which panics and crashes the process.
				if d <= 0 {
					return nil, c.Errf("poll_interval must be positive, got %q", c.Val())
				}
				cfg.pollInterval = d

			case "authorized_agent":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.authorizedAgents = append(cfg.authorizedAgents, c.Val())

			case "edns0_code":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				// strconv.ParseUint (unlike fmt.Sscanf with "%d") rejects trailing
				// garbage outright instead of silently stopping at the first
				// non-digit character.
				code, err := strconv.ParseUint(c.Val(), 10, 16)
				if err != nil {
					return nil, c.Errf("invalid edns0_code %q: %v", c.Val(), err)
				}
				if code < 65001 || code > 65534 {
					return nil, c.Errf("edns0_code %d is outside the local/experimental range 65001-65534", code)
				}
				cfg.edns0Code = uint16(code)

			case "workload_api":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.workloadAPI = c.Val()

			case "spire_server_id":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				cfg.spireServerID = c.Val()

			case "ttl":
				if !c.NextArg() {
					return nil, c.ArgErr()
				}
				// strconv.ParseUint rejects duration-shaped values ("5m", "30s")
				// and trailing garbage ("30.5", "65001abc") outright, where
				// fmt.Sscanf with "%d" would silently stop at the first
				// non-digit and accept a truncated prefix.
				ttl, err := strconv.ParseUint(c.Val(), 10, 32)
				if err != nil {
					return nil, c.Errf("invalid ttl %q: %v", c.Val(), err)
				}
				cfg.ttl = uint32(ttl)

			case "gateway":
				args := c.RemainingArgs()
				if len(args) != 2 {
					return nil, c.Errf("gateway needs a zone and an address, got %d arguments", len(args))
				}
				// ednszone.Valid is the character-set boundary the registry side
				// (spiffezone.FromPath) implicitly depends on too: a zone name with a
				// dot — permitted as a Kubernetes label value, rejected by
				// ednszone.Valid, see its doc and the "zone.a" test — works perfectly
				// well in the gateway table and the registry, while every source zone
				// declaration arriving from that zone is judged invalid by
				// ednszone.Get inside identity.SourceZone and discarded
				// (ReasonNoDeclaration). Those workloads would receive zone-blind
				// answers from then on, with no metric to alert on. Applying the same
				// rule at config parse time makes a non-conforming zone blow up at
				// startup instead of degrading quietly at runtime.
				if !ednszone.Valid(args[0]) {
					return nil, c.Errf("gateway zone %q is not a valid zone name (must match the "+
						"identity/registry zone character set, see ednszone.Valid)", args[0])
				}
				if _, dup := gateways[args[0]]; dup {
					return nil, c.Errf("gateway for zone %q is already configured", args[0])
				}
				addr, err := netip.ParseAddr(args[1])
				if err != nil {
					return nil, c.Errf("invalid gateway address %q for zone %q: %v", args[1], args[0], err)
				}
				gateways[args[0]] = addr

			default:
				return nil, c.Errf("unknown property %q", c.Val())
			}
		}
	}

	if cfg.spireServer == "" {
		return nil, c.Err("spire_server is required")
	}
	// With no authorized agent every declaration is ignored and the plugin can
	// never be zone-aware. That is always a misconfiguration, never a legitimate
	// setup.
	if len(cfg.authorizedAgents) == 0 {
		return nil, c.Err("at least one authorized_agent is required")
	}
	// When spire_server is a network address, dialSPIRE uses mTLS and
	// spire_server_id must pin SPIRE Server's exact identity. Without it, all that
	// can be verified is "some member of the trust domain", and any attacker
	// holding an SVID from the same trust domain could intercept the connection,
	// impersonate SPIRE Server, feed a forged registry and thereby steer every
	// routing decision — this must fail closed. A unix:// socket is local and
	// unaffected, so the field is not needed there.
	if !strings.HasPrefix(cfg.spireServer, "unix://") && cfg.spireServerID == "" {
		return nil, c.Err("spire_server_id is required when spire_server is a network address, to authenticate " +
			"the SPIRE Server by its exact identity rather than merely by trust domain membership")
	}

	cfg.zones = zonetable.New(gateways)
	return cfg, nil
}
