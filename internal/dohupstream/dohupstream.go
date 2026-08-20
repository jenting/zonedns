// Package dohupstream is the agent's DoH client for talking to central.
//
// The transport is DoH over mTLS: the agent presents its own SVID and MUST pin
// central by SPIFFE ID. Verifying the certificate chain alone is not enough —
// any SVID in the trust domain could impersonate central, and a forged central
// can return whatever it likes (claiming a same-zone service is cross-zone and
// handing back an attacker-controlled address, say), with no independent way for
// the agent to check the answer. See spec §7.5.
package dohupstream

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/coredns/coredns/plugin/pkg/doh"
	"github.com/miekg/dns"
	"github.com/spiffe/go-spiffe/v2/spiffeid"
	"github.com/spiffe/go-spiffe/v2/spiffetls/tlsconfig"
	"github.com/spiffe/go-spiffe/v2/workloadapi"
)

// defaultDialTimeout bounds the wait for the first SVID.
//
// workloadapi.NewX509Source blocks until the Workload API first responds, so
// without this bound a SPIRE agent that is not yet ready would stall CoreDNS's
// whole configuration parse, with neither a timeout nor a log line.
const defaultDialTimeout = 10 * time.Second

// defaultQueryTimeout bounds the total time of one DoH query from send to
// response, covering the dial, the TLS handshake, writing the request and
// reading the reply.
//
// http.Client has no Timeout by default. A connection that begins its three-way
// handshake with central and then goes quiet — a network partition, a firewall
// dropping packets, a central that has hung without dropping the connection —
// would strand the goroutine waiting inside Exchange and its underlying socket
// forever, and the number stranded grows linearly with query volume, with no log
// line or metric to hint that it is happening. Five seconds comes from
// traditional DNS resolver convention (glibc's /etc/resolv.conf timeout defaults
// to 5 seconds too): long enough to absorb a TLS handshake plus ordinary network
// latency, short enough that the caller — the client facing node-local DNS —
// gets a timeout that looks normal before its own patience runs out, rather than
// hanging indefinitely.
const defaultQueryTimeout = 5 * time.Second

// Config is what building an mTLS client requires.
type Config struct {
	// URL is central's address, WITHOUT a path.
	//
	// CoreDNS's doh.NewRequestWithContext appends "/dns-query" itself (its own
	// comment says so: "The URL should not have a path"), so passing
	// "https://central/dns-query" here makes the actual request
	// "/dns-query/dns-query", central's DoH server answers 404, and all the agent
	// sees is "upstream returned HTTP 404".
	//
	// This contract was once neither written down nor tested: every unit test used
	// httptest's srv.URL, which happens to carry no path, and the fake server
	// accepted any path anyway — the two gaps covered for each other. The caller's
	// configuration validation is what rejects a value with a path at startup.
	URL             string
	WorkloadAPIAddr string
	CentralSPIFFEID string
	DialTimeout     time.Duration
	// Timeout bounds the total time of each DoH query; see defaultQueryTimeout. A
	// zero value takes that default.
	Timeout time.Duration
}

// Client sends DoH queries to central.
type Client struct {
	url string
	hc  *http.Client
}

// NewWithHTTPClient builds a Client over an existing http.Client. For tests, and
// to keep transport configuration separate from DNS logic.
func NewWithHTTPClient(url string, hc *http.Client) *Client {
	return &Client{url: url, hc: hc}
}

// NewMTLS builds a Client that authenticates both ways by SPIFFE identity.
//
// The returned cleanup must be called on shutdown to release the X509Source.
func NewMTLS(ctx context.Context, cfg Config) (*Client, func(), error) {
	if cfg.CentralSPIFFEID == "" {
		return nil, nil, errors.New("dohupstream: central_spiffe_id is required; " +
			"without it any SVID in the trust domain could impersonate the central server")
	}
	id, err := spiffeid.FromString(cfg.CentralSPIFFEID)
	if err != nil {
		return nil, nil, fmt.Errorf("dohupstream: invalid central_spiffe_id %q: %w", cfg.CentralSPIFFEID, err)
	}

	timeout := cfg.DialTimeout
	if timeout == 0 {
		timeout = defaultDialTimeout
	}
	dialCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	source, err := workloadapi.NewX509Source(dialCtx,
		workloadapi.WithClientOptions(workloadapi.WithAddr(cfg.WorkloadAPIAddr)))
	if err != nil {
		return nil, nil, fmt.Errorf("dohupstream: obtain SVID from workload_api %q within %s: %w",
			cfg.WorkloadAPIAddr, timeout, err)
	}

	// Certificates come from the X509Source rather than static files, so SVID
	// rotation needs no configuration reload.
	tlsCfg := tlsconfig.MTLSClientConfig(source, source, tlsconfig.AuthorizeID(id))
	hc := buildHTTPClient(tlsCfg, cfg.Timeout)

	return &Client{url: cfg.URL, hc: hc}, func() { source.Close() }, nil
}

// buildHTTPClient assembles the http.Client used for queries, wiring in the mTLS
// configuration and the timeout. Split out of NewMTLS so the timeout-defaulting
// logic can be tested on its own, without a running SPIRE Workload API.
func buildHTTPClient(tlsCfg *tls.Config, timeout time.Duration) *http.Client {
	if timeout == 0 {
		timeout = defaultQueryTimeout
	}
	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   timeout,
	}
}

// Exchange sends a query and returns the answer.
func (c *Client) Exchange(ctx context.Context, m *dns.Msg) (*dns.Msg, error) {
	// RFC 8484 requires the DNS ID of a DoH query to be 0. We restore the ID on the
	// response, or the caller cannot match the answer back to its query.
	originalID := m.Id
	outbound := m.Copy()
	outbound.Id = 0

	req, err := doh.NewRequestWithContext(ctx, http.MethodPost, c.url, outbound)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: build request: %w", err)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		resp.Body.Close()
		return nil, fmt.Errorf("dohupstream: upstream returned HTTP %d", resp.StatusCode)
	}

	// ResponseToMsg closes the body.
	answer, err := doh.ResponseToMsg(resp)
	if err != nil {
		return nil, fmt.Errorf("dohupstream: decode response: %w", err)
	}
	answer.Id = originalID
	return answer, nil
}
