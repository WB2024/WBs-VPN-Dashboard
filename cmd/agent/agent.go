package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

var version = "dev"

const (
	minConnectGap   = 20 * time.Second // Nord throttles rapid reconnects
	rateLimitBackof = 10 * time.Minute
	verifyWindow    = 40 * time.Second
)

// Agent executes the fixed set of commands from the panel against the local Nord / Tailscale CLIs.
type Agent struct {
	run        Runner
	panelURL   string
	subnets    []string // always allowlisted so LAN and Tailscale keep working while connected
	piholeIPs  []string
	http       *http.Client
	healthy    func(ctx context.Context) error // post-connect check; replaced in tests
	now        func() time.Time
	sleep      func(time.Duration)
	lastConn   time.Time
	backoffTil time.Time
	baselined  bool

	dns          dnsState // desired DNS mode and what was changed on the LAN link
	stateFile    string   // persists dns across restarts ('' = memory only)
	localDomains []string // domains routed to the Pi-holes in split mode
	localCheck   string   // optional local name that must resolve in split/pihole mode
}

func NewAgent(r Runner, panelURL string, subnets, pihole []string) *Agent {
	a := &Agent{run: r, panelURL: strings.TrimRight(panelURL, "/"), subnets: subnets, piholeIPs: pihole,
		http: &http.Client{Timeout: 40 * time.Second}, now: time.Now, sleep: time.Sleep}
	a.healthy = a.defaultHealthy
	a.dns.Mode = proto.DNSNord
	return a
}

// defaultHealthy proves the device still has what we must never lose: the panel (LAN), DNS and the internet.
func (a *Agent) defaultHealthy(ctx context.Context) error {
	c := &http.Client{Timeout: 6 * time.Second}
	resp, err := c.Get(a.panelURL + "/healthz")
	if err != nil {
		return fmt.Errorf("panel unreachable: %w", err)
	}
	resp.Body.Close()
	rctx, cancel := context.WithTimeout(ctx, 6*time.Second)
	defer cancel()
	if _, err := net.DefaultResolver.LookupHost(rctx, "example.com"); err != nil {
		return fmt.Errorf("DNS not working: %w", err)
	}
	if a.localCheck != "" && a.dns.Mode != proto.DNSNord {
		if _, err := net.DefaultResolver.LookupHost(rctx, a.localCheck); err != nil {
			return fmt.Errorf("local name %s does not resolve: %w", a.localCheck, err)
		}
	}
	resp, err = c.Get("https://example.com")
	if err != nil {
		return fmt.Errorf("internet not reachable: %w", err)
	}
	resp.Body.Close()
	return nil
}

func (a *Agent) nord(ctx context.Context, args ...string) (string, error) {
	return a.run.Run(ctx, "nordvpn", args...)
}

// baseline puts the settings in place that keep the device reachable while connected. Idempotent.
func (a *Agent) baseline(ctx context.Context) {
	if a.baselined {
		return
	}
	a.nord(ctx, "set", "analytics", "off")
	a.nord(ctx, "set", "lan-discovery", "off") // private subnets can only be allowlisted with this off
	for _, s := range a.subnets {
		a.nord(ctx, "allowlist", "add", "subnet", s) // "already on the allowlist" is fine
	}
	a.baselined = true
}

func isRateLimited(out string) bool {
	l := strings.ToLower(out)
	return strings.Contains(l, "too many connection attempts") || strings.Contains(l, "session limit")
}

// Execute runs one command and returns its result. It never panics the loop.
func (a *Agent) Execute(ctx context.Context, c proto.Command) proto.Result {
	res := proto.Result{CommandID: c.ID, Type: c.Type, At: a.now().Unix()}
	var msg string
	var err error
	switch c.Type {
	case proto.CmdConnect:
		msg, err = a.connect(ctx, c.Country)
	case proto.CmdDisconnect:
		msg, err = a.disconnect(ctx)
	case proto.CmdKillSwitch:
		msg, err = a.killSwitch(ctx, c.Value == "on")
	case proto.CmdDNSMode:
		msg, err = a.setDNSMode(ctx, c.Value)
	case proto.CmdPiholeDNS: // legacy on/off
		msg, err = a.setDNSMode(ctx, map[bool]string{true: proto.DNSPihole, false: proto.DNSNord}[c.Value == "on"])
	case proto.CmdTailscale:
		msg, err = a.tailscale(ctx, c.Value == "on")
	default:
		err = errors.New("unknown command")
	}
	res.OK, res.Message = err == nil, msg
	if err != nil {
		res.Message = err.Error()
	}
	return res
}

func (a *Agent) requireNord() error {
	if !a.run.Has("nordvpn") {
		return errors.New("nordvpn CLI is not installed on this device")
	}
	return nil
}

func (a *Agent) connect(ctx context.Context, country string) (string, error) {
	if err := a.requireNord(); err != nil {
		return "", err
	}
	if wait := a.backoffTil.Sub(a.now()); wait > 0 {
		return "", fmt.Errorf("Nord is rate-limiting this account; retry in %d min", int(wait.Minutes())+1)
	}
	if gap := a.now().Sub(a.lastConn); gap < minConnectGap {
		a.sleep(minConnectGap - gap)
	}
	a.baseline(ctx)
	a.lastConn = a.now()
	out, err := a.nord(ctx, "connect", country)
	if isRateLimited(out) {
		a.backoffTil = a.now().Add(rateLimitBackof)
		return "", errors.New("Nord refused: too many connection attempts or session limit reached. Backing off 10 minutes")
	}
	if err != nil || !strings.Contains(strings.ToLower(out), "connected to") {
		return "", fmt.Errorf("connect failed: %s", firstLine(out, err))
	}
	if a.dns.Mode != proto.DNSNord {
		if err := a.applyDNS(ctx, a.dns.Mode, true); err != nil {
			a.disconnect(ctx)
			return "", fmt.Errorf("rolled back: DNS mode %s could not be applied: %v", a.dns.Mode, err)
		}
	}
	// Safety net: the new tunnel must keep the panel, DNS and internet reachable, or we undo it.
	deadline := a.now().Add(verifyWindow)
	var herr error
	for {
		if herr = a.healthy(ctx); herr == nil {
			return "connected: " + firstLine(out, nil), nil
		}
		if !a.now().Before(deadline) {
			break
		}
		a.sleep(4 * time.Second)
	}
	a.disconnect(ctx)
	return "", fmt.Errorf("rolled back: %v", herr)
}

// disconnect turns the kill switch off first, otherwise a "disconnected" device would have no internet.
func (a *Agent) disconnect(ctx context.Context) (string, error) {
	if err := a.requireNord(); err != nil {
		return "", err
	}
	a.nord(ctx, "set", "killswitch", "off")
	out, err := a.nord(ctx, "disconnect")
	if err != nil && !strings.Contains(strings.ToLower(out), "already disconnected") {
		return "", fmt.Errorf("disconnect failed: %s", firstLine(out, err))
	}
	a.restoreLink(ctx)
	return "disconnected", nil
}

func (a *Agent) killSwitch(ctx context.Context, on bool) (string, error) {
	if err := a.requireNord(); err != nil {
		return "", err
	}
	if on {
		out, _ := a.nord(ctx, "status")
		if !strings.EqualFold(kv(out)["status"], "connected") {
			return "", errors.New("refusing to enable the kill switch while disconnected: it would cut this device off the internet")
		}
	}
	v := map[bool]string{true: "on", false: "off"}[on]
	if out, err := a.nord(ctx, "set", "killswitch", v); err != nil {
		return "", fmt.Errorf("kill switch: %s", firstLine(out, err))
	}
	return "kill switch " + v, nil
}

func (a *Agent) tailscale(ctx context.Context, on bool) (string, error) {
	if !a.run.Has("tailscale") {
		return "", errors.New("tailscale is not installed on this device")
	}
	verb := map[bool]string{true: "up", false: "down"}[on]
	if out, err := a.run.Run(ctx, "tailscale", verb); err != nil {
		return "", fmt.Errorf("tailscale %s: %s", verb, firstLine(out, err))
	}
	return "tailscale " + verb, nil
}

func firstLine(out string, err error) string {
	if i := strings.Index(out, "\n"); i >= 0 {
		out = out[:i]
	}
	if out == "" && err != nil {
		return err.Error()
	}
	return out
}
