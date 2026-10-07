package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

// Why DNS needs care while Nord is connected (verified against the Nord client source, v5.4.0, and by experiment):
//   * Nord's firewall drops port 53 to private/LAN addresses unless port 53 is allowlisted. Subnet allowlists do not help.
//     Allowlisting port 53 sends ALL port-53 traffic outside the tunnel, so it is only done when a mode needs it.
//   * On systemd-resolved hosts, `nordvpn set dns <LAN address>` puts that server on Nord's tunnel link, so resolved sends the
//     query INTO the tunnel where the LAN address does not exist. We therefore never use `set dns` there; we steer resolved
//     per link instead (split: route local domains to the LAN link; pihole: make the LAN link the catch-all).
//   * Hosts without systemd-resolved write /etc/resolv.conf directly, so `set dns <Pi-holes>` works once port 53 is allowed.

const nordLink = "nordlynx"

// dnsState is persisted so a restart can still undo what was changed on the LAN link.
type dnsState struct {
	Mode    string   `json:"mode"`
	Link    string   `json:"link,omitempty"`
	Orig    []string `json:"orig_domains,omitempty"` // the LAN link's domains before we touched them
	Touched bool     `json:"touched,omitempty"`
}

func validMode(m string) bool {
	return m == proto.DNSNord || m == proto.DNSSplit || m == proto.DNSPihole
}

func (a *Agent) loadState() {
	if a.stateFile == "" {
		a.dns.Mode = proto.DNSNord
		return
	}
	if b, err := os.ReadFile(a.stateFile); err == nil {
		_ = json.Unmarshal(b, &a.dns)
	}
	if !validMode(a.dns.Mode) {
		a.dns.Mode = proto.DNSNord
	}
}

func (a *Agent) saveState() {
	if a.stateFile == "" {
		return
	}
	b, _ := json.MarshalIndent(a.dns, "", "  ")
	_ = os.MkdirAll(filepath.Dir(a.stateFile), 0o755)
	tmp := a.stateFile + ".tmp"
	if os.WriteFile(tmp, b, 0o600) == nil {
		_ = os.Rename(tmp, a.stateFile)
	}
}

func (a *Agent) resolvedUp(ctx context.Context) bool {
	if !a.run.Has("resolvectl") {
		return false
	}
	_, err := a.run.Run(ctx, "resolvectl", "dns")
	return err == nil
}

// primaryLink is the interface that reaches the Pi-holes (the LAN link).
func (a *Agent) primaryLink(ctx context.Context) (string, error) {
	if !a.run.Has("ip") || len(a.piholeIPs) == 0 {
		return "", errors.New("cannot find the LAN interface (needs the ip tool and PIHOLE_DNS)")
	}
	out, err := a.run.Run(ctx, "ip", "-o", "route", "get", a.piholeIPs[0])
	if err != nil {
		return "", fmt.Errorf("route to %s: %s", a.piholeIPs[0], firstLine(out, err))
	}
	f := strings.Fields(out)
	for i, w := range f {
		if w == "dev" && i+1 < len(f) {
			return f[i+1], nil
		}
	}
	return "", errors.New("could not read the LAN interface from the routing table")
}

func (a *Agent) routingDomains() []string {
	var out []string
	for _, d := range a.localDomains {
		out = append(out, "~"+strings.TrimPrefix(d, "~"))
	}
	return out
}

func (a *Agent) linkDomains(ctx context.Context, link string) []string {
	out, err := a.run.Run(ctx, "resolvectl", "domain", link)
	if err != nil {
		return nil
	}
	if i := strings.Index(out, ":"); i >= 0 {
		out = out[i+1:]
	}
	own := map[string]bool{"~.": true}
	for _, d := range a.routingDomains() {
		own[d] = true
	}
	var keep []string
	for _, d := range strings.Fields(out) {
		if !own[d] { // never record our own changes as the "original"
			keep = append(keep, d)
		}
	}
	return keep
}

func (a *Agent) setLinkDomains(ctx context.Context, link string, domains []string) error {
	args := append([]string{"domain", link}, domains...)
	if len(domains) == 0 {
		args = append(args, "")
	}
	if out, err := a.run.Run(ctx, "resolvectl", args...); err != nil {
		return fmt.Errorf("resolvectl domain %s: %s", link, firstLine(out, err))
	}
	return nil
}

// restoreLink undoes our changes on the LAN link. Safe to call at any time.
func (a *Agent) restoreLink(ctx context.Context) error {
	if !a.dns.Touched {
		return nil
	}
	err := a.setLinkDomains(ctx, a.dns.Link, a.dns.Orig)
	a.run.Run(ctx, "resolvectl", "flush-caches")
	if err == nil {
		a.dns.Touched = false
		a.saveState()
	}
	return err
}

// applyDNS puts the device into mode. connected says whether the tunnel is up (link changes only make sense then).
func (a *Agent) applyDNS(ctx context.Context, mode string, connected bool) error {
	switch mode {
	case proto.DNSNord:
		a.nord(ctx, "set", "dns", "off")
		a.nord(ctx, "allowlist", "remove", "port", "53")
		return a.restoreLink(ctx)
	case proto.DNSSplit, proto.DNSPihole:
		if len(a.piholeIPs) == 0 {
			return errors.New("no Pi-hole addresses configured (PIHOLE_DNS)")
		}
		resolved := a.resolvedUp(ctx)
		if mode == proto.DNSSplit && !resolved {
			return errors.New("split DNS needs systemd-resolved on this device; use the Pi-hole mode instead")
		}
		a.nord(ctx, "allowlist", "add", "port", "53") // otherwise Nord drops DNS to the LAN
		if !resolved {                                // resolv.conf is written directly, so Nord's own custom DNS works
			if out, err := a.nord(ctx, append([]string{"set", "dns"}, a.piholeIPs...)...); err != nil {
				return fmt.Errorf("set dns: %s", firstLine(out, err))
			}
			return nil
		}
		a.nord(ctx, "set", "dns", "off") // never put a LAN address on Nord's tunnel link (see top of file)
		if !connected {
			return nil // nothing to steer until the tunnel exists; re-applied right after connect
		}
		link, err := a.primaryLink(ctx)
		if err != nil {
			return err
		}
		if !a.dns.Touched || a.dns.Link != link {
			a.dns.Link, a.dns.Orig, a.dns.Touched = link, a.linkDomains(ctx, link), true
			a.saveState()
		}
		add := a.routingDomains()
		if mode == proto.DNSPihole {
			add = []string{"~."}
		}
		if err := a.setLinkDomains(ctx, link, append(append([]string{}, a.dns.Orig...), add...)); err != nil {
			return err
		}
		if mode == proto.DNSPihole {
			a.run.Run(ctx, "resolvectl", "default-route", nordLink, "no") // the LAN link becomes the only catch-all
		}
		a.run.Run(ctx, "resolvectl", "flush-caches")
		return nil
	}
	return errors.New("unknown DNS mode")
}

func (a *Agent) isConnected(ctx context.Context) bool {
	out, _ := a.nord(ctx, "status")
	return strings.EqualFold(kv(out)["status"], "connected")
}

// setDNSMode switches mode and, when connected, verifies it; a mode that breaks DNS is reverted on the spot.
func (a *Agent) setDNSMode(ctx context.Context, mode string) (string, error) {
	if err := a.requireNord(); err != nil {
		return "", err
	}
	if !validMode(mode) {
		return "", errors.New("mode must be nord, split or pihole")
	}
	prev := a.dns.Mode
	connected := a.isConnected(ctx)
	if err := a.applyDNS(ctx, mode, connected); err != nil {
		a.applyDNS(ctx, prev, connected)
		return "", err
	}
	if connected {
		a.sleep(3 * time.Second)
		if err := a.healthy(ctx); err != nil {
			a.applyDNS(ctx, prev, connected)
			return "", fmt.Errorf("reverted to %s: DNS check failed in %s mode (%v)", prev, mode, err)
		}
	}
	a.dns.Mode = mode
	a.saveState()
	msg := "DNS mode: " + mode
	if !connected && mode != proto.DNSNord {
		msg += " (takes effect when connected)"
	}
	return msg, nil
}
