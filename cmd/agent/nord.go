package main

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

// Runner abstracts command execution so tests can fake the nordvpn and tailscale CLIs.
type Runner interface {
	Run(ctx context.Context, name string, args ...string) (string, error)
	Has(name string) bool
}

type execRunner struct{}

func (execRunner) Has(name string) bool { _, err := exec.LookPath(name); return err == nil }

func (execRunner) Run(ctx context.Context, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	// The Nord CLI refuses to run without a real home directory; service users often have none.
	cmd.Env = append(os.Environ(), "LC_ALL=C", "TERM=dumb")
	if h := os.Getenv("HOME"); h == "" || h == "/nonexistent" {
		cmd.Env = append(cmd.Env, "HOME="+stateHome())
	}
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return cleanOutput(buf.String()), err
}

// stateHome returns a writable directory to use as HOME when the service has none.
func stateHome() string {
	for _, d := range []string{"/var/lib/wbs-vpn", os.TempDir()} {
		if st, err := os.Stat(d); err == nil && st.IsDir() {
			return d
		}
	}
	return "/tmp"
}

// cleanOutput strips the spinner / control characters the Nord CLI prints and trims whitespace.
func cleanOutput(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\n' || r == '\t' || (r >= 0x20 && r != 0x7f) {
			b.WriteRune(r)
		}
	}
	lines := strings.Split(b.String(), "\n")
	out := lines[:0]
	for _, l := range lines {
		if l = strings.TrimSpace(strings.TrimLeft(l, "-\\|/ ")); l != "" {
			out = append(out, l)
		}
	}
	return strings.Join(out, "\n")
}

// kv parses "Key: Value" lines (as printed by `nordvpn status` and `nordvpn settings`).
func kv(s string) map[string]string {
	m := map[string]string{}
	for _, l := range strings.Split(s, "\n") {
		if i := strings.Index(l, ":"); i > 0 {
			m[strings.ToLower(strings.TrimSpace(l[:i]))] = strings.TrimSpace(l[i+1:])
		}
	}
	return m
}

// readStatus gathers everything the panel shows about this device.
func readStatus(ctx context.Context, r Runner, piholeIPs []string) proto.Status {
	st := proto.Status{AgentVersion: version, Tailscale: "absent"}
	st.Hostname, _ = os.Hostname()
	if r.Has("tailscale") {
		st.Tailscale = "down"
		if out, err := r.Run(ctx, "tailscale", "status", "--json"); err == nil || out != "" {
			var js struct{ BackendState string }
			if i := strings.Index(out, "{"); i >= 0 && json.Unmarshal([]byte(out[i:]), &js) == nil && js.BackendState == "Running" {
				st.Tailscale = "up"
			}
		}
	}
	if !r.Has("nordvpn") {
		return st
	}
	st.NordInstalled = true
	v, verr := r.Run(ctx, "nordvpn", "--version")
	if verr == nil {
		st.Version = strings.TrimPrefix(v, "NordVPN Version ")
	} else {
		st.Error = "nordvpn: " + firstLine(v, verr)
		return st
	}
	out, err := r.Run(ctx, "nordvpn", "status")
	if err != nil && out == "" {
		st.Error = "nordvpn status failed: " + err.Error()
		return st
	}
	m := kv(out)
	if strings.EqualFold(m["status"], "connected") {
		st.Connected = true
		st.Country, st.City, st.Server, st.IP = m["country"], m["city"], m["hostname"], m["ip"]
		st.Technology = m["current technology"]
	} else if strings.Contains(out, "Permission denied") {
		st.Error = "nordvpn: permission denied (is the agent user in the nordvpn group?)"
	} else if strings.Contains(strings.ToLower(out), "log in") || strings.Contains(strings.ToLower(out), "not logged in") {
		st.Error = "nordvpn is not logged in on this device"
	}
	if set, err := r.Run(ctx, "nordvpn", "settings"); err != nil {
		if st.Error == "" {
			st.Error = "nordvpn settings: " + firstLine(set, err)
		}
	} else {
		sm := kv(set)
		st.KillSwitch = strings.EqualFold(sm["kill switch"], "enabled")
		dns := sm["dns"]
		for _, ip := range piholeIPs {
			if ip != "" && strings.Contains(dns, ip) {
				st.PiholeDNS = true
			}
		}
	}
	return st
}
