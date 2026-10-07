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
	cmd.Env = append(os.Environ(), "LC_ALL=C", "TERM=dumb")
	var buf bytes.Buffer
	cmd.Stdout, cmd.Stderr = &buf, &buf
	err := cmd.Run()
	return cleanOutput(buf.String()), err
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
	if v, err := r.Run(ctx, "nordvpn", "--version"); err == nil {
		st.Version = strings.TrimPrefix(v, "NordVPN Version ")
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
	if set, err := r.Run(ctx, "nordvpn", "settings"); err == nil {
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
