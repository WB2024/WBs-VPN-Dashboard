package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

type fakeRunner struct {
	has       map[string]bool
	responses map[string]string // key: "nordvpn connect United_Kingdom"
	calls     []string
}

func (f *fakeRunner) Has(n string) bool { return f.has[n] }
func (f *fakeRunner) Run(_ context.Context, name string, args ...string) (string, error) {
	key := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, key)
	if out, ok := f.responses[key]; ok {
		if strings.HasPrefix(out, "ERR:") {
			return out[4:], errors.New("exit 1")
		}
		return out, nil
	}
	return "", nil
}
func (f *fakeRunner) called(sub string) bool {
	for _, c := range f.calls {
		if strings.Contains(c, sub) {
			return true
		}
	}
	return false
}

func newTestAgent(f *fakeRunner, healthy func(context.Context) error) *Agent {
	a := NewAgent(f, "http://panel.test", []string{"192.168.1.0/24", "100.64.0.0/10"}, []string{"192.168.1.53"})
	a.healthy = healthy
	t := time.Unix(1_000_000, 0)
	a.now = func() time.Time { return t }
	a.sleep = func(d time.Duration) { t = t.Add(d) }
	return a
}

func TestKV(t *testing.T) {
	m := kv("Status: Connected\nCountry: United Kingdom\nCurrent technology: NORDLYNX\nKill Switch: disabled")
	if m["status"] != "Connected" || m["country"] != "United Kingdom" || m["current technology"] != "NORDLYNX" {
		t.Fatalf("bad parse: %v", m)
	}
}

func TestCleanOutput(t *testing.T) {
	if got := cleanOutput("\r-\r\\\r  \nConnecting...\x00\n\n"); got != "Connecting..." {
		t.Fatalf("got %q", got)
	}
}

func TestReadStatus(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true, "tailscale": true}, responses: map[string]string{
		"nordvpn --version":       "NordVPN Version 5.4.0",
		"nordvpn status":          "Status: Connected\nHostname: uk2271.nordvpn.com\nIP: 1.2.3.4\nCountry: United Kingdom\nCity: London\nCurrent technology: NORDLYNX",
		"nordvpn settings":        "Kill Switch: enabled\nDNS: 192.168.1.53, 192.168.1.54",
		"tailscale status --json": `{"BackendState":"Running"}`,
	}}
	st := readStatus(context.Background(), f, []string{"192.168.1.53"})
	if !st.Connected || st.Country != "United Kingdom" || !st.KillSwitch || !st.PiholeDNS || st.Tailscale != "up" || st.Version != "5.4.0" {
		t.Fatalf("unexpected status: %+v", st)
	}
	st = readStatus(context.Background(), &fakeRunner{has: map[string]bool{}}, nil)
	if st.NordInstalled || st.Tailscale != "absent" {
		t.Fatalf("absent tools mis-reported: %+v", st)
	}
}

func TestConnectSuccessSetsBaseline(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{
		"nordvpn connect United_Kingdom": "You are connected to United Kingdom #2271 (uk2271.nordvpn.com)!"}}
	a := newTestAgent(f, func(context.Context) error { return nil })
	r := a.Execute(context.Background(), proto.Command{ID: "1", Type: proto.CmdConnect, Country: "United_Kingdom"})
	if !r.OK {
		t.Fatalf("expected success: %+v", r)
	}
	for _, want := range []string{"allowlist add subnet 192.168.1.0/24", "allowlist add subnet 100.64.0.0/10", "set lan-discovery off"} {
		if !f.called(want) {
			t.Errorf("baseline missing %q; calls=%v", want, f.calls)
		}
	}
	// the allowlist must be in place BEFORE connecting
	ci, ai := -1, -1
	for i, c := range f.calls {
		if strings.HasPrefix(c, "nordvpn connect") {
			ci = i
		}
		if strings.Contains(c, "allowlist add subnet 192.168.1.0/24") {
			ai = i
		}
	}
	if !(ai >= 0 && ai < ci) {
		t.Fatalf("allowlist (%d) must precede connect (%d)", ai, ci)
	}
}

func TestConnectRollsBackWhenUnhealthy(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{
		"nordvpn connect Germany": "You are connected to Germany #1 (de1.nordvpn.com)!"}}
	a := newTestAgent(f, func(context.Context) error { return errors.New("DNS not working") })
	r := a.Execute(context.Background(), proto.Command{ID: "2", Type: proto.CmdConnect, Country: "Germany"})
	if r.OK || !strings.Contains(r.Message, "rolled back") {
		t.Fatalf("expected rollback, got %+v", r)
	}
	if !f.called("set killswitch off") || !f.called("nordvpn disconnect") {
		t.Fatalf("rollback must disable the kill switch and disconnect; calls=%v", f.calls)
	}
}

func TestRateLimitBacksOff(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{
		"nordvpn connect Germany": "ERR:Too many connection attempts. Wait a while before trying again."}}
	a := newTestAgent(f, func(context.Context) error { return nil })
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdConnect, Country: "Germany"})
	if r.OK || !strings.Contains(r.Message, "Backing off") {
		t.Fatalf("got %+v", r)
	}
	n := len(f.calls)
	r = a.Execute(context.Background(), proto.Command{Type: proto.CmdConnect, Country: "Germany"})
	if r.OK || !strings.Contains(r.Message, "rate-limiting") || len(f.calls) != n {
		t.Fatalf("second attempt must not call nordvpn during backoff: %+v calls=%v", r, f.calls[n:])
	}
}

func TestKillSwitchRefusedWhileDisconnected(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{"nordvpn status": "Status: Disconnected"}}
	a := newTestAgent(f, func(context.Context) error { return nil })
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdKillSwitch, Value: "on"})
	if r.OK || f.called("set killswitch on") {
		t.Fatalf("must refuse: %+v calls=%v", r, f.calls)
	}
}

func TestPiholeDNSRevertsOnBadDNS(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{"nordvpn status": "Status: Connected"}}
	a := newTestAgent(f, func(context.Context) error { return errors.New("DNS not working") })
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdPiholeDNS, Value: "on"})
	if r.OK || !strings.Contains(r.Message, "reverted") || !f.called("set dns off") {
		t.Fatalf("expected revert: %+v calls=%v", r, f.calls)
	}
}

func TestMissingNordReported(t *testing.T) {
	a := newTestAgent(&fakeRunner{has: map[string]bool{}}, func(context.Context) error { return nil })
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdConnect, Country: "Germany"})
	if r.OK || !strings.Contains(r.Message, "not installed") {
		t.Fatalf("got %+v", r)
	}
}

func TestReadStatusSurfacesCLIErrors(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{
		"nordvpn --version": "ERR:[Fatal] cannot get user home dir"}}
	st := readStatus(context.Background(), f, nil)
	if !strings.Contains(st.Error, "cannot get user home dir") {
		t.Fatalf("CLI error must reach the panel, got %+v", st)
	}
}
