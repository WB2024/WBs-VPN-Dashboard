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

// ---- DNS modes -------------------------------------------------------------------------------------------------

func resolvedRunner(connected bool) *fakeRunner {
	st := "Status: Disconnected"
	if connected {
		st = "Status: Connected"
	}
	return &fakeRunner{has: map[string]bool{"nordvpn": true, "resolvectl": true, "ip": true}, responses: map[string]string{
		"nordvpn status":               st,
		"ip -o route get 192.168.1.53": "192.168.1.53 dev eth0 src 192.168.1.48 uid 1000",
		"resolvectl domain eth0":       "Link 2 (eth0): lan",
	}}
}

func (f *fakeRunner) index(sub string) int {
	for i, c := range f.calls {
		if strings.Contains(c, sub) {
			return i
		}
	}
	return -1
}

func dnsAgent(f *fakeRunner, healthy func(context.Context) error) *Agent {
	a := newTestAgent(f, healthy)
	a.localDomains = []string{"wbhomelab", "1.168.192.in-addr.arpa"}
	a.piholeIPs = []string{"192.168.1.53", "192.168.1.54"}
	return a
}

func TestSplitModeOnResolved(t *testing.T) {
	f := resolvedRunner(true)
	a := dnsAgent(f, func(context.Context) error { return nil })
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdDNSMode, Value: "split"})
	if !r.OK {
		t.Fatalf("%+v calls=%v", r, f.calls)
	}
	for _, want := range []string{"allowlist add port 53", "set dns off", "resolvectl domain eth0 lan ~wbhomelab ~1.168.192.in-addr.arpa"} {
		if !f.called(want) {
			t.Errorf("missing %q in %v", want, f.calls)
		}
	}
	if f.called("set dns 192.168.1.53") {
		t.Fatal("must never put a LAN address on Nord's tunnel link on a resolved host")
	}
	if a.dns.Mode != proto.DNSSplit || !a.dns.Touched || a.dns.Link != "eth0" || strings.Join(a.dns.Orig, " ") != "lan" {
		t.Fatalf("state: %+v", a.dns)
	}
}

func TestPiholeModeOnResolvedMakesLANTheCatchAll(t *testing.T) {
	f := resolvedRunner(true)
	a := dnsAgent(f, func(context.Context) error { return nil })
	if r := a.Execute(context.Background(), proto.Command{Type: proto.CmdDNSMode, Value: "pihole"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if !f.called("resolvectl domain eth0 lan ~.") || !f.called("resolvectl default-route nordlynx no") {
		t.Fatalf("calls=%v", f.calls)
	}
}

func TestPiholeModeWithoutResolvedUsesNordCustomDNS(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{"nordvpn status": "Status: Connected"}}
	a := dnsAgent(f, func(context.Context) error { return nil })
	if r := a.Execute(context.Background(), proto.Command{Type: proto.CmdDNSMode, Value: "pihole"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if !f.called("allowlist add port 53") || !f.called("set dns 192.168.1.53 192.168.1.54") {
		t.Fatalf("calls=%v", f.calls)
	}
}

func TestSplitModeNeedsResolved(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{"nordvpn status": "Status: Connected"}}
	a := dnsAgent(f, func(context.Context) error { return nil })
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdDNSMode, Value: "split"})
	if r.OK || !strings.Contains(r.Message, "systemd-resolved") || a.dns.Mode != proto.DNSNord {
		t.Fatalf("%+v mode=%s", r, a.dns.Mode)
	}
}

func TestBadDNSModeIsRevertedAndLinkRestored(t *testing.T) {
	f := resolvedRunner(true)
	a := dnsAgent(f, func(context.Context) error { return errors.New("DNS not working") })
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdDNSMode, Value: "pihole"})
	if r.OK || !strings.Contains(r.Message, "reverted to nord") {
		t.Fatalf("%+v", r)
	}
	last := ""
	for _, c := range f.calls {
		if strings.HasPrefix(c, "resolvectl domain eth0 ") {
			last = c
		}
	}
	if last != "resolvectl domain eth0 lan" || a.dns.Touched || a.dns.Mode != proto.DNSNord {
		t.Fatalf("link not restored: last=%q state=%+v", last, a.dns)
	}
	if !f.called("allowlist remove port 53") {
		t.Fatalf("port 53 allowlist must be removed again; calls=%v", f.calls)
	}
}

func TestModeWhileDisconnectedDoesNotTouchLink(t *testing.T) {
	f := resolvedRunner(false)
	a := dnsAgent(f, func(context.Context) error { return nil })
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdDNSMode, Value: "split"})
	if !r.OK || !strings.Contains(r.Message, "when connected") {
		t.Fatalf("%+v", r)
	}
	if f.called("resolvectl domain eth0 lan") {
		t.Fatalf("must not touch the LAN link while disconnected: %v", f.calls)
	}
}

func TestConnectAppliesStoredModeAndDisconnectRestores(t *testing.T) {
	f := resolvedRunner(true)
	f.responses["nordvpn connect Germany"] = "You are connected to Germany #1 (de1.nordvpn.com)!"
	a := dnsAgent(f, func(context.Context) error { return nil })
	a.dns.Mode = proto.DNSSplit
	if r := a.Execute(context.Background(), proto.Command{Type: proto.CmdConnect, Country: "Germany"}); !r.OK {
		t.Fatalf("%+v", r)
	}
	if !(f.index("nordvpn connect") < f.index("~wbhomelab")) {
		t.Fatalf("link must be steered AFTER the tunnel exists: %v", f.calls)
	}
	f.calls = nil
	a.Execute(context.Background(), proto.Command{Type: proto.CmdDisconnect})
	if !f.called("resolvectl domain eth0 lan") || a.dns.Touched {
		t.Fatalf("disconnect must restore the link: %v %+v", f.calls, a.dns)
	}
	if a.dns.Mode != proto.DNSSplit {
		t.Fatal("the chosen mode must survive a disconnect")
	}
}

func TestConnectRollsBackWhenModeBreaksDNS(t *testing.T) {
	f := resolvedRunner(true)
	f.responses["nordvpn connect Germany"] = "You are connected to Germany #1 (de1.nordvpn.com)!"
	a := dnsAgent(f, func(context.Context) error { return errors.New("DNS not working") })
	a.dns.Mode = proto.DNSPihole
	r := a.Execute(context.Background(), proto.Command{Type: proto.CmdConnect, Country: "Germany"})
	if r.OK || !strings.Contains(r.Message, "rolled back") || a.dns.Touched || !f.called("nordvpn disconnect") {
		t.Fatalf("%+v touched=%v calls=%v", r, a.dns.Touched, f.calls)
	}
}

func TestOwnChangesAreNeverRecordedAsOriginal(t *testing.T) {
	f := resolvedRunner(true)
	f.responses["resolvectl domain eth0"] = "Link 2 (eth0): lan ~. ~wbhomelab ~1.168.192.in-addr.arpa"
	a := dnsAgent(f, nil)
	if got := strings.Join(a.linkDomains(context.Background(), "eth0"), " "); got != "lan" {
		t.Fatalf("got %q", got)
	}
}

func TestStatePersistsAcrossRestart(t *testing.T) {
	f := resolvedRunner(true)
	a := dnsAgent(f, func(context.Context) error { return nil })
	a.stateFile = t.TempDir() + "/state.json"
	a.Execute(context.Background(), proto.Command{Type: proto.CmdDNSMode, Value: "split"})
	b := dnsAgent(resolvedRunner(true), nil)
	b.stateFile = a.stateFile
	b.loadState()
	if b.dns.Mode != proto.DNSSplit || !b.dns.Touched || b.dns.Link != "eth0" {
		t.Fatalf("not restored: %+v", b.dns)
	}
}

func TestLegacyPiholeCommandMapsToModes(t *testing.T) {
	f := &fakeRunner{has: map[string]bool{"nordvpn": true}, responses: map[string]string{"nordvpn status": "Status: Disconnected"}}
	a := dnsAgent(f, func(context.Context) error { return nil })
	a.Execute(context.Background(), proto.Command{Type: proto.CmdPiholeDNS, Value: "on"})
	if a.dns.Mode != proto.DNSPihole {
		t.Fatalf("on -> %s", a.dns.Mode)
	}
	a.Execute(context.Background(), proto.Command{Type: proto.CmdPiholeDNS, Value: "off"})
	if a.dns.Mode != proto.DNSNord {
		t.Fatalf("off -> %s", a.dns.Mode)
	}
}
