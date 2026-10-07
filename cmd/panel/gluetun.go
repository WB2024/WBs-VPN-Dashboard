package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

// Gluetun devices are containers (for example qBittorrent behind a Nord WireGuard tunnel). The panel talks to Gluetun's own control
// API: GET /v1/vpn/status, GET /v1/publicip/ip, PUT /v1/vpn/status {"status":"running|stopped"} and
// PUT /v1/vpn/settings {"provider":{"server_selection":{"countries":["germany"]}}} (switches country without recreating the container).

const gluetunPoll = 5 * time.Second

// privateIP reports whether ip is somewhere the panel may call: loopback, RFC1918, link-local or Tailscale's range.
func privateIP(ip net.IP) bool {
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		return true
	}
	_, cgnat, _ := net.ParseCIDR("100.64.0.0/10")
	return cgnat.Contains(ip)
}

// safeClient only ever connects to private addresses, checked at dial time (so DNS tricks cannot point it at the internet).
func safeClient(timeout time.Duration) *http.Client {
	d := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if !privateIP(ip.IP) {
					return nil, fmt.Errorf("refusing to connect to non-private address %s", ip.IP)
				}
			}
			return d.DialContext(ctx, network, net.JoinHostPort(ips[0].IP.String(), port))
		}}}
}

func validGluetunURL(raw string) (string, error) {
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return "", errors.New("url must look like http://192.168.1.110:18010")
	}
	if ip := net.ParseIP(u.Hostname()); ip != nil && !privateIP(ip) {
		return "", errors.New("url must point at a private address")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host, "/"), nil
}

type gluetunAPI struct {
	base, key string
	c         *http.Client
}

func newGluetun(t gluetunTarget) gluetunAPI {
	return gluetunAPI{t.URL, t.Key, safeClient(8 * time.Second)}
}

func (g gluetunAPI) call(method, path string, body any, out any) error {
	var rd io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, g.base+path, rd)
	if err != nil {
		return err
	}
	req.Header.Set("X-API-Key", g.key)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := g.c.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode == http.StatusUnauthorized {
		return errors.New("Gluetun rejected the API key")
	}
	if resp.StatusCode >= 300 {
		return fmt.Errorf("Gluetun returned %s: %s", resp.Status, strings.TrimSpace(string(b)))
	}
	if out != nil && len(b) > 0 {
		return json.Unmarshal(b, out)
	}
	return nil
}

type gluetunInfo struct {
	Running           bool
	IP, Country, City string
	SelectedCountry   string
	Err               error
}

func (g gluetunAPI) info() gluetunInfo {
	var in gluetunInfo
	var st struct{ Status string }
	if in.Err = g.call("GET", "/v1/vpn/status", nil, &st); in.Err != nil {
		return in
	}
	in.Running = st.Status == "running"
	var set struct {
		Provider struct {
			ServerSelection struct{ Countries []string } `json:"server_selection"`
		}
	}
	if g.call("GET", "/v1/vpn/settings", nil, &set) == nil && len(set.Provider.ServerSelection.Countries) > 0 {
		in.SelectedCountry = set.Provider.ServerSelection.Countries[0]
	}
	if in.Running {
		var ip struct {
			PublicIP string `json:"public_ip"`
			Country  string
			City     string
		}
		if g.call("GET", "/v1/publicip/ip", nil, &ip) == nil {
			in.IP, in.Country, in.City = ip.PublicIP, ip.Country, ip.City
		}
	}
	return in
}

func gluetunStatus(in gluetunInfo) proto.Status {
	st := proto.Status{NordInstalled: true, KillSwitch: true, Tailscale: "absent", DNSMode: proto.DNSNord, AgentVersion: "gluetun"}
	if in.Running && in.IP != "" {
		st.Connected, st.Country, st.City, st.IP = true, in.Country, in.City, in.IP
	}
	return st
}

// gluetunCountry converts a panel country (United_Kingdom) to Gluetun's form (united kingdom).
func gluetunCountry(c string) string { return strings.ToLower(strings.ReplaceAll(c, "_", " ")) }

// runGluetunLoop keeps the status of every Gluetun device fresh.
func (s *Server) runGluetunLoop() {
	t := time.NewTicker(gluetunPoll)
	for range t.C {
		for _, tg := range s.store.GluetunTargets() {
			go func(tg gluetunTarget) {
				in := newGluetun(tg).info()
				st := gluetunStatus(in)
				if in.Err != nil {
					st.Error = "Gluetun unreachable: " + in.Err.Error()
				}
				s.store.SetPolled(tg.ID, st, in.Err == nil)
			}(tg)
		}
	}
}

// execGluetun runs connect / disconnect against Gluetun and records the result.
func (s *Server) execGluetun(tg gluetunTarget, c proto.Command) {
	g := newGluetun(tg)
	res := proto.Result{CommandID: c.ID, Type: c.Type}
	var msg string
	var err error
	switch c.Type {
	case proto.CmdConnect:
		msg, err = s.gluetunConnect(g, c.Country)
	case proto.CmdDisconnect:
		if err = g.call("PUT", "/v1/vpn/status", map[string]string{"status": "stopped"}, nil); err == nil {
			msg = "VPN stopped: the container has no internet until you connect again"
		}
	}
	res.OK, res.Message, res.At = err == nil, msg, time.Now().Unix()
	if err != nil {
		res.Message = err.Error()
	}
	s.store.FinishExec(tg.ID, res)
}

func (s *Server) gluetunConnect(g gluetunAPI, country string) (string, error) {
	want := gluetunCountry(country)
	body := map[string]any{"provider": map[string]any{"server_selection": map[string]any{"countries": []string{want}}}}
	if err := g.call("PUT", "/v1/vpn/settings", body, nil); err != nil {
		return "", fmt.Errorf("could not select %s: %v", country, err)
	}
	if err := g.call("PUT", "/v1/vpn/status", map[string]string{"status": "running"}, nil); err != nil {
		return "", err
	}
	deadline := time.Now().Add(120 * time.Second)
	for time.Now().Before(deadline) {
		time.Sleep(3 * time.Second)
		in := g.info()
		if in.Err == nil && in.Running && in.IP != "" && strings.EqualFold(in.Country, strings.ReplaceAll(want, "_", " ")) {
			return fmt.Sprintf("connected: %s, %s (%s)", in.Country, in.City, in.IP), nil
		}
	}
	return "", errors.New("timed out waiting for the tunnel to come up in " + country + " (Gluetun keeps retrying on its own)")
}
