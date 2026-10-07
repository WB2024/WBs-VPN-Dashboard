// Command agent runs on each managed device: it polls the panel and applies VPN commands via the local CLIs.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

func getenv(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func split(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

func main() {
	panel, token := os.Getenv("PANEL_URL"), os.Getenv("TOKEN")
	if panel == "" || token == "" {
		log.Fatal("PANEL_URL and TOKEN are required")
	}
	// LAN and Tailscale ranges stay reachable while the VPN is up. Override per device if your LAN differs.
	subnets := split(getenv("ALLOW_SUBNETS", "192.168.1.0/24,100.64.0.0/10"))
	pihole := split(getenv("PIHOLE_DNS", "192.168.1.53,192.168.1.54"))
	a := NewAgent(execRunner{}, panel, subnets, pihole)
	a.localDomains = split(getenv("LOCAL_DOMAINS", "wbhomelab,1.168.192.in-addr.arpa"))
	a.localCheck = os.Getenv("LOCAL_CHECK")
	a.stateFile = getenv("STATE_FILE", "/var/lib/wbs-vpn/state.json")
	a.loadState()

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	log.Printf("wbs-vpn-agent %s polling %s", version, a.panelURL)
	a.Loop(ctx, token)
}

// Loop polls until ctx is cancelled. Each poll reports status and the previous command's result.
func (a *Agent) Loop(ctx context.Context, token string) {
	var last *proto.Result
	fails := 0
	for ctx.Err() == nil {
		st := readStatus(ctx, a.run, a.piholeIPs)
		st.DNSMode = a.dns.Mode
		st.PiholeDNS = a.dns.Mode == proto.DNSPihole
		resp, err := a.poll(ctx, token, proto.PollRequest{Status: st, LastResult: last})
		if err != nil {
			fails++
			wait := time.Duration(min(fails, 12)) * 5 * time.Second
			log.Printf("poll failed (%d): %v; retrying in %s", fails, err, wait)
			select {
			case <-ctx.Done():
			case <-time.After(wait):
			}
			continue
		}
		fails, last = 0, nil
		if resp.Command != nil {
			log.Printf("command %s %s %s", resp.Command.Type, resp.Command.Country, resp.Command.Value)
			r := a.Execute(ctx, *resp.Command)
			log.Printf("  -> ok=%v %s", r.OK, r.Message)
			last = &r
		}
	}
}

func (a *Agent) poll(ctx context.Context, token string, req proto.PollRequest) (proto.PollResponse, error) {
	var out proto.PollResponse
	body, _ := json.Marshal(req)
	hr, err := http.NewRequestWithContext(ctx, http.MethodPost, a.panelURL+"/agent/v1/poll", bytes.NewReader(body))
	if err != nil {
		return out, err
	}
	hr.Header.Set("Authorization", "Bearer "+token)
	hr.Header.Set("Content-Type", "application/json")
	resp, err := a.http.Do(hr)
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return out, errors.New("panel rejected the token (device removed or token rotated)")
	}
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("panel returned %s", resp.Status)
	}
	return out, json.NewDecoder(resp.Body).Decode(&out)
}
