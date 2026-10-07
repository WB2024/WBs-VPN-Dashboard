// Command panel is the WB's VPN Dashboard server: it keeps the device list, queues commands for the
// agents and serves the JSON API (used by Glance) and a small fallback web page.
package main

import (
	"crypto/subtle"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

//go:embed web/index.html
var webFS embed.FS

var (
	nameRe    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9 ._-]{0,39}$`)
	countryRe = regexp.MustCompile(`^[A-Za-z][A-Za-z_ ]{1,38}$`)
	archRe    = regexp.MustCompile(`^[a-z0-9]+$`)
)

const pollHold = 25 * time.Second

type Server struct {
	store    *Store
	apiKey   string
	agentDir string
	public   string // public base URL used inside install commands
}

func main() {
	apiKey := os.Getenv("API_KEY")
	if len(apiKey) < 24 {
		log.Fatal("API_KEY must be set (24+ characters); generate one with: openssl rand -hex 24")
	}
	dataDir := env("DATA_DIR", "/data")
	st, err := OpenStore(filepath.Join(dataDir, "devices.json"))
	if err != nil {
		log.Fatalf("open store: %v", err)
	}
	s := &Server{store: st, apiKey: apiKey, agentDir: env("AGENT_DIR", "/app/agents"), public: strings.TrimRight(os.Getenv("PUBLIC_URL"), "/")}
	go s.runGluetunLoop()
	addr := env("LISTEN", ":8080")
	log.Printf("wbs-vpn-dashboard panel listening on %s (%d devices)", addr, len(st.List()))
	srv := &http.Server{Addr: addr, Handler: s.routes(), ReadHeaderTimeout: 10 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok")) })
	mux.HandleFunc("GET /{$}", s.ui)
	// agents
	mux.HandleFunc("POST /agent/v1/poll", s.poll)
	mux.HandleFunc("GET /dl/{file}", s.download)
	mux.HandleFunc("GET /install.sh", s.installScript)
	// api
	mux.HandleFunc("GET /api/v1/devices", s.api(s.listDevices))
	mux.HandleFunc("POST /api/v1/devices", s.api(s.addDevice))
	mux.HandleFunc("DELETE /api/v1/devices/{id}", s.api(s.deleteDevice))
	mux.HandleFunc("POST /api/v1/devices/{id}/token", s.api(s.rotateToken))
	mux.HandleFunc("POST /api/v1/devices/{id}/command", s.api(s.command))
	return mux
}

// ---- helpers

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}

func bearer(r *http.Request) string {
	if k := r.Header.Get("X-API-Key"); k != "" {
		return k
	}
	return strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
}

func (s *Server) api(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if subtle.ConstantTimeCompare([]byte(bearer(r)), []byte(s.apiKey)) != 1 {
			fail(w, http.StatusUnauthorized, "bad or missing API key")
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
		h(w, r)
	}
}

func (s *Server) baseURL(r *http.Request) string {
	if s.public != "" {
		return s.public
	}
	scheme := "http"
	if r.TLS != nil || r.Header.Get("X-Forwarded-Proto") == "https" {
		scheme = "https"
	}
	return scheme + "://" + r.Host
}

// ---- web page

func (s *Server) ui(w http.ResponseWriter, r *http.Request) {
	b, _ := webFS.ReadFile("web/index.html")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Write(b)
}

// ---- API

func (s *Server) listDevices(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"devices": s.store.List(), "countries": Countries})
}

func (s *Server) addDevice(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name, Kind, URL string
		APIKey          string `json:"api_key"`
	}
	if json.NewDecoder(r.Body).Decode(&in) != nil || !nameRe.MatchString(in.Name) {
		fail(w, http.StatusBadRequest, "name must be 1-40 characters: letters, digits, space, . _ -")
		return
	}
	if in.Kind == kindGluetun {
		base, err := validGluetunURL(in.URL)
		if err != nil || len(in.APIKey) < 8 {
			if err == nil {
				err = errors.New("api_key is required")
			}
			fail(w, http.StatusBadRequest, err.Error())
			return
		}
		// prove the URL and key work before saving the device
		if gi := newGluetun(gluetunTarget{URL: base, Key: in.APIKey}).info(); gi.Err != nil {
			fail(w, http.StatusBadGateway, "could not reach Gluetun: "+gi.Err.Error())
			return
		}
		d, err := s.store.AddGluetun(in.Name, base, in.APIKey)
		if err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"device": d})
		return
	}
	d, token, err := s.store.Add(in.Name)
	if err != nil {
		fail(w, http.StatusConflict, err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, map[string]any{"device": d, "token": token, "install": s.installCommand(r, token)})
}

func (s *Server) installCommand(r *http.Request, token string) string {
	base := s.baseURL(r)
	return fmt.Sprintf("curl -fsSL %s/install.sh | sudo TOKEN=%s sh", base, token)
}

func (s *Server) deleteDevice(w http.ResponseWriter, r *http.Request) {
	if err := s.store.Delete(r.PathValue("id")); err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) rotateToken(w http.ResponseWriter, r *http.Request) {
	token, err := s.store.Rotate(r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusNotFound, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"token": token, "install": s.installCommand(r, token)})
}

// validate checks a command from the API against the allow-list before it is queued.
func validate(c proto.Command) error {
	switch c.Type {
	case proto.CmdConnect:
		if !countryRe.MatchString(c.Country) {
			return errors.New("country must be a Nord country name such as United_Kingdom")
		}
	case proto.CmdDisconnect:
	case proto.CmdKillSwitch, proto.CmdPiholeDNS, proto.CmdTailscale:
		if c.Value != "on" && c.Value != "off" {
			return errors.New("value must be on or off")
		}
	case proto.CmdDNSMode:
		if c.Value != proto.DNSNord && c.Value != proto.DNSSplit && c.Value != proto.DNSPihole {
			return errors.New("dns mode must be nord, split or pihole")
		}
	default:
		return errors.New("unknown command type")
	}
	return nil
}

func (s *Server) command(w http.ResponseWriter, r *http.Request) {
	var c proto.Command
	if json.NewDecoder(r.Body).Decode(&c) != nil {
		fail(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	if err := validate(c); err != nil {
		fail(w, http.StatusBadRequest, err.Error())
		return
	}
	c = proto.Command{Type: c.Type, Country: c.Country, Value: c.Value}
	if tg, ok := s.store.Target(r.PathValue("id")); ok { // a Gluetun container: only connect / disconnect make sense
		if c.Type != proto.CmdConnect && c.Type != proto.CmdDisconnect {
			fail(w, http.StatusBadRequest, "this device is a Gluetun container: only connect and disconnect are supported")
			return
		}
		queued, err := s.store.BeginExec(tg.ID, c)
		if err != nil {
			fail(w, http.StatusConflict, err.Error())
			return
		}
		go s.execGluetun(tg, queued)
		writeJSON(w, http.StatusAccepted, queued)
		return
	}
	queued, err := s.store.Enqueue(r.PathValue("id"), c)
	switch {
	case errors.Is(err, errNotFound):
		fail(w, http.StatusNotFound, err.Error())
	case err != nil:
		fail(w, http.StatusConflict, err.Error())
	default:
		writeJSON(w, http.StatusAccepted, queued)
	}
}

// ---- agent endpoints

func (s *Server) poll(w http.ResponseWriter, r *http.Request) {
	id, ok := s.store.Authenticate(bearer(r))
	if !ok {
		fail(w, http.StatusUnauthorized, "unknown device token")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<16)
	var req proto.PollRequest
	if json.NewDecoder(r.Body).Decode(&req) != nil {
		fail(w, http.StatusBadRequest, "invalid JSON")
		return
	}
	s.store.Record(id, req)
	if c := s.store.Next(id); c != nil {
		writeJSON(w, http.StatusOK, proto.PollResponse{Command: c})
		return
	}
	// Long poll: hold the request so a command queued from the UI reaches the device at once.
	wake := s.store.Notifier(id)
	select {
	case <-wake:
	case <-time.After(pollHold):
	case <-r.Context().Done():
		return
	}
	writeJSON(w, http.StatusOK, proto.PollResponse{Command: s.store.Next(id)})
}

func (s *Server) download(w http.ResponseWriter, r *http.Request) {
	f := r.PathValue("file")
	if !strings.HasPrefix(f, "wbs-vpn-agent-linux-") || !archRe.MatchString(strings.TrimPrefix(f, "wbs-vpn-agent-linux-")) {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, filepath.Join(s.agentDir, f))
}

func (s *Server) installScript(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/x-shellscript")
	fmt.Fprint(w, strings.ReplaceAll(installTemplate, "@PANEL@", s.baseURL(r)))
}
