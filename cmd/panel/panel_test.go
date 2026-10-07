package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

const testKey = "0123456789abcdef0123456789abcdef"

func newTestServer(t *testing.T) (*Server, http.Handler) {
	t.Helper()
	st, err := OpenStore(filepath.Join(t.TempDir(), "devices.json"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{store: st, apiKey: testKey, agentDir: t.TempDir()}
	return s, s.routes()
}

func do(h http.Handler, method, path, key string, body any) *httptest.ResponseRecorder {
	var rd *bytes.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		rd = bytes.NewReader(b)
	} else {
		rd = bytes.NewReader(nil)
	}
	r := httptest.NewRequest(method, path, rd)
	if key != "" {
		r.Header.Set("X-API-Key", key)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}

func TestAPIRequiresKey(t *testing.T) {
	_, h := newTestServer(t)
	if w := do(h, "GET", "/api/v1/devices", "", nil); w.Code != 401 {
		t.Fatalf("no key: %d", w.Code)
	}
	if w := do(h, "GET", "/api/v1/devices", "wrong", nil); w.Code != 401 {
		t.Fatalf("wrong key: %d", w.Code)
	}
	if w := do(h, "GET", "/api/v1/devices", testKey, nil); w.Code != 200 {
		t.Fatalf("good key: %d", w.Code)
	}
}

func TestAddDeviceAndCommandFlow(t *testing.T) {
	s, h := newTestServer(t)
	w := do(h, "POST", "/api/v1/devices", testKey, map[string]string{"name": "laptop"})
	if w.Code != 201 {
		t.Fatalf("add: %d %s", w.Code, w.Body)
	}
	var added struct {
		Device  DeviceView
		Token   string
		Install string
	}
	json.Unmarshal(w.Body.Bytes(), &added)
	if len(added.Token) != 48 || !strings.Contains(added.Install, "TOKEN="+added.Token) {
		t.Fatalf("bad token/install: %+v", added)
	}
	if strings.Contains(w.Body.String(), "token_hash") {
		t.Fatal("token hash leaked")
	}
	// stored hashed, never in plaintext
	b, _ := readFile(s.store.path)
	if strings.Contains(string(b), added.Token) {
		t.Fatal("plaintext token persisted")
	}

	id := added.Device.ID
	if w := do(h, "POST", "/api/v1/devices/"+id+"/command", testKey, proto.Command{Type: "rm -rf"}); w.Code != 400 {
		t.Fatalf("unknown command must be rejected: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/devices/"+id+"/command", testKey, proto.Command{Type: "connect", Country: "UK; reboot"}); w.Code != 400 {
		t.Fatalf("bad country must be rejected: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/devices/"+id+"/command", testKey, proto.Command{Type: "connect", Country: "United_Kingdom"}); w.Code != 202 {
		t.Fatalf("queue: %d %s", w.Code, w.Body)
	}

	// agent polls with its token and receives the command at once
	pr := httptest.NewRequest("POST", "/agent/v1/poll", strings.NewReader(`{"status":{"nord_installed":true}}`))
	pr.Header.Set("Authorization", "Bearer "+added.Token)
	pw := httptest.NewRecorder()
	h.ServeHTTP(pw, pr)
	var resp proto.PollResponse
	json.Unmarshal(pw.Body.Bytes(), &resp)
	if pw.Code != 200 || resp.Command == nil || resp.Command.Country != "United_Kingdom" {
		t.Fatalf("poll: %d %s", pw.Code, pw.Body)
	}

	// result reported on the next poll clears in-flight and is shown
	pr = httptest.NewRequest("POST", "/agent/v1/poll", strings.NewReader(`{"status":{},"last_result":{"command_id":"`+resp.Command.ID+`","type":"connect","ok":true,"message":"connected"}}`))
	pr.Header.Set("Authorization", "Bearer "+added.Token)
	done := make(chan struct{})
	go func() { h.ServeHTTP(httptest.NewRecorder(), pr); close(done) }()
	// wake the long poll so the test does not wait 25s
	s.store.Notifier(id) <- struct{}{}
	<-done
	v, _ := s.store.Get(id)
	if v.Inflight != nil || len(v.Results) != 1 || !v.Results[0].OK || !v.Online {
		t.Fatalf("state after result: %+v", v)
	}
}

func TestPollRejectsBadToken(t *testing.T) {
	_, h := newTestServer(t)
	r := httptest.NewRequest("POST", "/agent/v1/poll", strings.NewReader("{}"))
	r.Header.Set("Authorization", "Bearer nope")
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 401 {
		t.Fatalf("got %d", w.Code)
	}
}

func TestRotateInvalidatesOldToken(t *testing.T) {
	s, h := newTestServer(t)
	_, old, _ := s.store.Add("pc")
	id, _ := s.store.Authenticate(old)
	fresh, _ := s.store.Rotate(id)
	if _, ok := s.store.Authenticate(old); ok {
		t.Fatal("old token still valid")
	}
	if _, ok := s.store.Authenticate(fresh); !ok {
		t.Fatal("new token invalid")
	}
	_ = h
}

func TestDuplicateNameAndValidation(t *testing.T) {
	_, h := newTestServer(t)
	do(h, "POST", "/api/v1/devices", testKey, map[string]string{"name": "pc"})
	if w := do(h, "POST", "/api/v1/devices", testKey, map[string]string{"name": "pc"}); w.Code != 409 {
		t.Fatalf("dup: %d", w.Code)
	}
	if w := do(h, "POST", "/api/v1/devices", testKey, map[string]string{"name": "bad;name"}); w.Code != 400 {
		t.Fatalf("invalid: %d", w.Code)
	}
}

func TestInstallScriptBakesPanelURL(t *testing.T) {
	s, h := newTestServer(t)
	s.public = "http://vpn.wbhomelab"
	w := do(h, "GET", "/install.sh", "", nil)
	if w.Code != 200 || !strings.Contains(w.Body.String(), `PANEL="http://vpn.wbhomelab"`) {
		t.Fatalf("%d %s", w.Code, w.Body.String()[:80])
	}
}

func TestDownloadRejectsPathTricks(t *testing.T) {
	_, h := newTestServer(t)
	for _, p := range []string{"/dl/..%2Fetc%2Fpasswd", "/dl/wbs-vpn-agent-linux-..%2Fx", "/dl/other"} {
		if w := do(h, "GET", p, "", nil); w.Code != 404 {
			t.Errorf("%s -> %d", p, w.Code)
		}
	}
}
