package main

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/WB2024/WBs-VPN-Dashboard/internal/proto"
)

const (
	onlineWindow = 60 // seconds without a poll before a device shows as offline
	maxQueued    = 5
	maxResults   = 8
)

// Device is the stored record. TokenHash is never sent to API clients.
type Device struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	TokenHash string          `json:"token_hash"`
	Created   int64           `json:"created"`
	LastSeen  int64           `json:"last_seen"`
	Status    *proto.Status   `json:"status,omitempty"`
	Pending   []proto.Command `json:"pending,omitempty"`
	Inflight  *proto.Command  `json:"inflight,omitempty"`
	Results   []proto.Result  `json:"results,omitempty"`
}

// DeviceView is the API representation of a Device.
type DeviceView struct {
	ID       string          `json:"id"`
	Name     string          `json:"name"`
	Online   bool            `json:"online"`
	LastSeen int64           `json:"last_seen"`
	Status   *proto.Status   `json:"status,omitempty"`
	Pending  []proto.Command `json:"pending"`
	Inflight *proto.Command  `json:"inflight,omitempty"`
	Results  []proto.Result  `json:"results"`
}

type Store struct {
	mu      sync.Mutex
	path    string
	devices map[string]*Device
	notify  map[string]chan struct{}
	now     func() time.Time
}

func OpenStore(path string) (*Store, error) {
	s := &Store{path: path, devices: map[string]*Device{}, notify: map[string]chan struct{}{}, now: time.Now}
	b, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return s, nil
		}
		return nil, err
	}
	var list []*Device
	if err := json.Unmarshal(b, &list); err != nil {
		return nil, err
	}
	for _, d := range list {
		s.devices[d.ID] = d
		s.notify[d.ID] = make(chan struct{}, 1)
	}
	return s, nil
}

func (s *Store) saveLocked() error {
	list := make([]*Device, 0, len(s.devices))
	for _, d := range s.devices {
		list = append(list, d)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Created < list[j].Created })
	b, err := json.MarshalIndent(list, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o755); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, b, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

func randHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}

func hashToken(t string) string {
	h := sha256.Sum256([]byte(t))
	return hex.EncodeToString(h[:])
}

func (d *Device) view(now int64) DeviceView {
	v := DeviceView{ID: d.ID, Name: d.Name, LastSeen: d.LastSeen, Status: d.Status, Inflight: d.Inflight,
		Online: d.LastSeen > 0 && now-d.LastSeen <= onlineWindow, Pending: d.Pending, Results: d.Results}
	if v.Pending == nil {
		v.Pending = []proto.Command{}
	}
	if v.Results == nil {
		v.Results = []proto.Result{}
	}
	return v
}

// Add creates a device and returns it with its one-time plaintext token.
func (s *Store) Add(name string) (DeviceView, string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, d := range s.devices {
		if d.Name == name {
			return DeviceView{}, "", errors.New("a device with that name already exists")
		}
	}
	token := randHex(24)
	d := &Device{ID: randHex(4), Name: name, TokenHash: hashToken(token), Created: s.now().Unix()}
	s.devices[d.ID] = d
	s.notify[d.ID] = make(chan struct{}, 1)
	return d.view(s.now().Unix()), token, s.saveLocked()
}

// Rotate issues a fresh token for a device (the old one stops working at once).
func (s *Store) Rotate(id string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return "", errNotFound
	}
	token := randHex(24)
	d.TokenHash = hashToken(token)
	return token, s.saveLocked()
}

func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.devices[id]; !ok {
		return errNotFound
	}
	delete(s.devices, id)
	delete(s.notify, id)
	return s.saveLocked()
}

func (s *Store) List() []DeviceView {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := s.now().Unix()
	out := make([]DeviceView, 0, len(s.devices))
	for _, d := range s.devices {
		out = append(out, d.view(now))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func (s *Store) Get(id string) (DeviceView, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return DeviceView{}, errNotFound
	}
	return d.view(s.now().Unix()), nil
}

var errNotFound = errors.New("device not found")

// Enqueue validates nothing (the HTTP layer does) and queues a command for a device.
func (s *Store) Enqueue(id string, c proto.Command) (proto.Command, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return c, errNotFound
	}
	if len(d.Pending) >= maxQueued {
		return c, errors.New("too many queued commands for this device")
	}
	c.ID = randHex(4)
	c.Created = s.now().Unix()
	d.Pending = append(d.Pending, c)
	if err := s.saveLocked(); err != nil {
		return c, err
	}
	select {
	case s.notify[id] <- struct{}{}:
	default:
	}
	return c, nil
}

// Authenticate finds the device that owns token (constant-time comparison of hashes).
func (s *Store) Authenticate(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	h := []byte(hashToken(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	found := ""
	for id, d := range s.devices {
		if subtle.ConstantTimeCompare(h, []byte(d.TokenHash)) == 1 {
			found = id
		}
	}
	return found, found != ""
}

// Notifier returns the wake-up channel for a device's long poll.
func (s *Store) Notifier(id string) chan struct{} {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.notify[id]
}

// Record applies an agent's poll: status, last-seen and the result of the previous command.
func (s *Store) Record(id string, req proto.PollRequest) {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok {
		return
	}
	st := req.Status
	d.Status = &st
	d.LastSeen = s.now().Unix()
	if r := req.LastResult; r != nil {
		d.Results = append([]proto.Result{*r}, d.Results...)
		if len(d.Results) > maxResults {
			d.Results = d.Results[:maxResults]
		}
		if d.Inflight != nil && d.Inflight.ID == r.CommandID {
			d.Inflight = nil
		}
	}
	_ = s.saveLocked()
}

// Next pops the next queued command for delivery, marking it in flight.
func (s *Store) Next(id string) *proto.Command {
	s.mu.Lock()
	defer s.mu.Unlock()
	d, ok := s.devices[id]
	if !ok || len(d.Pending) == 0 {
		return nil
	}
	c := d.Pending[0]
	d.Pending = d.Pending[1:]
	d.Inflight = &c
	_ = s.saveLocked()
	return &c
}
