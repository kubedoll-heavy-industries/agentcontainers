// Package adversarial provides reusable primitives for hostile-agent tests.
package adversarial

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
)

// Canary is a marker value that must never leave its intended boundary.
type Canary struct {
	Name  string
	Token string
}

// NewCanary returns a canary with a high-entropy token and a stable prefix.
func NewCanary(name string) (Canary, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return Canary{}, fmt.Errorf("generate canary %q: %w", name, err)
	}
	return Canary{
		Name:  name,
		Token: "ac-canary-" + name + "-" + hex.EncodeToString(raw[:]),
	}, nil
}

// Leak records a canary token observed in a command result or exfil request.
type Leak struct {
	Canary Canary
	Where  string
}

// Corpus is a versioned set of hostile-prompt probes.
type Corpus struct {
	Version int           `json:"version"`
	Prompts []PromptProbe `json:"prompts"`
}

// PromptProbe describes one prompt-injection style instruction and the
// deterministic probe used to test the same boundary.
type PromptProbe struct {
	ID       string   `json:"id"`
	Prompt   string   `json:"prompt"`
	Boundary string   `json:"boundary"`
	Canaries []string `json:"canaries"`
	Probe    []string `json:"probe"`
	Expect   string   `json:"expect"`
}

// LoadCorpus parses a hostile-prompt corpus JSON document.
func LoadCorpus(r io.Reader) (*Corpus, error) {
	var corpus Corpus
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&corpus); err != nil {
		return nil, fmt.Errorf("parse adversarial corpus: %w", err)
	}
	if corpus.Version == 0 {
		return nil, fmt.Errorf("parse adversarial corpus: version is required")
	}
	for i, p := range corpus.Prompts {
		if p.ID == "" {
			return nil, fmt.Errorf("parse adversarial corpus: prompts[%d].id is required", i)
		}
		if len(p.Probe) == 0 {
			return nil, fmt.Errorf("parse adversarial corpus: prompt %q has empty probe", p.ID)
		}
		if p.Expect == "" {
			return nil, fmt.Errorf("parse adversarial corpus: prompt %q has empty expect", p.ID)
		}
	}
	return &corpus, nil
}

// FindLeaks scans text blobs for canary tokens.
func FindLeaks(canaries []Canary, outputs map[string]string) []Leak {
	var leaks []Leak
	for _, c := range canaries {
		if c.Token == "" {
			continue
		}
		for where, out := range outputs {
			if strings.Contains(out, c.Token) {
				leaks = append(leaks, Leak{Canary: c, Where: where})
			}
		}
	}
	return leaks
}

// ExfilServer is a local HTTP sink that records requests containing canaries.
type ExfilServer struct {
	server   *httptest.Server
	canaries []Canary
	mu       sync.Mutex
	hits     []Leak
}

// NewExfilServer starts a local HTTP sink for canary exfiltration attempts.
func NewExfilServer(canaries []Canary) *ExfilServer {
	s := &ExfilServer{canaries: append([]Canary(nil), canaries...)}
	s.server = httptest.NewServer(http.HandlerFunc(s.handle))
	return s
}

// URL returns the HTTP endpoint used by adversarial commands.
func (s *ExfilServer) URL() string {
	return s.server.URL
}

// Close stops the HTTP sink.
func (s *ExfilServer) Close() {
	s.server.Close()
}

// Hits returns recorded canary exfiltration attempts.
func (s *ExfilServer) Hits() []Leak {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]Leak(nil), s.hits...)
}

// Reset clears recorded hits while leaving the server running.
func (s *ExfilServer) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.hits = nil
}

func (s *ExfilServer) handle(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(io.LimitReader(r.Body, 64*1024))
	_ = r.Body.Close()

	observed := fmt.Sprintf("%s %s\n%v\n%s", r.Method, r.URL.String(), r.Header, body)
	leaks := FindLeaks(s.canaries, map[string]string{"http request": observed})
	if len(leaks) > 0 {
		s.mu.Lock()
		s.hits = append(s.hits, leaks...)
		s.mu.Unlock()
	}
	w.WriteHeader(http.StatusNoContent)
}
