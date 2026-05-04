package cli

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
)

// setupMockRegistry creates an httptest.TLSServer that returns canned digests
// for any manifest HEAD request. It injects the resolver factory and returns
// the server's host:port (for use in image references) and a cleanup function.
func setupMockRegistry(t *testing.T, digests map[string]string) (string, func()) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Extract the tag from /v2/<name>/manifests/<reference>.
		parts := strings.Split(r.URL.Path, "/manifests/")
		if len(parts) == 2 && r.Method == http.MethodHead {
			ref := parts[1]
			if digest, ok := digests[ref]; ok {
				w.Header().Set("Docker-Content-Digest", digest)
				w.WriteHeader(http.StatusOK)
				return
			}
		}
		w.WriteHeader(http.StatusNotFound)
	}))

	client := srv.Client()
	old := resolverFactory
	resolverFactory = func() *oci.Resolver {
		return oci.NewResolver(oci.WithHTTPClient(client))
	}

	// Extract host:port from the server URL (e.g. "https://127.0.0.1:54321" → "127.0.0.1:54321").
	addr := strings.TrimPrefix(srv.URL, "https://")

	return addr, func() {
		resolverFactory = old
		srv.Close()
	}
}

func TestLockCreatesLockfile(t *testing.T) {
	dir := t.TempDir()

	// Use a digest-pinned image so the resolver returns it directly
	// without hitting the network.
	configContent := `{
  "name": "test-lock",
  "image": "alpine:3@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"lock", "--config", configPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("lock command failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "Lockfile written to") {
		t.Errorf("expected 'Lockfile written to' in output, got:\n%s", output)
	}

	// Verify lockfile was created.
	lfPath := filepath.Join(dir, config.LockfileName)
	if _, err := os.Stat(lfPath); err != nil {
		t.Fatalf("expected lockfile to be created at %s: %v", lfPath, err)
	}

	// Verify it's valid JSON and can be loaded.
	lf, err := config.ParseLockfile(lfPath)
	if err != nil {
		t.Fatalf("ParseLockfile() error: %v", err)
	}
	if lf.Version != 2 {
		t.Errorf("lockfile Version = %d, want 2", lf.Version)
	}
	if err := lf.Validate(); err != nil {
		t.Fatalf("generated lockfile should validate: %v", err)
	}
	if lf.Resolved.Image == nil {
		t.Error("lockfile should have an image entry")
	}
	if lf.Resolved.Image.Digest != "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Errorf("image digest = %q, want sha256:e3b0...", lf.Resolved.Image.Digest)
	}
}

func TestLockCustomOutput(t *testing.T) {
	dir := t.TempDir()

	configContent := `{"name": "test", "image": "alpine:3@sha256:abc123"}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	outputPath := filepath.Join(dir, "custom-lock.json")

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"lock", "--config", configPath, "--output", outputPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("lock command failed: %v", err)
	}

	if _, err := os.Stat(outputPath); err != nil {
		t.Fatalf("expected lockfile at custom path %s: %v", outputPath, err)
	}
}

func TestLockMissingConfig(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "nonexistent.json")

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"lock", "--config", configPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for missing config, got nil")
	}
}

func TestLockWithMCPAndSkills(t *testing.T) {
	dir := t.TempDir()

	// All references are digest-pinned so no network calls are needed.
	configContent := `{
  "name": "full-test",
  "image": "alpine:3@sha256:aaa111",
  "features": {
    "ghcr.io/devcontainers/features/node:1@sha256:bbb222": {}
  },
  "agent": {
    "tools": {
      "mcp": {
        "github": {
          "image": "ghcr.io/github/mcp-server:2.1@sha256:ccc333"
        }
      },
      "skills": {
        "code-review": {
          "artifact": "ghcr.io/myorg/skills/code-review:1.2@sha256:ddd444"
        }
      }
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"lock", "--config", configPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("lock command failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "image:") {
		t.Error("expected image line in output")
	}
	if !strings.Contains(output, "feature:") {
		t.Error("expected feature line in output")
	}
	if !strings.Contains(output, "mcp:") {
		t.Error("expected mcp line in output")
	}
	if !strings.Contains(output, "skill:") {
		t.Error("expected skill line in output")
	}

	// Verify lockfile structure.
	lfPath := filepath.Join(dir, config.LockfileName)
	lf, err := config.ParseLockfile(lfPath)
	if err != nil {
		t.Fatalf("ParseLockfile() error: %v", err)
	}
	if len(lf.Resolved.Features) != 1 {
		t.Errorf("len(Features) = %d, want 1", len(lf.Resolved.Features))
	}
	if len(lf.Resolved.MCP) != 1 {
		t.Errorf("len(MCP) = %d, want 1", len(lf.Resolved.MCP))
	}
	if len(lf.Resolved.Skills) != 1 {
		t.Errorf("len(Skills) = %d, want 1", len(lf.Resolved.Skills))
	}

	// Verify actual digests were resolved.
	if lf.Resolved.Image.Digest != "sha256:aaa111" {
		t.Errorf("image digest = %q, want sha256:aaa111", lf.Resolved.Image.Digest)
	}
	for _, feat := range lf.Resolved.Features {
		if feat.Digest != "sha256:bbb222" {
			t.Errorf("feature digest = %q, want sha256:bbb222", feat.Digest)
		}
	}
	if mcp, ok := lf.Resolved.MCP["github"]; !ok {
		t.Error("missing mcp entry for 'github'")
	} else if mcp.Digest != "sha256:ccc333" {
		t.Errorf("mcp digest = %q, want sha256:ccc333", mcp.Digest)
	}
	if skill, ok := lf.Resolved.Skills["code-review"]; !ok {
		t.Error("missing skill entry for 'code-review'")
	} else if skill.Digest != "sha256:ddd444" {
		t.Errorf("skill digest = %q, want sha256:ddd444", skill.Digest)
	}
}

func TestLockWithMockRegistry(t *testing.T) {
	// Test the full flow with a mock registry that resolves tags.
	addr, cleanup := setupMockRegistry(t, map[string]string{
		"3.19":   "sha256:registry-resolved-image-digest",
		"1":      "sha256:registry-resolved-feature-digest",
		"latest": "sha256:registry-resolved-mcp-digest",
	})
	defer cleanup()

	dir := t.TempDir()
	configContent := `{
  "name": "mock-test",
  "image": "` + addr + `/library/alpine:3.19",
  "features": {
    "` + addr + `/devcontainers/features/node:1": {}
  },
  "agent": {
    "tools": {
      "mcp": {
        "test-server": {
          "image": "` + addr + `/myorg/mcp-server:latest"
        }
      }
    }
  }
}`
	configPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"lock", "--config", configPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("lock command failed: %v", err)
	}

	// Read the lockfile and check digests were resolved from the mock registry.
	lfPath := filepath.Join(dir, config.LockfileName)
	data, err := os.ReadFile(lfPath)
	if err != nil {
		t.Fatal(err)
	}

	var lf config.Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		t.Fatal(err)
	}

	if lf.Resolved.Image == nil || lf.Resolved.Image.Digest != "sha256:registry-resolved-image-digest" {
		t.Errorf("image digest = %v, want sha256:registry-resolved-image-digest", lf.Resolved.Image)
	}
}

func TestLockFlagDefaults(t *testing.T) {
	cmd := newLockCmd()

	configFlag := cmd.Flags().Lookup("config")
	if configFlag == nil {
		t.Fatal("expected --config flag")
	}
	if configFlag.DefValue != "" {
		t.Errorf("--config default = %q, want empty", configFlag.DefValue)
	}
	if configFlag.Shorthand != "c" {
		t.Errorf("--config shorthand = %q, want %q", configFlag.Shorthand, "c")
	}

	outputFlag := cmd.Flags().Lookup("output")
	if outputFlag == nil {
		t.Fatal("expected --output flag")
	}
	if outputFlag.DefValue != "" {
		t.Errorf("--output default = %q, want empty", outputFlag.DefValue)
	}
	if outputFlag.Shorthand != "o" {
		t.Errorf("--output shorthand = %q, want %q", outputFlag.Shorthand, "o")
	}
}

func TestLockHelpText(t *testing.T) {
	var outBuf bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&outBuf)
	cmd.SetArgs([]string{"lock", "--help"})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("lock --help failed: %v", err)
	}

	output := outBuf.String()
	if !strings.Contains(output, "lockfile") {
		t.Errorf("expected 'lockfile' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--config") {
		t.Errorf("expected '--config' in help text, got:\n%s", output)
	}
	if !strings.Contains(output, "--output") {
		t.Errorf("expected '--output' in help text, got:\n%s", output)
	}
}
