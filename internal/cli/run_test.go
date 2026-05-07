package cli

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/moby/moby/client"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/orgpolicy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sidecar"
)

func TestMain(m *testing.M) {
	// The package-level logger is nil until PersistentPreRunE runs. Set a nop
	// logger so unit tests that call runEnforcerLiveness do not panic.
	logger = zap.NewNop()
	os.Exit(m.Run())
}

func TestRunCmd_DefaultFlags(t *testing.T) {
	cmd := newRunCmd()

	detach, err := cmd.Flags().GetBool("detach")
	if err != nil {
		t.Fatalf("getting detach flag: %v", err)
	}
	if detach {
		t.Error("detach should default to false")
	}

	timeout, err := cmd.Flags().GetDuration("timeout")
	if err != nil {
		t.Fatalf("getting timeout flag: %v", err)
	}
	if timeout.Hours() != 4 {
		t.Errorf("timeout should default to 4h, got %v", timeout)
	}

	configFlag, err := cmd.Flags().GetString("config")
	if err != nil {
		t.Fatalf("getting config flag: %v", err)
	}
	if configFlag != "" {
		t.Errorf("config should default to empty, got %q", configFlag)
	}

	runtimeFlag, err := cmd.Flags().GetString("runtime")
	if err != nil {
		t.Fatalf("getting runtime flag: %v", err)
	}
	if runtimeFlag != "docker" {
		t.Errorf("runtime should default to 'docker', got %q", runtimeFlag)
	}
}

func TestRunCmd_FlagShortcuts(t *testing.T) {
	cmd := newRunCmd()

	f := cmd.Flags().ShorthandLookup("d")
	if f == nil {
		t.Fatal("expected -d shorthand for --detach")
	}
	if f.Name != "detach" {
		t.Errorf("expected -d to map to 'detach', got %q", f.Name)
	}

	f = cmd.Flags().ShorthandLookup("c")
	if f == nil {
		t.Fatal("expected -c shorthand for --config")
	}
	if f.Name != "config" {
		t.Errorf("expected -c to map to 'config', got %q", f.Name)
	}
}

func TestRunCmd_NoConfigError(t *testing.T) {
	dir := t.TempDir()

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"run"})

	err = cmd.Execute()
	if err == nil {
		t.Fatal("expected error when no config exists")
	}
	if !strings.Contains(err.Error(), "no agentcontainer.json") {
		t.Errorf("expected 'no agentcontainer.json' in error, got: %v", err)
	}
}

func TestRunCmd_ExplicitConfigNotFound(t *testing.T) {
	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"run", "--config", "/nonexistent/path/agentcontainer.json"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for nonexistent config path")
	}
	if !strings.Contains(err.Error(), "loading config") {
		t.Errorf("expected 'loading config' in error, got: %v", err)
	}
}

func TestRunCmd_InvalidJSON(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(cfgPath, []byte("{invalid json"), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"run", "--config", cfgPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for invalid JSON config")
	}
	if !strings.Contains(err.Error(), "loading config") {
		t.Errorf("expected 'loading config' in error, got: %v", err)
	}
}

func TestRunCmd_ValidationError(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"name": "test"}`), 0644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)
	cmd.SetArgs([]string{"run", "--config", cfgPath})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "invalid configuration") {
		t.Errorf("expected 'invalid configuration' in error, got: %v", err)
	}
}

func TestRunCmd_RuntimeSelection(t *testing.T) {
	tests := []struct {
		name        string
		runtime     string
		errContains []string
	}{
		{
			name:    "unknown runtime",
			runtime: "podman",
			// "unknown runtime" is the expected error when policy extraction
			// succeeds or is skipped. "extracting org policy" occurs when the
			// stricter error handling in ExtractPolicy propagates a registry
			// error (e.g. alpine:3.19 image index has no layers field).
			// Either outcome means the run was rejected.
			errContains: []string{"unknown runtime", "extracting org policy"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			cfgPath := filepath.Join(dir, "agentcontainer.json")
			// Set enforcer.required: false so the sidecar auto-start is skipped
			// gracefully and the test can reach the runtime selection step.
			cfg := `{"name":"test","image":"alpine:3.19","agent":{"enforcer":{"required":false}}}`
			if err := os.WriteFile(cfgPath, []byte(cfg), 0644); err != nil {
				t.Fatal(err)
			}

			cmd := newRootCmd("test", "abc", "now")
			var buf bytes.Buffer
			cmd.SetOut(&buf)
			cmd.SetErr(&buf)
			cmd.SetArgs([]string{"run", "--config", cfgPath, "--runtime", tt.runtime})

			err := cmd.Execute()
			if err == nil {
				t.Fatal("expected error")
			}
			matched := false
			for _, want := range tt.errContains {
				if strings.Contains(err.Error(), want) {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("expected error containing one of %v, got: %v", tt.errContains, err)
			}
		})
	}
}

func TestRuntimeAutoFlag(t *testing.T) {
	cmd := newRunCmd()
	if err := cmd.ParseFlags([]string{"--runtime", "auto"}); err != nil {
		t.Fatalf("unexpected error parsing --runtime auto: %v", err)
	}

	runtimeVal, err := cmd.Flags().GetString("runtime")
	if err != nil {
		t.Fatalf("unexpected error getting runtime flag: %v", err)
	}
	if runtimeVal != "auto" {
		t.Errorf("expected runtime %q, got %q", "auto", runtimeVal)
	}
}

func TestRunRuntimeAutoUsesResolvedRuntime(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "agentcontainer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"name":"test","image":"alpine:3.19","agent":{"enforcer":{"required":false}}}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var gotRuntime string
	restoreRunHooks(t)
	runResolveSidecar = func(*cobra.Command, *config.AgentContainer) (*sidecar.SidecarHandle, string, error) {
		return nil, "", nil
	}
	runRuntimeFactory = func(runtimeName string, _ *zap.Logger, _ enforcement.Level) (container.Runtime, error) {
		gotRuntime = runtimeName
		return &recordingRuntime{}, nil
	}
	runExtractPolicy = func(context.Context, string, ...oci.ResolverOption) (*orgpolicy.OrgPolicy, error) {
		return orgpolicy.DefaultPolicy(), nil
	}
	runMergePolicy = func(*orgpolicy.OrgPolicy, *config.AgentContainer) error { return nil }
	runVerifyImageSignature = func(*cobra.Command, *config.AgentContainer, string) error { return nil }

	cmd := newRunCmd()
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	if err := runRun(cmd, true, time.Minute, cfgPath, "auto", true, false); err != nil {
		t.Fatalf("runRun() error = %v", err)
	}
	if gotRuntime == "auto" || gotRuntime == "" {
		t.Fatalf("runRuntimeFactory runtime = %q, want resolved runtime", gotRuntime)
	}
	if gotRuntime != string(container.RuntimeDocker) && gotRuntime != string(container.RuntimeSandbox) {
		t.Fatalf("runRuntimeFactory runtime = %q, want docker or sandbox", gotRuntime)
	}
}

func TestNewRuntime_UnknownRuntime(t *testing.T) {
	tests := []struct {
		name    string
		runtime string
	}{
		{"empty string", ""},
		{"arbitrary string", "runc"},
		{"typo", "dockers"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := newRuntime(tt.runtime, zap.NewNop(), enforcement.LevelNone)
			if err == nil {
				t.Fatal("expected error for unknown runtime")
			}
			if !strings.Contains(err.Error(), "unknown runtime") {
				t.Errorf("expected 'unknown runtime' in error, got: %v", err)
			}
		})
	}
}

func TestLoadConfig_ExplicitPath(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "custom.json")
	if err := os.WriteFile(cfgPath, []byte(`{"name":"explicit","image":"ubuntu:22.04"}`), 0644); err != nil {
		t.Fatal(err)
	}

	cfg, path, err := loadConfig(cfgPath)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "explicit" {
		t.Errorf("expected name 'explicit', got %q", cfg.Name)
	}
	if cfg.Image != "ubuntu:22.04" {
		t.Errorf("expected image 'ubuntu:22.04', got %q", cfg.Image)
	}
	if path != cfgPath {
		t.Errorf("expected path %q, got %q", cfgPath, path)
	}
}

func TestLoadConfig_SearchOrder(t *testing.T) {
	dir := t.TempDir()

	rootCfg := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(rootCfg, []byte(`{"name":"root","image":"alpine:3.19"}`), 0644); err != nil {
		t.Fatal(err)
	}

	dcDir := filepath.Join(dir, ".devcontainer")
	if err := os.Mkdir(dcDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dcDir, "agentcontainer.json"), []byte(`{"name":"devcontainer","image":"node:20"}`), 0644); err != nil {
		t.Fatal(err)
	}

	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(dir); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	cfg, _, err := loadConfig("")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if cfg.Name != "root" {
		t.Errorf("expected name 'root' (from root config), got %q", cfg.Name)
	}
}

func TestLoadConfig_ExplicitPathNotFound(t *testing.T) {
	_, _, err := loadConfig("/definitely/does/not/exist.json")
	if err == nil {
		t.Fatal("expected error for missing file")
	}
	if !strings.Contains(err.Error(), "loading config") {
		t.Errorf("expected 'loading config' in error, got: %v", err)
	}
}

func TestBuildSecretsManager_EnvProvider(t *testing.T) {
	t.Setenv("TEST_BUILD_SECRET", "env-value")

	// Use the env:// URI scheme so params are parsed correctly by ParseSecretURI.
	cfg := parseConfigJSON(t, `{
		"name": "test",
		"image": "alpine:3.19",
		"agent": {
			"secrets": {
				"MY_SECRET": {"provider": "env://TEST_BUILD_SECRET"}
			}
		}
	}`)

	mgr, cleanup, err := buildSecretsManager(context.Background(), cfg)
	if err != nil {
		t.Fatalf("buildSecretsManager() error = %v", err)
	}
	if cleanup != nil {
		defer cleanup()
	}
	if mgr == nil {
		t.Fatal("expected non-nil manager")
	}
	cached := mgr.CachedSecrets()
	if s, ok := cached["MY_SECRET"]; !ok {
		t.Error("expected MY_SECRET in cached secrets")
	} else if string(s.Value) != "env-value" {
		t.Errorf("cached value = %q, want %q", s.Value, "env-value")
	}
}

func TestBuildSecretsManager_UnknownProvider(t *testing.T) {
	cfg := parseConfigJSON(t, `{
		"name": "test",
		"image": "alpine:3.19",
		"agent": {
			"secrets": {
				"BAD": {"provider": "bogus-provider"}
			}
		}
	}`)

	_, _, err := buildSecretsManager(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for unknown provider")
	}
	if !strings.Contains(err.Error(), "unknown secret provider") {
		t.Errorf("error = %q, want contains 'unknown secret provider'", err.Error())
	}
}

func TestBuildSecretsManager_InfisicalXORValidation(t *testing.T) {
	// Only CLIENT_ID set — must error.
	t.Setenv("INFISICAL_CLIENT_ID", "cid")
	t.Setenv("INFISICAL_CLIENT_SECRET", "")

	cfg := parseConfigJSON(t, `{
		"name": "test",
		"image": "alpine:3.19",
		"agent": {
			"secrets": {
				"S": {"provider": "infisical"}
			}
		}
	}`)

	_, _, err := buildSecretsManager(context.Background(), cfg)
	if err == nil {
		t.Fatal("expected error for mismatched Infisical credentials")
	}
	if !strings.Contains(err.Error(), "must both be set") {
		t.Errorf("error = %q, want contains 'must both be set'", err.Error())
	}
}

func TestBuildSecretsManager_URINormalization(t *testing.T) {
	// A Provider field that is a vault:// URI should be normalised to "vault".
	// The actual Vault resolve will fail (no server), but the provider wiring
	// must not return "unknown secret provider".
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:19200")
	t.Setenv("VAULT_TOKEN", "test-token")

	cfg := parseConfigJSON(t, `{
		"name": "test",
		"image": "alpine:3.19",
		"agent": {
			"secrets": {
				"V": {"provider": "vault://myapp/config"}
			}
		}
	}`)

	_, _, err := buildSecretsManager(context.Background(), cfg)
	// Expected: a connection/resolve error from Vault, NOT "unknown secret provider".
	if err != nil && strings.Contains(err.Error(), "unknown secret provider") {
		t.Errorf("URI normalization failed: %v", err)
	}
}

func TestRunEnforcerLiveness_ClosesDeadAfterMaxFails(t *testing.T) {
	// Always return unhealthy.
	probe := func(string) bool { return false }

	ctx, cancel := context.WithCancel(context.Background())
	dead := make(chan struct{})

	// Use a very short interval so the test finishes quickly.
	go runEnforcerLiveness(ctx, cancel, "127.0.0.1:50051", 5*time.Millisecond, 3, dead, probe)

	select {
	case <-dead:
		// Expected: dead channel closed after 3 failures.
	case <-time.After(2 * time.Second):
		t.Fatal("timeout: enforcerDead was never closed")
	}

	// ctx must be cancelled (may race slightly behind dead channel close).
	select {
	case <-ctx.Done():
	case <-time.After(time.Second):
		t.Fatal("context was not cancelled after liveness failure")
	}
}

func TestRunEnforcerLiveness_ResetOnSuccess(t *testing.T) {
	// Fail twice then succeed; dead should never be closed.
	var calls int64
	probe := func(string) bool {
		n := atomic.AddInt64(&calls, 1)
		// First two calls fail, subsequent succeed.
		return n > 2
	}

	ctx, cancel := context.WithCancel(context.Background())
	dead := make(chan struct{})

	done := make(chan struct{})
	go func() {
		defer close(done)
		runEnforcerLiveness(ctx, cancel, "127.0.0.1:50051", 10*time.Millisecond, 3, dead, probe)
	}()

	// Wait long enough for the fail-reset-succeed sequence.
	time.Sleep(200 * time.Millisecond)

	select {
	case <-dead:
		cancel()
		<-done
		t.Fatal("enforcerDead closed unexpectedly: consecutive counter should have reset")
	default:
		// Good — no failure declared.
	}

	// Cancel and wait for the goroutine to finish to avoid data races with
	// subsequent tests that run in the same binary.
	cancel()
	<-done
}

func TestRunEnforcerLiveness_ExitsOnContextCancel(t *testing.T) {
	probe := func(string) bool { return true }

	ctx, cancel := context.WithCancel(context.Background())
	dead := make(chan struct{})

	cancel() // Cancel before the goroutine has a chance to tick.
	// Should return without closing dead or blocking.
	done := make(chan struct{})
	go func() {
		runEnforcerLiveness(ctx, cancel, "127.0.0.1:50051", 1*time.Millisecond, 3, dead, probe)
		close(done)
	}()

	select {
	case <-done:
		// goroutine exited cleanly.
	case <-time.After(1 * time.Second):
		t.Fatal("timeout: liveness goroutine did not exit on context cancel")
	}

	select {
	case <-dead:
		t.Fatal("dead channel closed unexpectedly on context cancel")
	default:
		// Good.
	}
}

// TestPolicyImageRef_WithLockfile verifies that policyImageRef appends the
// lockfile-pinned digest to the image tag, preventing F-4 TOCTOU attacks.
func TestPolicyImageRef_WithLockfile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"name":"t","image":"myrepo/myimage:v1"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	// Write a lockfile with a pinned digest.
	pinnedDigest := "sha256:" + strings.Repeat("a", 64)
	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     pinnedDigest,
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	if err := config.WriteLockfile(filepath.Join(dir, config.LockfileName), lf); err != nil {
		t.Fatalf("WriteLockfile: %v", err)
	}

	got := policyImageRef("myrepo/myimage:v1", cfgPath)
	want := "myrepo/myimage:v1@" + pinnedDigest
	if got != want {
		t.Errorf("policyImageRef() = %q, want %q", got, want)
	}
}

// TestPolicyImageRef_NoLockfile verifies that policyImageRef falls back to the
// mutable tag when no lockfile exists (graceful degradation for `agentcontainer run`
// without a prior `agentcontainer lock`).
func TestPolicyImageRef_NoLockfile(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")
	// No lockfile written.

	got := policyImageRef("myrepo/myimage:v1", cfgPath)
	if got != "myrepo/myimage:v1" {
		t.Errorf("policyImageRef() = %q, want original tag (no lockfile)", got)
	}
}

// TestPolicyImageRef_LockfileNoImageDigest verifies that policyImageRef falls
// back to the mutable tag when the lockfile has no image entry.
func TestPolicyImageRef_LockfileNoImageDigest(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")

	// Write a lockfile without an image entry.
	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved:    config.ResolvedArtifacts{},
	}
	if err := config.WriteLockfile(filepath.Join(dir, config.LockfileName), lf); err != nil {
		t.Fatalf("WriteLockfile: %v", err)
	}

	got := policyImageRef("myrepo/myimage:v1", cfgPath)
	if got != "myrepo/myimage:v1" {
		t.Errorf("policyImageRef() = %q, want original tag (no image in lockfile)", got)
	}
}

// TestPolicyImageRef_StripExistingDigest verifies that policyImageRef strips
// any existing digest from the imageTag before appending the lockfile digest,
// preventing double-@ references like "image:tag@sha256:old@sha256:new".
func TestPolicyImageRef_StripExistingDigest(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")

	pinnedDigest := "sha256:" + strings.Repeat("b", 64)
	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     pinnedDigest,
				ResolvedAt: time.Now().UTC(),
			},
		},
	}
	if err := config.WriteLockfile(filepath.Join(dir, config.LockfileName), lf); err != nil {
		t.Fatalf("WriteLockfile: %v", err)
	}

	// imageTag already has a (stale) digest — it must be replaced.
	staleDigest := "sha256:" + strings.Repeat("0", 64)
	imageTagWithDigest := "myrepo/myimage:v1@" + staleDigest

	got := policyImageRef(imageTagWithDigest, cfgPath)
	want := "myrepo/myimage:v1@" + pinnedDigest
	if got != want {
		t.Errorf("policyImageRef() = %q, want %q", got, want)
	}
	if strings.Count(got, "@") != 1 {
		t.Errorf("policyImageRef() has multiple '@': %q", got)
	}
}

// TestPolicyImageRef_EmptyImage verifies that policyImageRef is a no-op for
// an empty image string.
func TestPolicyImageRef_EmptyImage(t *testing.T) {
	got := policyImageRef("", "/any/path/agentcontainer.json")
	if got != "" {
		t.Errorf("policyImageRef(\"\", ...) = %q, want \"\"", got)
	}
}

// TestVerifyImageSignature_NoProvenanceConfig verifies that verifyImageSignature
// is a no-op when there is no provenance config (F-1: only required when declared).
func TestVerifyImageSignature_NoProvenanceConfig(t *testing.T) {
	cfg := &config.AgentContainer{
		Name:  "test",
		Image: "myrepo/myimage:v1",
	}

	cmd := newRunCmd()
	if err := verifyImageSignature(cmd, cfg, "myrepo/myimage:v1@sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Errorf("verifyImageSignature() error = %v, want nil (no provenance config)", err)
	}
}

// TestVerifyImageSignature_SignaturesNotRequired verifies that verifyImageSignature
// is a no-op when provenance.require.signatures is false.
func TestVerifyImageSignature_SignaturesNotRequired(t *testing.T) {
	cfg := &config.AgentContainer{
		Name:  "test",
		Image: "myrepo/myimage:v1",
		Agent: &config.AgentConfig{
			Provenance: &config.ProvenanceConfig{
				Require: &config.ProvenanceRequirements{
					Signatures: false,
				},
			},
		},
	}

	cmd := newRunCmd()
	if err := verifyImageSignature(cmd, cfg, "myrepo/myimage:v1@sha256:"+strings.Repeat("a", 64)); err != nil {
		t.Errorf("verifyImageSignature() error = %v, want nil (signatures not required)", err)
	}
}

// TestVerifyImageSignature_EmptyRef verifies that verifyImageSignature is a
// no-op for an empty image reference.
func TestVerifyImageSignature_EmptyRef(t *testing.T) {
	cfg := &config.AgentContainer{
		Name:  "test",
		Image: "myrepo/myimage:v1",
		Agent: &config.AgentConfig{
			Provenance: &config.ProvenanceConfig{
				Require: &config.ProvenanceRequirements{
					Signatures: true,
				},
			},
		},
	}

	cmd := newRunCmd()
	if err := verifyImageSignature(cmd, cfg, ""); err != nil {
		t.Errorf("verifyImageSignature() error = %v, want nil (empty ref)", err)
	}
}

// TestVerifyImageSignature_CosignNotInstalled verifies that when signatures are
// required but cosign is not on PATH, verifyImageSignature fails closed rather
// than silently skipping (F-1 fail-closed behavior).
func TestVerifyImageSignature_CosignNotInstalled(t *testing.T) {
	cfg := &config.AgentContainer{
		Name:  "test",
		Image: "myrepo/myimage:v1",
		Agent: &config.AgentConfig{
			Provenance: &config.ProvenanceConfig{
				Require: &config.ProvenanceRequirements{
					Signatures: true,
				},
			},
		},
	}

	// Override PATH so cosign cannot be found.
	t.Setenv("PATH", "")

	cmd := newRunCmd()
	err := verifyImageSignature(cmd, cfg, "myrepo/myimage:v1@sha256:"+strings.Repeat("a", 64))
	if err == nil {
		t.Error("verifyImageSignature() = nil, want error (cosign missing, signatures required)")
		return
	}
	if !strings.Contains(err.Error(), "cosign not found") {
		t.Errorf("verifyImageSignature() error = %q, want 'cosign not found' message", err.Error())
	}
}

func TestRunRun_StartupFailureStopsManagedSidecar(t *testing.T) {
	cfgPath := filepath.Join(t.TempDir(), "agentcontainer.json")
	if err := os.WriteFile(cfgPath, []byte(`{"name":"test","image":"alpine:3.19"}`), 0o644); err != nil {
		t.Fatal(err)
	}

	var stopCalls int
	handle := &sidecar.SidecarHandle{ContainerID: "sidecar-123", Addr: "127.0.0.1:50051", Managed: true}
	restoreRunHooks(t)
	runResolveSidecar = func(*cobra.Command, *config.AgentContainer) (*sidecar.SidecarHandle, string, error) {
		return handle, handle.Addr, nil
	}
	runRuntimeFactory = func(string, *zap.Logger, enforcement.Level) (container.Runtime, error) {
		return &recordingRuntime{startErr: fmt.Errorf("boom")}, nil
	}
	runExtractPolicy = func(context.Context, string, ...oci.ResolverOption) (*orgpolicy.OrgPolicy, error) {
		return nil, nil
	}
	runMergePolicy = func(*orgpolicy.OrgPolicy, *config.AgentContainer) error { return nil }
	runVerifyImageSignature = func(*cobra.Command, *config.AgentContainer, string) error { return nil }
	runNewDockerClient = func() (client.APIClient, error) { return nil, nil }
	runStopSidecar = func(context.Context, client.APIClient, *sidecar.SidecarHandle) error {
		stopCalls++
		return nil
	}

	cmd := newRunCmd()
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetContext(context.Background())

	err := runRun(cmd, false, time.Minute, cfgPath, "docker", false, false)
	if err == nil {
		t.Fatal("expected startup error")
	}
	if !strings.Contains(err.Error(), "starting container") {
		t.Fatalf("unexpected error: %v", err)
	}
	if stopCalls != 1 {
		t.Fatalf("stop sidecar calls = %d, want 1", stopCalls)
	}
	if !strings.Contains(out.String(), "Enforcer stopped") {
		t.Fatalf("expected sidecar teardown message, got %q", out.String())
	}
}

// parseConfigJSON writes JSON to a temp file, parses it, and returns the config.
func parseConfigJSON(t *testing.T, jsonStr string) *config.AgentContainer {
	t.Helper()
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(cfgPath, []byte(jsonStr), 0o644); err != nil {
		t.Fatalf("writeFile: %v", err)
	}
	cfg, err := config.ParseFile(cfgPath)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}
	return cfg
}

func restoreRunHooks(t *testing.T) {
	t.Helper()
	prevRuntimeFactory := runRuntimeFactory
	prevResolveSidecar := runResolveSidecar
	prevExtractPolicy := runExtractPolicy
	prevMergePolicy := runMergePolicy
	prevVerifyImageSignature := runVerifyImageSignature
	prevNewDockerClient := runNewDockerClient
	prevStopSidecar := runStopSidecar
	t.Cleanup(func() {
		runRuntimeFactory = prevRuntimeFactory
		runResolveSidecar = prevResolveSidecar
		runExtractPolicy = prevExtractPolicy
		runMergePolicy = prevMergePolicy
		runVerifyImageSignature = prevVerifyImageSignature
		runNewDockerClient = prevNewDockerClient
		runStopSidecar = prevStopSidecar
	})
}
