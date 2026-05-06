package cli

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
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
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

func init() {
	policySignatureVerifierFactory = func() signing.Verifier {
		return signing.NewMockVerifier()
	}
}

func TestLockPinsConfiguredPolicyChannel(t *testing.T) {
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	policyJSON := policyBundleJSON(t, 3, expiresAt, nil)
	policyRef, manifestDigest, cleanup := setupPolicyBundleRegistry(t, "prod", policyJSON)
	defer cleanup()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "agentcontainer.json")
	imageDigest := "sha256:" + strings.Repeat("a", 64)
	configContent := fmt.Sprintf(`{
  "name": "policy-lock",
  "image": "alpine:3@%s",
  "agent": {
    "provenance": {
      "policy": {"ref": %q}
    }
  }
}`, imageDigest, policyRef)
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"lock", "--config", configPath})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("lock command failed: %v", err)
	}
	if !strings.Contains(out.String(), fmt.Sprintf("policy: %s -> %s (epoch 3)", policyRef, manifestDigest)) {
		t.Fatalf("lock output missing policy pin:\n%s", out.String())
	}

	lf, err := config.ParseLockfile(filepath.Join(dir, config.LockfileName))
	if err != nil {
		t.Fatalf("ParseLockfile: %v", err)
	}
	if lf.Resolved.Policy == nil {
		t.Fatal("Resolved.Policy is nil")
	}
	if lf.Resolved.Policy.Ref != policyRef {
		t.Errorf("Policy.Ref = %q, want %q", lf.Resolved.Policy.Ref, policyRef)
	}
	if lf.Resolved.Policy.Digest != manifestDigest {
		t.Errorf("Policy.Digest = %q, want %q", lf.Resolved.Policy.Digest, manifestDigest)
	}
	if lf.Resolved.Policy.Epoch != 3 {
		t.Errorf("Policy.Epoch = %d, want 3", lf.Resolved.Policy.Epoch)
	}
	if !lf.Resolved.Policy.ExpiresAt.Equal(expiresAt) {
		t.Errorf("Policy.ExpiresAt = %s, want %s", lf.Resolved.Policy.ExpiresAt, expiresAt)
	}
	if lf.Resolved.Policy.Signature == nil {
		t.Fatal("Policy.Signature is nil, want policy channel signature pin")
	}
	if lf.Resolved.Policy.Signature.KeylessRef != digestPinnedRef(policyRef, manifestDigest) {
		t.Errorf("Policy.Signature.KeylessRef = %q, want digest-pinned policy ref", lf.Resolved.Policy.Signature.KeylessRef)
	}
}

func TestVerifyConfiguredPolicyMissingPinStrictFails(t *testing.T) {
	dir := t.TempDir()
	policyRef := "ghcr.io/acme/agentcontainers-policy:prod"
	configPath := writePolicyChannelConfig(t, dir, policyRef, "sha256:"+strings.Repeat("a", 64))
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &config.Lockfile{
		Version:     2,
		GeneratedAt: time.Now().UTC(),
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     "sha256:" + strings.Repeat("a", 64),
				ResolvedAt: time.Now().UTC(),
			},
		},
	})

	var out bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry=false", "--strict"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected strict verify error for missing policy pin")
	}
	if !strings.Contains(out.String(), "MISSING: policy "+policyRef+": not pinned in lockfile") {
		t.Fatalf("verify output missing policy pin diagnostic:\n%s", out.String())
	}
}

func TestVerifyPolicyChannelRevokedImageStrictFails(t *testing.T) {
	imageDigest := "sha256:" + strings.Repeat("b", 64)
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	policyJSON := policyBundleJSON(t, 4, expiresAt, []string{imageDigest})
	policyRef, manifestDigest, cleanup := setupPolicyBundleRegistry(t, "prod", policyJSON)
	defer cleanup()

	dir := t.TempDir()
	configPath := writePolicyChannelConfig(t, dir, policyRef, imageDigest)
	writePolicyChannelLockfile(t, dir, imageDigest, policyRef, manifestDigest, 4, expiresAt)

	var out bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry", "--strict"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected strict verify error for revoked image digest")
	}
	if !strings.Contains(err.Error(), "policy-fail") {
		t.Fatalf("strict error = %v, want policy-fail", err)
	}
	if !strings.Contains(out.String(), "POLICY FAIL: image") || !strings.Contains(out.String(), "digest is revoked by policy bundle") {
		t.Fatalf("verify output missing policy failure:\n%s", out.String())
	}
}

func TestRunPolicyChannelRevokedImageFailsBeforeStartup(t *testing.T) {
	imageDigest := "sha256:" + strings.Repeat("c", 64)
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	policyJSON := policyBundleJSON(t, 5, expiresAt, []string{imageDigest})
	policyRef, manifestDigest, cleanup := setupPolicyBundleRegistry(t, "prod", policyJSON)
	defer cleanup()

	dir := t.TempDir()
	configPath := writePolicyChannelConfig(t, dir, policyRef, imageDigest)
	writePolicyChannelLockfile(t, dir, imageDigest, policyRef, manifestDigest, 5, expiresAt)

	var sidecarCalls int
	var runtimeFactoryCalls int
	var extractPolicyCalls int

	restoreRunHooks(t)
	runResolveSidecar = func(*cobra.Command, *config.AgentContainer) (*sidecar.SidecarHandle, string, error) {
		sidecarCalls++
		return nil, "", nil
	}
	runRuntimeFactory = func(string, *zap.Logger, enforcement.Level) (container.Runtime, error) {
		runtimeFactoryCalls++
		return &recordingRuntime{}, nil
	}
	runExtractPolicy = func(context.Context, string, ...oci.ResolverOption) (*orgpolicy.OrgPolicy, error) {
		extractPolicyCalls++
		return orgpolicy.DefaultPolicy(), nil
	}
	runMergePolicy = func(*orgpolicy.OrgPolicy, *config.AgentContainer) error { return nil }
	runVerifyImageSignature = func(*cobra.Command, *config.AgentContainer, string) error { return nil }
	runNewDockerClient = func() (client.APIClient, error) { return nil, nil }

	cmd := newRunCmd()
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := runRun(cmd, false, time.Minute, configPath, "docker", true, false)
	if err == nil {
		t.Fatal("expected run error for revoked image digest")
	}
	if !strings.Contains(err.Error(), "mutable policy channel denied artifact") {
		t.Fatalf("run error = %v, want mutable policy channel denial", err)
	}
	if sidecarCalls != 0 || runtimeFactoryCalls != 0 || extractPolicyCalls != 0 {
		t.Fatalf("policy denial should happen before startup: sidecar=%d runtimeFactory=%d extractPolicy=%d",
			sidecarCalls, runtimeFactoryCalls, extractPolicyCalls)
	}
}

func TestRunPolicyChannelUnsignedPolicyFailsBeforeStartup(t *testing.T) {
	imageDigest := "sha256:" + strings.Repeat("4", 64)
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	policyJSON := policyBundleJSON(t, 5, expiresAt, nil)
	policyRef, manifestDigest, cleanup := setupPolicyBundleRegistry(t, "prod", policyJSON)
	defer cleanup()

	dir := t.TempDir()
	configPath := writePolicyChannelConfig(t, dir, policyRef, imageDigest)
	writePolicyChannelLockfile(t, dir, imageDigest, policyRef, manifestDigest, 5, expiresAt)

	previousVerifier := policySignatureVerifierFactory
	policySignatureVerifierFactory = func() signing.Verifier {
		return signing.NewMockVerifierFailing()
	}
	t.Cleanup(func() {
		policySignatureVerifierFactory = previousVerifier
	})

	var sidecarCalls int
	var runtimeFactoryCalls int
	var extractPolicyCalls int

	restoreRunHooks(t)
	runResolveSidecar = func(*cobra.Command, *config.AgentContainer) (*sidecar.SidecarHandle, string, error) {
		sidecarCalls++
		return nil, "", nil
	}
	runRuntimeFactory = func(string, *zap.Logger, enforcement.Level) (container.Runtime, error) {
		runtimeFactoryCalls++
		return &recordingRuntime{}, nil
	}
	runExtractPolicy = func(context.Context, string, ...oci.ResolverOption) (*orgpolicy.OrgPolicy, error) {
		extractPolicyCalls++
		return orgpolicy.DefaultPolicy(), nil
	}
	runMergePolicy = func(*orgpolicy.OrgPolicy, *config.AgentContainer) error { return nil }
	runVerifyImageSignature = func(*cobra.Command, *config.AgentContainer, string) error { return nil }
	runNewDockerClient = func() (client.APIClient, error) { return nil, nil }

	cmd := newRunCmd()
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := runRun(cmd, false, time.Minute, configPath, "docker", true, false)
	if err == nil {
		t.Fatal("expected run error for unsigned policy bundle")
	}
	if !strings.Contains(err.Error(), "signature verification failed") {
		t.Fatalf("run error = %v, want policy signature verification failure", err)
	}
	if sidecarCalls != 0 || runtimeFactoryCalls != 0 || extractPolicyCalls != 0 {
		t.Fatalf("policy signature failure should happen before startup: sidecar=%d runtimeFactory=%d extractPolicy=%d",
			sidecarCalls, runtimeFactoryCalls, extractPolicyCalls)
	}
}

func TestRunPolicyChannelStaleDigestFailsBeforeStartup(t *testing.T) {
	imageDigest := "sha256:" + strings.Repeat("d", 64)
	expiresAt := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
	policyJSON := policyBundleJSON(t, 6, expiresAt, nil)
	lockedDigest := "sha256:" + strings.Repeat("5", 64)
	policyRef, currentDigest, cleanup := setupPolicyBundleRegistry(t, "prod", policyJSON)
	defer cleanup()
	if lockedDigest == currentDigest {
		t.Fatal("test setup needs distinct locked and current policy digests")
	}

	dir := t.TempDir()
	configPath := writePolicyChannelConfig(t, dir, policyRef, imageDigest)
	writePolicyChannelLockfile(t, dir, imageDigest, policyRef, lockedDigest, 5, expiresAt)

	var sidecarCalls int
	var runtimeFactoryCalls int
	var extractPolicyCalls int

	restoreRunHooks(t)
	runResolveSidecar = func(*cobra.Command, *config.AgentContainer) (*sidecar.SidecarHandle, string, error) {
		sidecarCalls++
		return nil, "", nil
	}
	runRuntimeFactory = func(string, *zap.Logger, enforcement.Level) (container.Runtime, error) {
		runtimeFactoryCalls++
		return &recordingRuntime{}, nil
	}
	runExtractPolicy = func(context.Context, string, ...oci.ResolverOption) (*orgpolicy.OrgPolicy, error) {
		extractPolicyCalls++
		return orgpolicy.DefaultPolicy(), nil
	}
	runMergePolicy = func(*orgpolicy.OrgPolicy, *config.AgentContainer) error { return nil }
	runVerifyImageSignature = func(*cobra.Command, *config.AgentContainer, string) error { return nil }
	runNewDockerClient = func() (client.APIClient, error) { return nil, nil }

	cmd := newRunCmd()
	cmd.SetContext(context.Background())
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)

	err := runRun(cmd, false, time.Minute, configPath, "docker", true, false)
	if err == nil {
		t.Fatal("expected run error for stale policy digest")
	}
	if !strings.Contains(err.Error(), "policy "+policyRef+" digest changed") {
		t.Fatalf("run error = %v, want stale policy digest", err)
	}
	if sidecarCalls != 0 || runtimeFactoryCalls != 0 || extractPolicyCalls != 0 {
		t.Fatalf("policy digest mismatch should happen before startup: sidecar=%d runtimeFactory=%d extractPolicy=%d",
			sidecarCalls, runtimeFactoryCalls, extractPolicyCalls)
	}
}

func TestPolicyChannelSameEpochDifferentDigestRejected(t *testing.T) {
	locked := &config.ResolvedPolicy{
		Ref:    "ghcr.io/acme/policy:prod",
		Digest: "sha256:" + strings.Repeat("6", 64),
		Epoch:  7,
	}
	current := &config.ResolvedPolicy{
		Ref:    locked.Ref,
		Digest: "sha256:" + strings.Repeat("7", 64),
		Epoch:  locked.Epoch,
	}

	err := checkPolicyReplacement(locked, current)
	if err == nil {
		t.Fatal("expected same-epoch replacement error")
	}
	if !strings.Contains(err.Error(), "same-epoch policy replacement detected") {
		t.Fatalf("error = %v, want same-epoch replacement diagnostic", err)
	}
}

func TestRunPolicyChannelUnpinnedMCPAndSkillFailBeforeFetch(t *testing.T) {
	dir := t.TempDir()
	imageDigest := "sha256:" + strings.Repeat("e", 64)
	policyRef := "ghcr.io/acme/agentcontainers-policy:prod"
	configPath := filepath.Join(dir, "agentcontainer.json")
	configContent := fmt.Sprintf(`{
  "name": "policy-channel-tools",
  "image": "registry.example/app:1@%s",
  "agent": {
    "tools": {
      "mcp": {
        "github": {"image": "ghcr.io/acme/github-mcp:1"}
      },
      "skills": {
        "review": {"artifact": "ghcr.io/acme/skills/review:1"}
      }
    },
    "provenance": {
      "policy": {"ref": %q}
    }
  }
}`, imageDigest, policyRef)
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}
	writePolicyChannelLockfile(t, dir, imageDigest, policyRef, "sha256:"+strings.Repeat("8", 64), 8, time.Now().UTC().Add(time.Hour))

	cfg, err := config.ParseFile(configPath)
	if err != nil {
		t.Fatalf("ParseFile: %v", err)
	}

	err = verifyRunPolicyChannel(context.Background(), cfg, configPath, forbiddenPolicyBundleFetcher{t: t})
	if err == nil {
		t.Fatal("expected run policy channel coverage error")
	}
	if !strings.Contains(err.Error(), "mcp github is not pinned in lockfile") {
		t.Fatalf("error = %v, want missing mcp lock entry", err)
	}
	if !strings.Contains(err.Error(), "skill review is not pinned in lockfile") {
		t.Fatalf("error = %v, want missing skill lock entry", err)
	}
}

func TestVerifyStrictOfflineExpiredLockedPolicyFailsWithoutRegistryFetch(t *testing.T) {
	dir := t.TempDir()
	imageDigest := "sha256:" + strings.Repeat("f", 64)
	policyRef := "ghcr.io/acme/agentcontainers-policy:prod"
	configPath := writePolicyChannelConfig(t, dir, policyRef, imageDigest)
	writePolicyChannelLockfile(t, dir, imageDigest, policyRef, "sha256:"+strings.Repeat("9", 64), 9, time.Now().UTC().Add(-time.Hour))

	var out bytes.Buffer
	cmd := newRootCmd("test", "abc", "now")
	cmd.SetOut(&out)
	cmd.SetArgs([]string{"verify", "--config", configPath, "--registry=false", "--strict"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected strict offline verify error for expired locked policy")
	}
	if !strings.Contains(err.Error(), "policy-fail") {
		t.Fatalf("strict error = %v, want policy-fail", err)
	}
	if !strings.Contains(out.String(), "POLICY FAIL: policy "+policyRef+": locked policy is expired") {
		t.Fatalf("verify output missing expired locked policy diagnostic:\n%s", out.String())
	}
}

type forbiddenPolicyBundleFetcher struct {
	t *testing.T
}

func (f forbiddenPolicyBundleFetcher) FetchPolicyBundle(context.Context, string) ([]byte, string, error) {
	f.t.Helper()
	f.t.Fatal("policy bundle fetch should not be called when lockfile coverage is missing")
	return nil, "", fmt.Errorf("unexpected policy bundle fetch")
}

func setupPolicyBundleRegistry(t *testing.T, tag, policyJSON string) (string, string, func()) {
	t.Helper()

	policyDigest := digestOf(policyJSON)
	manifest := map[string]any{
		"schemaVersion": 2,
		"mediaType":     "application/vnd.oci.image.manifest.v1+json",
		"config": map[string]any{
			"mediaType": "application/vnd.oci.empty.v1+json",
			"digest":    "sha256:" + strings.Repeat("0", 64),
			"size":      2,
		},
		"layers": []map[string]any{
			{
				"mediaType": oci.PolicyBundleArtifactMediaType,
				"digest":    policyDigest,
				"size":      len(policyJSON),
			},
		},
	}
	manifestBytes, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestDigest := digestOf(string(manifestBytes))

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/"+tag):
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"+manifestDigest):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write(manifestBytes)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"+policyDigest):
			_, _ = w.Write([]byte(policyJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))

	client := srv.Client()
	oldFactory := resolverFactory
	resolverFactory = func() *oci.Resolver {
		return oci.NewResolver(oci.WithHTTPClient(client))
	}

	addr := strings.TrimPrefix(srv.URL, "https://")
	return addr + "/acme/policy:" + tag, manifestDigest, func() {
		resolverFactory = oldFactory
		srv.Close()
	}
}

func writePolicyChannelConfig(t *testing.T, dir, policyRef, imageDigest string) string {
	t.Helper()
	configPath := filepath.Join(dir, "agentcontainer.json")
	configContent := fmt.Sprintf(`{
  "name": "policy-channel-test",
  "image": "registry.example/app:1@%s",
  "agent": {
    "provenance": {
      "policy": {"ref": %q}
    }
  }
}`, imageDigest, policyRef)
	if err := os.WriteFile(configPath, []byte(configContent), 0o644); err != nil {
		t.Fatal(err)
	}
	return configPath
}

func writePolicyChannelLockfile(t *testing.T, dir, imageDigest, policyRef, policyDigest string, epoch int, expiresAt time.Time) {
	t.Helper()
	now := time.Now().UTC()
	writeLockfileHelper(t, filepath.Join(dir, config.LockfileName), &config.Lockfile{
		Version:     2,
		GeneratedAt: now,
		GeneratedBy: "agentcontainer",
		Resolved: config.ResolvedArtifacts{
			Image: &config.ResolvedImage{
				Digest:     imageDigest,
				ResolvedAt: now,
			},
			Policy: &config.ResolvedPolicy{
				Ref:        policyRef,
				Digest:     policyDigest,
				Epoch:      epoch,
				ExpiresAt:  expiresAt,
				ResolvedAt: now,
				Signature: &config.SignatureRef{
					KeylessRef: digestPinnedRef(policyRef, policyDigest),
					Subject:    "test@example.com",
					Issuer:     "https://issuer.example.com",
				},
			},
		},
	})
}

func policyBundleJSON(t *testing.T, epoch int, expiresAt time.Time, revoked []string) string {
	t.Helper()
	bundle := map[string]any{
		"mediaType":      orgpolicy.PolicyBundleMediaType,
		"artifactType":   orgpolicy.PolicyBundleMediaType,
		"epoch":          epoch,
		"expiresAt":      expiresAt.Format(time.RFC3339),
		"revokedDigests": revoked,
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func digestOf(s string) string {
	sum := sha256.Sum256([]byte(s))
	return "sha256:" + hex.EncodeToString(sum[:])
}
