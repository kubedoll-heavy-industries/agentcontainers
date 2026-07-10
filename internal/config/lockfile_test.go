package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

func TestLockfile_Validate(t *testing.T) {
	now := time.Date(2026, 1, 28, 0, 0, 0, 0, time.UTC)
	expiresAt := now.Add(24 * time.Hour)

	tests := []struct {
		name    string
		lf      Lockfile
		wantErr string
	}{
		{
			name: "valid minimal lockfile",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Image: &ResolvedImage{
						Digest:     "sha256:abc123",
						ResolvedAt: now,
					},
				},
			},
			wantErr: "",
		},
		{
			name: "valid full lockfile",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Image: &ResolvedImage{
						Digest:     "sha256:abc123",
						ResolvedAt: now,
					},
					Features: map[string]ResolvedFeature{
						"ghcr.io/devcontainers/features/node:1": {
							Digest:     "sha256:def456",
							ResolvedAt: now,
						},
					},
					MCP: map[string]ResolvedMCP{
						"github": {
							Digest:     "sha256:aabbcc",
							ResolvedAt: now,
							Signature: &SignatureRef{
								KeylessRef: "https://rekor.sigstore.dev/api/v1/log/entries/abc",
								Issuer:     "https://token.actions.githubusercontent.com",
								Subject:    "https://github.com/github/mcp-server/.github/workflows/release.yml@refs/tags/v2.1.0",
							},
							SBOM: &SBOMRef{
								Digest: "sha256:sbom11",
								Format: "cyclonedx+json",
								Vulnerabilities: &VulnSummary{
									Critical:  0,
									High:      0,
									Medium:    2,
									ScannedAt: now,
								},
							},
						},
					},
					Skills: map[string]ResolvedSkill{
						"code-review": {
							Digest:     "sha256:112233",
							ResolvedAt: now,
							SkillBOM: &SkillBOMRef{
								Digest:        "sha256:skillbom01",
								EmbeddingHash: "sha256:embed01",
								Capabilities:  []string{"filesystem.read", "git.diff"},
							},
						},
					},
					Policy: &ResolvedPolicy{
						Ref:        "ghcr.io/acme/org-policy:stable",
						Digest:     "sha256:policy01",
						Epoch:      7,
						ExpiresAt:  expiresAt,
						ResolvedAt: now,
						Signature: &SignatureRef{
							KeylessRef: "https://rekor.sigstore.dev/api/v1/log/entries/policy",
							Issuer:     "https://token.actions.githubusercontent.com",
							Subject:    "https://github.com/acme/org-policy/.github/workflows/release.yml@refs/tags/v7",
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "v1 lockfile rejected with migration message",
			lf: Lockfile{
				Version:     1,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved:    ResolvedArtifacts{},
			},
			wantErr: "re-run `agentcontainer lock`",
		},
		{
			name: "wrong version",
			lf: Lockfile{
				Version:     3,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved:    ResolvedArtifacts{},
			},
			wantErr: "version must be 2",
		},
		{
			name: "zero generatedAt",
			lf: Lockfile{
				Version:     2,
				GeneratedBy: "ac/0.1.0",
				Resolved:    ResolvedArtifacts{},
			},
			wantErr: "generatedAt must not be zero",
		},
		{
			name: "empty generatedBy",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				Resolved:    ResolvedArtifacts{},
			},
			wantErr: "generatedBy must not be empty",
		},
		{
			name: "empty image digest",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Image: &ResolvedImage{
						Digest:     "",
						ResolvedAt: now,
					},
				},
			},
			wantErr: "resolved.image.digest: must not be empty",
		},
		{
			name: "invalid digest format",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Image: &ResolvedImage{
						Digest:     "nocolon",
						ResolvedAt: now,
					},
				},
			},
			wantErr: "must be in algorithm:hex format",
		},
		{
			name: "empty feature digest",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Features: map[string]ResolvedFeature{
						"some-feature": {
							Digest:     "",
							ResolvedAt: now,
						},
					},
				},
			},
			wantErr: "resolved.features[some-feature].digest: must not be empty",
		},
		{
			name: "empty mcp digest",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					MCP: map[string]ResolvedMCP{
						"github": {
							Digest:     "",
							ResolvedAt: now,
						},
					},
				},
			},
			wantErr: "resolved.mcp[github].digest: must not be empty",
		},
		{
			name: "empty sbom format",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					MCP: map[string]ResolvedMCP{
						"github": {
							Digest:     "sha256:aabbcc",
							ResolvedAt: now,
							SBOM: &SBOMRef{
								Digest: "sha256:sbom11",
								Format: "",
							},
						},
					},
				},
			},
			wantErr: "resolved.mcp[github].sbom.format must not be empty",
		},
		{
			name: "empty skill digest",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Skills: map[string]ResolvedSkill{
						"deploy": {
							Digest:     "",
							ResolvedAt: now,
						},
					},
				},
			},
			wantErr: "resolved.skills[deploy].digest: must not be empty",
		},
		{
			name: "empty skillbom embeddingHash",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Skills: map[string]ResolvedSkill{
						"deploy": {
							Digest:     "sha256:112233",
							ResolvedAt: now,
							SkillBOM: &SkillBOMRef{
								Digest:        "sha256:skillbom01",
								EmbeddingHash: "",
							},
						},
					},
				},
			},
			wantErr: "resolved.skills[deploy].skillbom.embeddingHash must not be empty",
		},
		{
			name: "empty policy ref",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Policy: &ResolvedPolicy{
						Ref:        "",
						Digest:     "sha256:policy01",
						Epoch:      1,
						ExpiresAt:  expiresAt,
						ResolvedAt: now,
					},
				},
			},
			wantErr: "resolved.policy.ref must not be empty",
		},
		{
			name: "invalid policy digest",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Policy: &ResolvedPolicy{
						Ref:        "ghcr.io/acme/org-policy:stable",
						Digest:     "nocolon",
						Epoch:      1,
						ExpiresAt:  expiresAt,
						ResolvedAt: now,
					},
				},
			},
			wantErr: "resolved.policy.digest: must be in algorithm:hex format",
		},
		{
			name: "invalid policy epoch",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Policy: &ResolvedPolicy{
						Ref:        "ghcr.io/acme/org-policy:stable",
						Digest:     "sha256:policy01",
						Epoch:      0,
						ExpiresAt:  expiresAt,
						ResolvedAt: now,
					},
				},
			},
			wantErr: "resolved.policy.epoch must be greater than 0",
		},
		{
			name: "zero policy expiresAt",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Policy: &ResolvedPolicy{
						Ref:        "ghcr.io/acme/org-policy:stable",
						Digest:     "sha256:policy01",
						Epoch:      1,
						ResolvedAt: now,
					},
				},
			},
			wantErr: "resolved.policy.expiresAt must not be zero",
		},
		{
			name: "zero policy resolvedAt",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved: ResolvedArtifacts{
					Policy: &ResolvedPolicy{
						Ref:       "ghcr.io/acme/org-policy:stable",
						Digest:    "sha256:policy01",
						Epoch:     1,
						ExpiresAt: expiresAt,
					},
				},
			},
			wantErr: "resolved.policy.resolvedAt must not be zero",
		},
		{
			name: "nil image is valid",
			lf: Lockfile{
				Version:     2,
				GeneratedAt: now,
				GeneratedBy: "ac/0.1.0",
				Resolved:    ResolvedArtifacts{},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.lf.Validate()

			if tt.wantErr == "" {
				if err != nil {
					t.Errorf("Validate() unexpected error: %v", err)
				}
			} else {
				if err == nil {
					t.Errorf("Validate() expected error containing %q, got nil", tt.wantErr)
				} else if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("Validate() error = %v, want error containing %q", err, tt.wantErr)
				}
			}
		})
	}
}

func TestLockfile_Validate_MultipleErrors(t *testing.T) {
	lf := Lockfile{
		Version: 0,
		// Zero GeneratedAt, empty GeneratedBy.
		Resolved: ResolvedArtifacts{
			Image: &ResolvedImage{Digest: ""},
		},
	}

	err := lf.Validate()
	if err == nil {
		t.Fatal("Validate() expected error, got nil")
	}

	errStr := err.Error()
	expectedErrors := []string{
		"version must be 2",
		"generatedAt must not be zero",
		"generatedBy must not be empty",
		"resolved.image.digest: must not be empty",
	}

	for _, expected := range expectedErrors {
		if !strings.Contains(errStr, expected) {
			t.Errorf("Validate() error missing %q in: %s", expected, errStr)
		}
	}
}

// ---------------------------------------------------------------------------
// Round-trip marshal/unmarshal tests
// ---------------------------------------------------------------------------

func TestLockfile_RoundTrip(t *testing.T) {
	now := time.Date(2026, 1, 28, 0, 0, 0, 0, time.UTC)
	expiresAt := now.Add(24 * time.Hour)

	original := &Lockfile{
		Version:     2,
		GeneratedAt: now,
		GeneratedBy: "ac/0.1.0",
		Resolved: ResolvedArtifacts{
			Image: &ResolvedImage{
				Digest:     "sha256:abc123def456",
				ResolvedAt: now,
			},
			Features: map[string]ResolvedFeature{
				"ghcr.io/devcontainers/features/node:1": {
					Digest:     "sha256:def456",
					ResolvedAt: now,
				},
			},
			MCP: map[string]ResolvedMCP{
				"github": {
					Digest:     "sha256:aabbcc",
					ResolvedAt: now,
					Signature: &SignatureRef{
						KeylessRef: "https://rekor.sigstore.dev/api/v1/log/entries/abc",
						Issuer:     "https://token.actions.githubusercontent.com",
						Subject:    "https://github.com/github/mcp-server/.github/workflows/release.yml@refs/tags/v2.1.0",
					},
					SBOM: &SBOMRef{
						Digest: "sha256:sbom11",
						Format: "cyclonedx+json",
						Vulnerabilities: &VulnSummary{
							Critical:  0,
							High:      0,
							Medium:    2,
							ScannedAt: now,
						},
					},
				},
			},
			Skills: map[string]ResolvedSkill{
				"code-review": {
					Digest:     "sha256:112233",
					ResolvedAt: now,
					SkillBOM: &SkillBOMRef{
						Digest:        "sha256:skillbom01",
						EmbeddingHash: "sha256:embed01",
						Capabilities:  []string{"filesystem.read", "git.diff"},
					},
				},
			},
			Policy: &ResolvedPolicy{
				Ref:        "ghcr.io/acme/org-policy:stable",
				Digest:     "sha256:policy01",
				Epoch:      7,
				ExpiresAt:  expiresAt,
				ResolvedAt: now,
				Signature: &SignatureRef{
					KeylessRef: "https://rekor.sigstore.dev/api/v1/log/entries/policy",
					Issuer:     "https://token.actions.githubusercontent.com",
					Subject:    "https://github.com/acme/org-policy/.github/workflows/release.yml@refs/tags/v7",
				},
			},
		},
	}

	data, err := json.MarshalIndent(original, "", "  ")
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %v", err)
	}

	var roundTripped Lockfile
	if err := json.Unmarshal(data, &roundTripped); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %v", err)
	}

	// Verify key fields survived the round trip.
	if roundTripped.Version != original.Version {
		t.Errorf("Version = %d, want %d", roundTripped.Version, original.Version)
	}
	if !roundTripped.GeneratedAt.Equal(original.GeneratedAt) {
		t.Errorf("GeneratedAt = %v, want %v", roundTripped.GeneratedAt, original.GeneratedAt)
	}
	if roundTripped.GeneratedBy != original.GeneratedBy {
		t.Errorf("GeneratedBy = %q, want %q", roundTripped.GeneratedBy, original.GeneratedBy)
	}
	if roundTripped.Resolved.Image == nil {
		t.Fatal("Resolved.Image is nil, want non-nil")
	}
	if roundTripped.Resolved.Image.Digest != original.Resolved.Image.Digest {
		t.Errorf("Image.Digest = %q, want %q", roundTripped.Resolved.Image.Digest, original.Resolved.Image.Digest)
	}
	if got := len(roundTripped.Resolved.Features); got != 1 {
		t.Errorf("len(Features) = %d, want 1", got)
	}
	if got := len(roundTripped.Resolved.MCP); got != 1 {
		t.Errorf("len(MCP) = %d, want 1", got)
	}
	if mcp, ok := roundTripped.Resolved.MCP["github"]; ok {
		if mcp.Signature == nil {
			t.Error("MCP[github].Signature is nil, want non-nil")
		}
		if mcp.SBOM == nil {
			t.Error("MCP[github].SBOM is nil, want non-nil")
		} else if mcp.SBOM.Format != "cyclonedx+json" {
			t.Errorf("MCP[github].SBOM.Format = %q, want %q", mcp.SBOM.Format, "cyclonedx+json")
		}
	} else {
		t.Error("MCP[github] not found in round-tripped lockfile")
	}
	if got := len(roundTripped.Resolved.Skills); got != 1 {
		t.Errorf("len(Skills) = %d, want 1", got)
	}
	if skill, ok := roundTripped.Resolved.Skills["code-review"]; ok {
		if skill.SkillBOM == nil {
			t.Error("Skills[code-review].SkillBOM is nil, want non-nil")
		} else {
			if skill.SkillBOM.EmbeddingHash != "sha256:embed01" {
				t.Errorf("SkillBOM.EmbeddingHash = %q, want %q", skill.SkillBOM.EmbeddingHash, "sha256:embed01")
			}
			if got := len(skill.SkillBOM.Capabilities); got != 2 {
				t.Errorf("len(SkillBOM.Capabilities) = %d, want 2", got)
			}
		}
	} else {
		t.Error("Skills[code-review] not found in round-tripped lockfile")
	}
	if roundTripped.Resolved.Policy == nil {
		t.Fatal("Resolved.Policy is nil, want non-nil")
	}
	if roundTripped.Resolved.Policy.Ref != original.Resolved.Policy.Ref {
		t.Errorf("Policy.Ref = %q, want %q", roundTripped.Resolved.Policy.Ref, original.Resolved.Policy.Ref)
	}
	if roundTripped.Resolved.Policy.Digest != original.Resolved.Policy.Digest {
		t.Errorf("Policy.Digest = %q, want %q", roundTripped.Resolved.Policy.Digest, original.Resolved.Policy.Digest)
	}
	if roundTripped.Resolved.Policy.Epoch != original.Resolved.Policy.Epoch {
		t.Errorf("Policy.Epoch = %d, want %d", roundTripped.Resolved.Policy.Epoch, original.Resolved.Policy.Epoch)
	}
	if !roundTripped.Resolved.Policy.ExpiresAt.Equal(original.Resolved.Policy.ExpiresAt) {
		t.Errorf("Policy.ExpiresAt = %v, want %v", roundTripped.Resolved.Policy.ExpiresAt, original.Resolved.Policy.ExpiresAt)
	}
	if !roundTripped.Resolved.Policy.ResolvedAt.Equal(original.Resolved.Policy.ResolvedAt) {
		t.Errorf("Policy.ResolvedAt = %v, want %v", roundTripped.Resolved.Policy.ResolvedAt, original.Resolved.Policy.ResolvedAt)
	}
	if roundTripped.Resolved.Policy.Signature == nil {
		t.Error("Policy.Signature is nil, want non-nil")
	}
}

// ---------------------------------------------------------------------------
// Load/Save file tests
// ---------------------------------------------------------------------------

func TestLoadLockfile(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 28, 0, 0, 0, 0, time.UTC)

	content := `{
  "version": 2,
  "generatedAt": "2026-01-28T00:00:00Z",
  "generatedBy": "ac/0.1.0",
  "resolved": {
    "image": {
      "digest": "sha256:abc123",
      "resolvedAt": "2026-01-28T00:00:00Z"
    }
  }
}`

	if err := os.WriteFile(filepath.Join(dir, LockfileName), []byte(content), 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	lf, err := LoadLockfile(dir)
	if err != nil {
		t.Fatalf("LoadLockfile() unexpected error: %v", err)
	}

	if lf.Version != 2 {
		t.Errorf("Version = %d, want 2", lf.Version)
	}
	if !lf.GeneratedAt.Equal(now) {
		t.Errorf("GeneratedAt = %v, want %v", lf.GeneratedAt, now)
	}
	if lf.GeneratedBy != "ac/0.1.0" {
		t.Errorf("GeneratedBy = %q, want %q", lf.GeneratedBy, "ac/0.1.0")
	}
	if lf.Resolved.Image == nil {
		t.Fatal("Resolved.Image is nil, want non-nil")
	}
	if lf.Resolved.Image.Digest != "sha256:abc123" {
		t.Errorf("Image.Digest = %q, want %q", lf.Resolved.Image.Digest, "sha256:abc123")
	}
}

func TestLoadLockfile_NotFound(t *testing.T) {
	dir := t.TempDir()

	_, err := LoadLockfile(dir)
	if err == nil {
		t.Fatal("LoadLockfile() expected error for missing file, got nil")
	}
	if !strings.Contains(err.Error(), "reading lockfile") {
		t.Errorf("error = %v, want error containing %q", err, "reading lockfile")
	}
}

func TestLoadLockfile_InvalidJSON(t *testing.T) {
	dir := t.TempDir()

	if err := os.WriteFile(filepath.Join(dir, LockfileName), []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("writing lockfile: %v", err)
	}

	_, err := LoadLockfile(dir)
	if err == nil {
		t.Fatal("LoadLockfile() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "unmarshaling lockfile") {
		t.Errorf("error = %v, want error containing %q", err, "unmarshaling lockfile")
	}
}

func TestSaveLockfile(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 28, 0, 0, 0, 0, time.UTC)

	lf := &Lockfile{
		Version:     2,
		GeneratedAt: now,
		GeneratedBy: "ac/0.1.0",
		Resolved: ResolvedArtifacts{
			Image: &ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: now,
			},
		},
	}

	if err := SaveLockfile(dir, lf); err != nil {
		t.Fatalf("SaveLockfile() unexpected error: %v", err)
	}

	// Read it back and verify.
	loaded, err := LoadLockfile(dir)
	if err != nil {
		t.Fatalf("LoadLockfile() after save unexpected error: %v", err)
	}

	if loaded.Version != lf.Version {
		t.Errorf("Version = %d, want %d", loaded.Version, lf.Version)
	}
	if loaded.GeneratedBy != lf.GeneratedBy {
		t.Errorf("GeneratedBy = %q, want %q", loaded.GeneratedBy, lf.GeneratedBy)
	}
	if loaded.Resolved.Image == nil {
		t.Fatal("Resolved.Image is nil, want non-nil")
	}
	if loaded.Resolved.Image.Digest != lf.Resolved.Image.Digest {
		t.Errorf("Image.Digest = %q, want %q", loaded.Resolved.Image.Digest, lf.Resolved.Image.Digest)
	}

	// Verify file ends with newline.
	data, err := os.ReadFile(filepath.Join(dir, LockfileName))
	if err != nil {
		t.Fatalf("reading lockfile: %v", err)
	}
	if len(data) == 0 || data[len(data)-1] != '\n' {
		t.Error("lockfile does not end with newline")
	}
}

func TestSaveLockfile_RoundTrip(t *testing.T) {
	dir := t.TempDir()
	now := time.Date(2026, 1, 28, 0, 0, 0, 0, time.UTC)

	original := &Lockfile{
		Version:     2,
		GeneratedAt: now,
		GeneratedBy: "ac/0.1.0",
		Resolved: ResolvedArtifacts{
			Image: &ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: now,
			},
			Features: map[string]ResolvedFeature{
				"ghcr.io/devcontainers/features/node:1": {
					Digest:     "sha256:feat01",
					ResolvedAt: now,
				},
			},
			MCP: map[string]ResolvedMCP{
				"github": {
					Digest:     "sha256:mcp01",
					ResolvedAt: now,
				},
			},
			Skills: map[string]ResolvedSkill{
				"deploy": {
					Digest:     "sha256:skill01",
					ResolvedAt: now,
					SkillBOM: &SkillBOMRef{
						Digest:        "sha256:sbom01",
						EmbeddingHash: "sha256:embed01",
						Capabilities:  []string{"shell.npm"},
					},
				},
			},
		},
	}

	if err := SaveLockfile(dir, original); err != nil {
		t.Fatalf("SaveLockfile() unexpected error: %v", err)
	}

	loaded, err := LoadLockfile(dir)
	if err != nil {
		t.Fatalf("LoadLockfile() unexpected error: %v", err)
	}

	if loaded.Resolved.Image.Digest != original.Resolved.Image.Digest {
		t.Errorf("Image.Digest = %q, want %q", loaded.Resolved.Image.Digest, original.Resolved.Image.Digest)
	}

	feat, ok := loaded.Resolved.Features["ghcr.io/devcontainers/features/node:1"]
	if !ok {
		t.Fatal("Features[ghcr.io/devcontainers/features/node:1] not found")
	}
	if feat.Digest != "sha256:feat01" {
		t.Errorf("Feature.Digest = %q, want %q", feat.Digest, "sha256:feat01")
	}

	mcp, ok := loaded.Resolved.MCP["github"]
	if !ok {
		t.Fatal("MCP[github] not found")
	}
	if mcp.Digest != "sha256:mcp01" {
		t.Errorf("MCP.Digest = %q, want %q", mcp.Digest, "sha256:mcp01")
	}

	skill, ok := loaded.Resolved.Skills["deploy"]
	if !ok {
		t.Fatal("Skills[deploy] not found")
	}
	if skill.SkillBOM == nil {
		t.Fatal("Skills[deploy].SkillBOM is nil, want non-nil")
	}
	if skill.SkillBOM.EmbeddingHash != "sha256:embed01" {
		t.Errorf("SkillBOM.EmbeddingHash = %q, want %q", skill.SkillBOM.EmbeddingHash, "sha256:embed01")
	}
}

// ---------------------------------------------------------------------------
// Omitempty behavior tests
// ---------------------------------------------------------------------------

func TestLockfile_OmitsEmptyOptionalFields(t *testing.T) {
	now := time.Date(2026, 1, 28, 0, 0, 0, 0, time.UTC)

	lf := &Lockfile{
		Version:     2,
		GeneratedAt: now,
		GeneratedBy: "ac/0.1.0",
		Resolved: ResolvedArtifacts{
			Image: &ResolvedImage{
				Digest:     "sha256:abc123",
				ResolvedAt: now,
			},
		},
	}

	data, err := json.Marshal(lf)
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %v", err)
	}

	s := string(data)
	if strings.Contains(s, "features") {
		t.Error("marshaled JSON should omit empty features")
	}
	if strings.Contains(s, "mcp") {
		t.Error("marshaled JSON should omit empty mcp")
	}
	if strings.Contains(s, "skills") {
		t.Error("marshaled JSON should omit empty skills")
	}
}
