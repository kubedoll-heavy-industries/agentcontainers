package signing

import (
	"context"
	"encoding/json"
	"testing"
)

func TestReadGitHubEnv(t *testing.T) {
	tests := []struct {
		name    string
		envVars map[string]string
		wantErr string
		check   func(t *testing.T, env *GitHubEnv)
	}{
		{
			name: "all variables set",
			envVars: map[string]string{
				"GITHUB_ACTOR":      "test-user",
				"GITHUB_WORKFLOW":   "ci.yml",
				"GITHUB_SHA":        "abc123def456",
				"GITHUB_REF":        "refs/heads/main",
				"GITHUB_RUN_ID":     "12345",
				"GITHUB_SERVER_URL": "https://github.com",
				"GITHUB_REPOSITORY": "org/repo",
			},
			check: func(t *testing.T, env *GitHubEnv) {
				if env.Actor != "test-user" {
					t.Errorf("Actor = %q, want %q", env.Actor, "test-user")
				}
				if env.Workflow != "ci.yml" {
					t.Errorf("Workflow = %q, want %q", env.Workflow, "ci.yml")
				}
				if env.SHA != "abc123def456" {
					t.Errorf("SHA = %q, want %q", env.SHA, "abc123def456")
				}
				if env.Ref != "refs/heads/main" {
					t.Errorf("Ref = %q, want %q", env.Ref, "refs/heads/main")
				}
				if env.RunID != "12345" {
					t.Errorf("RunID = %q, want %q", env.RunID, "12345")
				}
				if env.ServerURL != "https://github.com" {
					t.Errorf("ServerURL = %q, want %q", env.ServerURL, "https://github.com")
				}
				if env.Repository != "org/repo" {
					t.Errorf("Repository = %q, want %q", env.Repository, "org/repo")
				}
			},
		},
		{
			name: "default server URL",
			envVars: map[string]string{
				"GITHUB_WORKFLOW":   "ci.yml",
				"GITHUB_SHA":        "abc123",
				"GITHUB_REPOSITORY": "org/repo",
			},
			check: func(t *testing.T, env *GitHubEnv) {
				if env.ServerURL != "https://github.com" {
					t.Errorf("ServerURL = %q, want default %q", env.ServerURL, "https://github.com")
				}
			},
		},
		{
			name: "missing SHA",
			envVars: map[string]string{
				"GITHUB_WORKFLOW":   "ci.yml",
				"GITHUB_REPOSITORY": "org/repo",
			},
			wantErr: "GITHUB_SHA",
		},
		{
			name: "missing repository",
			envVars: map[string]string{
				"GITHUB_WORKFLOW": "ci.yml",
				"GITHUB_SHA":      "abc123",
			},
			wantErr: "GITHUB_REPOSITORY",
		},
		{
			name: "missing workflow",
			envVars: map[string]string{
				"GITHUB_SHA":        "abc123",
				"GITHUB_REPOSITORY": "org/repo",
			},
			wantErr: "GITHUB_WORKFLOW",
		},
		{
			name:    "all required missing",
			envVars: map[string]string{},
			wantErr: "GITHUB_SHA",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Clear all GitHub env vars.
			for _, key := range []string{
				"GITHUB_ACTOR", "GITHUB_WORKFLOW", "GITHUB_SHA",
				"GITHUB_REF", "GITHUB_RUN_ID", "GITHUB_SERVER_URL",
				"GITHUB_REPOSITORY",
			} {
				t.Setenv(key, "")
			}

			// Set test values.
			for k, v := range tt.envVars {
				t.Setenv(k, v)
			}

			env, err := ReadGitHubEnv()
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, env)
			}
		})
	}
}

func TestNewProvenanceFromGitHub(t *testing.T) {
	tests := []struct {
		name    string
		env     *GitHubEnv
		wantErr string
		check   func(t *testing.T, p *Provenance)
	}{
		{
			name: "full environment",
			env: &GitHubEnv{
				Actor:      "test-user",
				Workflow:   "docker.yml",
				SHA:        "abc123def456789",
				Ref:        "refs/heads/main",
				RunID:      "98765",
				ServerURL:  "https://github.com",
				Repository: "Kubedoll-Heavy-Industries/agentcontainers",
			},
			check: func(t *testing.T, p *Provenance) {
				expectedBuilder := "https://github.com/Kubedoll-Heavy-Industries/agentcontainers/.github/workflows/docker.yml"
				if p.Builder.ID != expectedBuilder {
					t.Errorf("Builder.ID = %q, want %q", p.Builder.ID, expectedBuilder)
				}
				if p.BuildType != GitHubActionsBuildType {
					t.Errorf("BuildType = %q, want %q", p.BuildType, GitHubActionsBuildType)
				}
				expectedURI := "git+https://github.com/Kubedoll-Heavy-Industries/agentcontainers@refs/heads/main"
				if p.Invocation.ConfigSource.URI != expectedURI {
					t.Errorf("ConfigSource.URI = %q, want %q", p.Invocation.ConfigSource.URI, expectedURI)
				}
				if p.Invocation.ConfigSource.Digest["sha1"] != "abc123def456789" {
					t.Errorf("ConfigSource.Digest[sha1] = %q, want %q",
						p.Invocation.ConfigSource.Digest["sha1"], "abc123def456789")
				}
				if p.Invocation.Parameters["runID"] != "98765" {
					t.Errorf("Parameters[runID] = %q, want %q",
						p.Invocation.Parameters["runID"], "98765")
				}
				if len(p.Materials) != 1 {
					t.Fatalf("expected 1 material, got %d", len(p.Materials))
				}
				if p.Materials[0].URI != expectedURI {
					t.Errorf("Material[0].URI = %q, want %q", p.Materials[0].URI, expectedURI)
				}
				if p.Materials[0].Digest["sha1"] != "abc123def456789" {
					t.Errorf("Material[0].Digest[sha1] = %q, want %q",
						p.Materials[0].Digest["sha1"], "abc123def456789")
				}
				// Should be at least SLSA L3 (hosted builder with commit digest).
				if p.DetermineSLSALevel() < SLSALevel3 {
					t.Errorf("expected SLSA level >= 3, got %d", p.DetermineSLSALevel())
				}
			},
		},
		{
			name: "no ref",
			env: &GitHubEnv{
				Workflow:   "ci.yml",
				SHA:        "abc123",
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			check: func(t *testing.T, p *Provenance) {
				// URI should not have @ref suffix.
				expectedURI := "git+https://github.com/org/repo"
				if p.Invocation.ConfigSource.URI != expectedURI {
					t.Errorf("ConfigSource.URI = %q, want %q", p.Invocation.ConfigSource.URI, expectedURI)
				}
			},
		},
		{
			name: "no run ID",
			env: &GitHubEnv{
				Workflow:   "ci.yml",
				SHA:        "abc123",
				ServerURL:  "https://github.com",
				Repository: "org/repo",
			},
			check: func(t *testing.T, p *Provenance) {
				if len(p.Invocation.Parameters) != 0 {
					t.Errorf("expected no parameters when RunID is empty, got %v", p.Invocation.Parameters)
				}
			},
		},
		{
			name: "trailing slash on server URL",
			env: &GitHubEnv{
				Workflow:   "build.yml",
				SHA:        "abc123",
				ServerURL:  "https://github.com/",
				Repository: "org/repo",
			},
			check: func(t *testing.T, p *Provenance) {
				expectedBuilder := "https://github.com/org/repo/.github/workflows/build.yml"
				if p.Builder.ID != expectedBuilder {
					t.Errorf("Builder.ID = %q, want %q", p.Builder.ID, expectedBuilder)
				}
			},
		},
		{
			name:    "nil env",
			env:     nil,
			wantErr: "nil GitHub environment",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := NewProvenanceFromGitHub(tt.env)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, p)
			}
		})
	}
}

func TestGenerateInTotoStatement(t *testing.T) {
	baseProv := &Provenance{
		BuildType: GitHubActionsBuildType,
		Builder:   ProvenanceBuilder{ID: "https://github.com/org/repo/.github/workflows/ci.yml"},
		Invocation: ProvenanceInvocation{
			ConfigSource: ProvenanceConfigSource{
				URI:    "git+https://github.com/org/repo@refs/heads/main",
				Digest: map[string]string{"sha1": "abc123"},
			},
		},
	}

	tests := []struct {
		name          string
		prov          *Provenance
		subjectName   string
		subjectDigest map[string]string
		wantErr       string
		check         func(t *testing.T, stmt *InTotoStatement)
	}{
		{
			name:          "valid statement",
			prov:          baseProv,
			subjectName:   "ghcr.io/org/image",
			subjectDigest: map[string]string{"sha256": "deadbeef"},
			check: func(t *testing.T, stmt *InTotoStatement) {
				if stmt.Type != InTotoStatementType {
					t.Errorf("Type = %q, want %q", stmt.Type, InTotoStatementType)
				}
				if stmt.PredicateType != SLSAProvenancePredicateType {
					t.Errorf("PredicateType = %q, want %q", stmt.PredicateType, SLSAProvenancePredicateType)
				}
				if len(stmt.Subject) != 1 {
					t.Fatalf("expected 1 subject, got %d", len(stmt.Subject))
				}
				if stmt.Subject[0].Name != "ghcr.io/org/image" {
					t.Errorf("Subject[0].Name = %q, want %q", stmt.Subject[0].Name, "ghcr.io/org/image")
				}
				if stmt.Subject[0].Digest["sha256"] != "deadbeef" {
					t.Errorf("Subject[0].Digest[sha256] = %q, want %q",
						stmt.Subject[0].Digest["sha256"], "deadbeef")
				}
				// Predicate should be parseable back to Provenance.
				var roundTripped Provenance
				if err := json.Unmarshal(stmt.Predicate, &roundTripped); err != nil {
					t.Fatalf("failed to unmarshal predicate: %v", err)
				}
				if roundTripped.Builder.ID != baseProv.Builder.ID {
					t.Errorf("roundtripped builder ID = %q, want %q",
						roundTripped.Builder.ID, baseProv.Builder.ID)
				}
			},
		},
		{
			name:          "nil provenance",
			prov:          nil,
			subjectName:   "image",
			subjectDigest: map[string]string{"sha256": "abc"},
			wantErr:       "nil provenance",
		},
		{
			name:          "empty subject name",
			prov:          baseProv,
			subjectName:   "",
			subjectDigest: map[string]string{"sha256": "abc"},
			wantErr:       "empty subject name",
		},
		{
			name:        "empty subject digest",
			prov:        baseProv,
			subjectName: "image",
			wantErr:     "empty subject digest",
		},
		{
			name:          "nil subject digest",
			prov:          baseProv,
			subjectName:   "image",
			subjectDigest: nil,
			wantErr:       "empty subject digest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stmt, err := GenerateInTotoStatement(tt.prov, tt.subjectName, tt.subjectDigest)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if tt.check != nil {
				tt.check(t, stmt)
			}
		})
	}
}

func TestGenerateInTotoStatementRoundTrip(t *testing.T) {
	env := &GitHubEnv{
		Actor:      "test-user",
		Workflow:   "release.yml",
		SHA:        "fa21826abc",
		Ref:        "refs/tags/v1.0.0",
		RunID:      "42",
		ServerURL:  "https://github.com",
		Repository: "Kubedoll-Heavy-Industries/agentcontainers",
	}

	prov, err := NewProvenanceFromGitHub(env)
	if err != nil {
		t.Fatalf("NewProvenanceFromGitHub() error: %v", err)
	}

	stmt, err := GenerateInTotoStatement(prov, "ghcr.io/khi/agentcontainer", map[string]string{"sha256": "abc123"})
	if err != nil {
		t.Fatalf("GenerateInTotoStatement() error: %v", err)
	}

	// Serialize and parse back.
	data, err := json.Marshal(stmt)
	if err != nil {
		t.Fatalf("json.Marshal(stmt) error: %v", err)
	}

	parsedStmt, parsedProv, err := ParseInTotoStatement(data)
	if err != nil {
		t.Fatalf("ParseInTotoStatement() error: %v", err)
	}

	if parsedStmt.Type != InTotoStatementType {
		t.Errorf("Type = %q, want %q", parsedStmt.Type, InTotoStatementType)
	}
	if parsedProv.Builder.ID != prov.Builder.ID {
		t.Errorf("Builder.ID = %q, want %q", parsedProv.Builder.ID, prov.Builder.ID)
	}
	if parsedProv.Invocation.ConfigSource.Digest["sha1"] != "fa21826abc" {
		t.Errorf("ConfigSource.Digest[sha1] = %q, want %q",
			parsedProv.Invocation.ConfigSource.Digest["sha1"], "fa21826abc")
	}
	if parsedProv.DetermineSLSALevel() < SLSALevel3 {
		t.Errorf("expected SLSA level >= 3, got %d", parsedProv.DetermineSLSALevel())
	}
}

func TestValidateBuilderIdentity(t *testing.T) {
	tests := []struct {
		name            string
		prov            *Provenance
		trustedBuilders []string
		wantErr         string
	}{
		{
			name: "trusted builder matches",
			prov: &Provenance{
				Builder: ProvenanceBuilder{
					ID: "https://github.com/slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@refs/tags/v2.1.0",
				},
			},
			trustedBuilders: []string{
				"https://github.com/slsa-framework/slsa-github-generator",
			},
		},
		{
			name: "multiple trusted builders - second matches",
			prov: &Provenance{
				Builder: ProvenanceBuilder{
					ID: "https://cloudbuild.googleapis.com/GoogleHostedWorker@v0.4",
				},
			},
			trustedBuilders: []string{
				"https://github.com/slsa-framework/slsa-github-generator",
				"https://cloudbuild.googleapis.com",
			},
		},
		{
			name: "no trusted builders configured - skips validation",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "any-builder"},
			},
			trustedBuilders: nil,
		},
		{
			name: "empty trusted builders - skips validation",
			prov: &Provenance{
				Builder: ProvenanceBuilder{ID: "any-builder"},
			},
			trustedBuilders: []string{},
		},
		{
			name: "builder not in trusted list",
			prov: &Provenance{
				Builder: ProvenanceBuilder{
					ID: "https://untrusted-ci.example.com/builder",
				},
			},
			trustedBuilders: []string{
				"https://github.com/slsa-framework/slsa-github-generator",
				"https://cloudbuild.googleapis.com",
			},
			wantErr: "not in trusted builders list",
		},
		{
			name:            "nil provenance",
			prov:            nil,
			trustedBuilders: []string{"builder"},
			wantErr:         "nil provenance",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := ValidateBuilderIdentity(tt.prov, tt.trustedBuilders)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tt.wantErr)
				}
				if !contains(err.Error(), tt.wantErr) {
					t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestBuildAttestArgs(t *testing.T) {
	tests := []struct {
		name          string
		ref           string
		predicatePath string
		opts          AttestOptions
		wantContains  []string
	}{
		{
			name:          "basic keyless",
			ref:           "ghcr.io/org/image@sha256:abc",
			predicatePath: "/tmp/prov.json",
			opts:          AttestOptions{},
			wantContains: []string{
				"attest", "--type", "slsaprovenance",
				"--predicate", "/tmp/prov.json",
				"--yes",
				"ghcr.io/org/image@sha256:abc",
			},
		},
		{
			name:          "with key",
			ref:           "ghcr.io/org/image@sha256:abc",
			predicatePath: "/tmp/prov.json",
			opts:          AttestOptions{KeyPath: "cosign.key"},
			wantContains: []string{
				"--key", "cosign.key",
			},
		},
		{
			name:          "with rekor URL",
			ref:           "ghcr.io/org/image@sha256:abc",
			predicatePath: "/tmp/prov.json",
			opts:          AttestOptions{RekorURL: "https://rekor.example.com"},
			wantContains: []string{
				"--rekor-url", "https://rekor.example.com",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			args := buildAttestArgs(tt.ref, tt.predicatePath, tt.opts)
			joined := joinArgs(args)
			for _, want := range tt.wantContains {
				if !contains(joined, want) {
					t.Errorf("args %v do not contain %q", args, want)
				}
			}
		})
	}
}

func TestBuildAttestEnv(t *testing.T) {
	tests := []struct {
		name     string
		opts     AttestOptions
		wantExpr bool
	}{
		{
			name:     "keyless sets COSIGN_EXPERIMENTAL",
			opts:     AttestOptions{},
			wantExpr: true,
		},
		{
			name:     "key-based does not set COSIGN_EXPERIMENTAL",
			opts:     AttestOptions{KeyPath: "cosign.key"},
			wantExpr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			env := buildAttestEnv(tt.opts)
			found := false
			for _, e := range env {
				if e == "COSIGN_EXPERIMENTAL=1" {
					found = true
				}
			}
			if found != tt.wantExpr {
				t.Errorf("COSIGN_EXPERIMENTAL found=%v, want=%v", found, tt.wantExpr)
			}
		})
	}
}

func TestCosignAttesterEmptyRef(t *testing.T) {
	attester := NewCosignAttester()
	_, err := attester.Attest(context.Background(), "", nil, AttestOptions{})
	if err == nil {
		t.Fatal("expected error for empty ref")
	}
	if !contains(err.Error(), "empty artifact reference") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestCosignAttesterNilStatement(t *testing.T) {
	attester := NewCosignAttester()
	_, err := attester.Attest(context.Background(), "ref@sha256:abc", nil, AttestOptions{})
	if err == nil {
		t.Fatal("expected error for nil statement")
	}
	if !contains(err.Error(), "nil in-toto statement") {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestMockAttester(t *testing.T) {
	attester := NewMockAttester()
	result, err := attester.Attest(context.Background(), "ghcr.io/org/image@sha256:abc",
		&InTotoStatement{Type: InTotoStatementType}, AttestOptions{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.Ref != "ghcr.io/org/image@sha256:abc" {
		t.Errorf("Ref = %q, want %q", result.Ref, "ghcr.io/org/image@sha256:abc")
	}
	if result.AttestationDigest == "" {
		t.Error("expected non-empty attestation digest")
	}
}

func TestMockAttesterFailing(t *testing.T) {
	attester := NewMockAttesterFailing("registry unavailable")
	_, err := attester.Attest(context.Background(), "ghcr.io/org/image@sha256:abc",
		&InTotoStatement{Type: InTotoStatementType}, AttestOptions{})
	if err == nil {
		t.Fatal("expected error")
	}
	if !contains(err.Error(), "registry unavailable") {
		t.Errorf("expected 'registry unavailable' in error, got: %v", err)
	}
}

func TestConstants(t *testing.T) {
	if InTotoStatementType != "https://in-toto.io/Statement/v1" {
		t.Errorf("InTotoStatementType = %q", InTotoStatementType)
	}
	if SLSAProvenancePredicateType != "https://slsa.dev/provenance/v1" {
		t.Errorf("SLSAProvenancePredicateType = %q", SLSAProvenancePredicateType)
	}
	if GitHubActionsIssuer != "https://token.actions.githubusercontent.com" {
		t.Errorf("GitHubActionsIssuer = %q", GitHubActionsIssuer)
	}
}
