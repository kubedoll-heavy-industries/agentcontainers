package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// parseFile tests
// ---------------------------------------------------------------------------

func TestParseFile_ValidJSON(t *testing.T) {
	cfg, err := parseFile(filepath.Join("testdata", "valid.json"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	if cfg.Name != "full-agent-container" {
		t.Errorf("Name = %q, want %q", cfg.Name, "full-agent-container")
	}
	if cfg.Image != "ghcr.io/kubedoll/agent-base:latest" {
		t.Errorf("Image = %q, want %q", cfg.Image, "ghcr.io/kubedoll/agent-base:latest")
	}
	if cfg.Agent == nil {
		t.Fatal("Agent is nil, want non-nil")
	}
	if cfg.Agent.Capabilities == nil {
		t.Fatal("Agent.Capabilities is nil, want non-nil")
	}
	if cfg.Agent.Capabilities.Shell == nil {
		t.Fatal("Agent.Capabilities.Shell is nil, want non-nil")
	}
	if got := len(cfg.Agent.Capabilities.Shell.Commands); got != 3 {
		t.Errorf("len(Shell.Commands) = %d, want 3", got)
	}
	if cfg.Agent.Capabilities.Network == nil {
		t.Fatal("Agent.Capabilities.Network is nil, want non-nil")
	}
	if got := len(cfg.Agent.Capabilities.Network.Egress); got != 2 {
		t.Errorf("len(Network.Egress) = %d, want 2", got)
	}
	// agent.policy, agent.secrets, agent.provenance removed from valid.json
	// because they are not yet implemented and now fail validation.
}

func TestParseFile_MinimalJSON(t *testing.T) {
	cfg, err := parseFile(filepath.Join("testdata", "minimal.json"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	if cfg.Name != "minimal-container" {
		t.Errorf("Name = %q, want %q", cfg.Name, "minimal-container")
	}
	if cfg.Image != "ubuntu:24.04" {
		t.Errorf("Image = %q, want %q", cfg.Image, "ubuntu:24.04")
	}
	if cfg.Agent != nil {
		t.Errorf("Agent = %+v, want nil (no agent key in minimal config)", cfg.Agent)
	}
}

func TestParseFile_JSONC(t *testing.T) {
	cfg, err := parseFile(filepath.Join("testdata", "with_comments.jsonc"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	if cfg.Name != "commented-container" {
		t.Errorf("Name = %q, want %q", cfg.Name, "commented-container")
	}
	if cfg.Image != "node:22-bookworm" {
		t.Errorf("Image = %q, want %q", cfg.Image, "node:22-bookworm")
	}
	if cfg.Agent == nil {
		t.Fatal("Agent is nil, want non-nil")
	}
	if cfg.Agent.Capabilities == nil {
		t.Fatal("Agent.Capabilities is nil, want non-nil")
	}
	if cfg.Agent.Capabilities.Shell == nil {
		t.Fatal("Agent.Capabilities.Shell is nil, want non-nil")
	}
	if got := len(cfg.Agent.Capabilities.Shell.Commands); got != 2 {
		t.Errorf("len(Shell.Commands) = %d, want 2", got)
	}
	if cfg.Agent.Capabilities.Shell.Commands[0].Binary != "git" {
		t.Errorf("Shell.Commands[0].Binary = %q, want %q", cfg.Agent.Capabilities.Shell.Commands[0].Binary, "git")
	}
}

func TestParseFile_DevcontainerJSON(t *testing.T) {
	cfg, err := parseFile(filepath.Join("testdata", "devcontainer.json"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	if cfg.Name != "plain-devcontainer" {
		t.Errorf("Name = %q, want %q", cfg.Name, "plain-devcontainer")
	}
	if cfg.Image != "mcr.microsoft.com/devcontainers/base:ubuntu" {
		t.Errorf("Image = %q, want %q", cfg.Image, "mcr.microsoft.com/devcontainers/base:ubuntu")
	}
	// A plain devcontainer.json has no agent key, so Agent must be nil.
	if cfg.Agent != nil {
		t.Errorf("Agent = %+v, want nil for plain devcontainer.json", cfg.Agent)
	}
}

func TestParseFile_NonexistentFile(t *testing.T) {
	_, err := parseFile(filepath.Join("testdata", "does_not_exist.json"))
	if err == nil {
		t.Fatal("parseFile() expected error for nonexistent file, got nil")
	}
	if !strings.Contains(err.Error(), "reading file") {
		t.Errorf("error = %v, want error containing %q", err, "reading file")
	}
}

func TestParseFile_InvalidJSON(t *testing.T) {
	// Create a temporary file with invalid JSON.
	dir := t.TempDir()
	path := filepath.Join(dir, "bad.json")
	if err := os.WriteFile(path, []byte(`{"name": broken}`), 0o644); err != nil {
		t.Fatalf("writing temp file: %v", err)
	}

	_, err := parseFile(path)
	if err == nil {
		t.Fatal("parseFile() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "standardizing JSONC") {
		t.Errorf("error = %v, want error containing %q", err, "standardizing JSONC")
	}
}

// ---------------------------------------------------------------------------
// Load tests (config resolution order)
// ---------------------------------------------------------------------------

func TestLoad_ResolutionOrder(t *testing.T) {
	tests := []struct {
		name     string
		files    map[string]string // relative path -> content
		wantName string            // expected config name
		wantRel  string            // expected resolved relative path suffix
		wantErr  bool
	}{
		{
			name: "root agentcontainer.json takes priority",
			files: map[string]string{
				"agentcontainer.json":               `{"name":"root","image":"alpine:3"}`,
				".devcontainer/agentcontainer.json": `{"name":"devcontainer-agent","image":"alpine:3"}`,
				".devcontainer/devcontainer.json":   `{"name":"devcontainer","image":"alpine:3"}`,
			},
			wantName: "root",
			wantRel:  "agentcontainer.json",
		},
		{
			name: ".devcontainer/agentcontainer.json is second",
			files: map[string]string{
				".devcontainer/agentcontainer.json": `{"name":"devcontainer-agent","image":"alpine:3"}`,
				".devcontainer/devcontainer.json":   `{"name":"devcontainer","image":"alpine:3"}`,
			},
			wantName: "devcontainer-agent",
			wantRel:  filepath.Join(".devcontainer", "agentcontainer.json"),
		},
		{
			name: ".devcontainer/devcontainer.json is fallback",
			files: map[string]string{
				".devcontainer/devcontainer.json": `{"name":"devcontainer","image":"alpine:3"}`,
			},
			wantName: "devcontainer",
			wantRel:  filepath.Join(".devcontainer", "devcontainer.json"),
		},
		{
			name:    "no config files returns error",
			files:   map[string]string{},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()

			for relPath, content := range tt.files {
				absPath := filepath.Join(dir, relPath)
				if err := os.MkdirAll(filepath.Dir(absPath), 0o755); err != nil {
					t.Fatalf("creating directory: %v", err)
				}
				if err := os.WriteFile(absPath, []byte(content), 0o644); err != nil {
					t.Fatalf("writing file %s: %v", relPath, err)
				}
			}

			cfg, resolvedPath, err := Load(dir)

			if tt.wantErr {
				if err == nil {
					t.Fatal("Load() expected error, got nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Load() unexpected error: %v", err)
			}

			if cfg.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", cfg.Name, tt.wantName)
			}

			wantPath := filepath.Join(dir, tt.wantRel)
			if resolvedPath != wantPath {
				t.Errorf("resolvedPath = %q, want %q", resolvedPath, wantPath)
			}
		})
	}
}

func TestLoad_DevcontainerHasNilAgent(t *testing.T) {
	dir := t.TempDir()

	devcontainerDir := filepath.Join(dir, ".devcontainer")
	if err := os.MkdirAll(devcontainerDir, 0o755); err != nil {
		t.Fatalf("creating .devcontainer dir: %v", err)
	}

	content := `{"name":"plain-dc","image":"ubuntu:24.04"}`
	if err := os.WriteFile(filepath.Join(devcontainerDir, "devcontainer.json"), []byte(content), 0o644); err != nil {
		t.Fatalf("writing devcontainer.json: %v", err)
	}

	cfg, _, err := Load(dir)
	if err != nil {
		t.Fatalf("Load() unexpected error: %v", err)
	}

	if cfg.Agent != nil {
		t.Errorf("Agent = %+v, want nil for plain devcontainer.json (default-deny)", cfg.Agent)
	}
}

func TestLoad_ParseError(t *testing.T) {
	dir := t.TempDir()

	// Write invalid JSON to root agentcontainer.json.
	if err := os.WriteFile(filepath.Join(dir, "agentcontainer.json"), []byte(`{invalid`), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, _, err := Load(dir)
	if err == nil {
		t.Fatal("Load() expected error for invalid JSON, got nil")
	}
	if !strings.Contains(err.Error(), "parsing agentcontainer.json") {
		t.Errorf("error = %v, want error containing %q", err, "parsing agentcontainer.json")
	}
}

// ---------------------------------------------------------------------------
// Validate tests
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// New fields round-trip tests (M1 spec alignment)
// ---------------------------------------------------------------------------

func TestParseFile_NewFields(t *testing.T) {
	cfg, err := parseFile(filepath.Join("testdata", "new_fields.json"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	// ShellCommand.Args
	cmd := cfg.Agent.Capabilities.Shell.Commands[0]
	if got := len(cmd.Args); got != 2 {
		t.Errorf("len(Shell.Commands[0].Args) = %d, want 2", got)
	} else {
		if cmd.Args[0] != "--file" {
			t.Errorf("Shell.Commands[0].Args[0] = %q, want %q", cmd.Args[0], "--file")
		}
		if cmd.Args[1] != "*.sh" {
			t.Errorf("Shell.Commands[0].Args[1] = %q, want %q", cmd.Args[1], "*.sh")
		}
	}

	// ShellCommand.ScriptValidation
	if cmd.ScriptValidation != "ast" {
		t.Errorf("Shell.Commands[0].ScriptValidation = %q, want %q", cmd.ScriptValidation, "ast")
	}

	// GitCaps.Operations
	git := cfg.Agent.Capabilities.Git
	if git == nil {
		t.Fatal("Agent.Capabilities.Git is nil, want non-nil")
	}
	if got := len(git.Operations); got != 3 {
		t.Errorf("len(Git.Operations) = %d, want 3", got)
	} else {
		wantOps := []string{"clone", "pull", "push"}
		for i, want := range wantOps {
			if git.Operations[i] != want {
				t.Errorf("Git.Operations[%d] = %q, want %q", i, git.Operations[i], want)
			}
		}
	}
	// Ensure branches still parse alongside operations.
	if git.Branches == nil {
		t.Fatal("Git.Branches is nil, want non-nil")
	}
	if got := len(git.Branches.Push); got != 1 {
		t.Errorf("len(Git.Branches.Push) = %d, want 1", got)
	}

	// MCPToolConfig.Mounts
	helm, ok := cfg.Agent.Tools.MCP["helm"]
	if !ok {
		t.Fatal("MCP[\"helm\"] not found")
	}
	if got := len(helm.Mounts); got != 1 {
		t.Errorf("len(MCP[\"helm\"].Mounts) = %d, want 1", got)
	} else if helm.Mounts[0] != "/home/user/.kube:/root/.kube:ro" {
		t.Errorf("MCP[\"helm\"].Mounts[0] = %q, want %q", helm.Mounts[0], "/home/user/.kube:/root/.kube:ro")
	}

	// SkillConfig.Requires
	skill, ok := cfg.Agent.Tools.Skills["code-review"]
	if !ok {
		t.Fatal("Skills[\"code-review\"] not found")
	}
	if got := len(skill.Requires); got != 2 {
		t.Errorf("len(Skills[\"code-review\"].Requires) = %d, want 2", got)
	} else {
		if skill.Requires[0] != "filesystem.read" {
			t.Errorf("Skills[\"code-review\"].Requires[0] = %q, want %q", skill.Requires[0], "filesystem.read")
		}
		if skill.Requires[1] != "network.egress" {
			t.Errorf("Skills[\"code-review\"].Requires[1] = %q, want %q", skill.Requires[1], "network.egress")
		}
	}

	// SecretConfig: Rotation, Role, Path
	secret, ok := cfg.Agent.Secrets["VAULT_TOKEN"]
	if !ok {
		t.Fatal("Secrets[\"VAULT_TOKEN\"] not found")
	}
	if secret.Rotation != "24h" {
		t.Errorf("Secrets[\"VAULT_TOKEN\"].Rotation = %q, want %q", secret.Rotation, "24h")
	}
	if secret.Role != "agent-reader" {
		t.Errorf("Secrets[\"VAULT_TOKEN\"].Role = %q, want %q", secret.Role, "agent-reader")
	}
	if secret.Path != "secret/data/agent" {
		t.Errorf("Secrets[\"VAULT_TOKEN\"].Path = %q, want %q", secret.Path, "secret/data/agent")
	}
}

func TestParseFile_NewFieldsOmitempty(t *testing.T) {
	// Existing valid.json has none of the new fields. They should all be zero values.
	cfg, err := parseFile(filepath.Join("testdata", "valid.json"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	// ShellCommand.Args and ScriptValidation should be zero.
	for i, cmd := range cfg.Agent.Capabilities.Shell.Commands {
		if cmd.Args != nil {
			t.Errorf("Shell.Commands[%d].Args = %v, want nil", i, cmd.Args)
		}
		if cmd.ScriptValidation != "" {
			t.Errorf("Shell.Commands[%d].ScriptValidation = %q, want empty", i, cmd.ScriptValidation)
		}
	}

	// GitCaps.Operations should be nil.
	if cfg.Agent.Capabilities.Git.Operations != nil {
		t.Errorf("Git.Operations = %v, want nil", cfg.Agent.Capabilities.Git.Operations)
	}

	// MCPToolConfig.Mounts should be nil.
	helm := cfg.Agent.Tools.MCP["helm"]
	if helm.Mounts != nil {
		t.Errorf("MCP[\"helm\"].Mounts = %v, want nil", helm.Mounts)
	}

	// SkillConfig.Requires should be nil.
	skill := cfg.Agent.Tools.Skills["code-review"]
	if skill.Requires != nil {
		t.Errorf("Skills[\"code-review\"].Requires = %v, want nil", skill.Requires)
	}

	// SecretConfig: Rotation, Role, Path should be empty.
	secret := cfg.Agent.Secrets["GITHUB_TOKEN"]
	if secret.Rotation != "" {
		t.Errorf("Secrets[\"GITHUB_TOKEN\"].Rotation = %q, want empty", secret.Rotation)
	}
	if secret.Role != "" {
		t.Errorf("Secrets[\"GITHUB_TOKEN\"].Role = %q, want empty", secret.Role)
	}
	if secret.Path != "" {
		t.Errorf("Secrets[\"GITHUB_TOKEN\"].Path = %q, want empty", secret.Path)
	}
}

func TestMarshalRoundTrip_NewFields(t *testing.T) {
	// Parse, marshal back to JSON, parse again, and verify fields survive the round-trip.
	cfg, err := parseFile(filepath.Join("testdata", "new_fields.json"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("json.Marshal() unexpected error: %v", err)
	}

	var cfg2 AgentContainer
	if err := json.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("json.Unmarshal() unexpected error: %v", err)
	}

	// Verify all new fields survive the round-trip.
	cmd := cfg2.Agent.Capabilities.Shell.Commands[0]
	if len(cmd.Args) != 2 || cmd.Args[0] != "--file" {
		t.Errorf("round-trip Shell.Commands[0].Args = %v, want [--file *.sh]", cmd.Args)
	}
	if cmd.ScriptValidation != "ast" {
		t.Errorf("round-trip Shell.Commands[0].ScriptValidation = %q, want %q", cmd.ScriptValidation, "ast")
	}
	if len(cfg2.Agent.Capabilities.Git.Operations) != 3 {
		t.Errorf("round-trip Git.Operations = %v, want [clone pull push]", cfg2.Agent.Capabilities.Git.Operations)
	}
	if len(cfg2.Agent.Tools.MCP["helm"].Mounts) != 1 {
		t.Errorf("round-trip MCP[\"helm\"].Mounts = %v, want 1 element", cfg2.Agent.Tools.MCP["helm"].Mounts)
	}
	if len(cfg2.Agent.Tools.Skills["code-review"].Requires) != 2 {
		t.Errorf("round-trip Skills[\"code-review\"].Requires = %v, want 2 elements", cfg2.Agent.Tools.Skills["code-review"].Requires)
	}
	secret := cfg2.Agent.Secrets["VAULT_TOKEN"]
	if secret.Rotation != "24h" || secret.Role != "agent-reader" || secret.Path != "secret/data/agent" {
		t.Errorf("round-trip secret = {Rotation:%q, Role:%q, Path:%q}, want {24h, agent-reader, secret/data/agent}",
			secret.Rotation, secret.Role, secret.Path)
	}
}

func TestSecretConfig_AllowedTools(t *testing.T) {
	raw := `{
		"name": "test",
		"image": "alpine:3",
		"agent": {
			"secrets": {
				"API_KEY": {
					"provider": "vault",
					"path": "/run/secrets/API_KEY",
					"ttl": "1h",
					"allowedTools": ["http-client", "api-tool"]
				},
				"DB_PASS": {
					"provider": "env",
					"path": "/run/secrets/DB_PASS"
				}
			}
		}
	}`

	var cfg AgentContainer
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("Unmarshal() unexpected error: %v", err)
	}

	apiKey, ok := cfg.Agent.Secrets["API_KEY"]
	if !ok {
		t.Fatal("Secrets[\"API_KEY\"] not found")
	}
	if len(apiKey.AllowedTools) != 2 {
		t.Fatalf("len(AllowedTools) = %d, want 2", len(apiKey.AllowedTools))
	}
	if apiKey.AllowedTools[0] != "http-client" {
		t.Errorf("AllowedTools[0] = %q, want %q", apiKey.AllowedTools[0], "http-client")
	}
	if apiKey.AllowedTools[1] != "api-tool" {
		t.Errorf("AllowedTools[1] = %q, want %q", apiKey.AllowedTools[1], "api-tool")
	}

	dbPass, ok := cfg.Agent.Secrets["DB_PASS"]
	if !ok {
		t.Fatal("Secrets[\"DB_PASS\"] not found")
	}
	if dbPass.AllowedTools != nil {
		t.Errorf("AllowedTools = %v, want nil", dbPass.AllowedTools)
	}

	// Validate should pass now that secrets are supported.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AgentContainer
		wantErr string
	}{
		{
			name: "valid with image",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
			},
			wantErr: "",
		},
		{
			name: "valid with build",
			cfg: AgentContainer{
				Name: "test",
				Build: &BuildConfig{
					Dockerfile: "Dockerfile",
					Context:    ".",
				},
			},
			wantErr: "",
		},
		{
			name: "valid with image and agent",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Capabilities: &Capabilities{
						Shell: &ShellCaps{
							Commands: []ShellCommand{
								{Binary: "git"},
								{Binary: "npm"},
							},
						},
						Network: &NetworkCaps{
							Egress: []EgressRule{
								{Host: "github.com", Port: 443},
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name:    "missing both image and build",
			cfg:     AgentContainer{Name: "test"},
			wantErr: "either image or build must be specified",
		},
		{
			name: "both image and build specified",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Build: &BuildConfig{Dockerfile: "Dockerfile"},
			},
			wantErr: "image and build are mutually exclusive",
		},
		{
			name: "shell command with empty binary",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Capabilities: &Capabilities{
						Shell: &ShellCaps{
							Commands: []ShellCommand{
								{Binary: "git"},
								{Binary: ""},
							},
						},
					},
				},
			},
			wantErr: "agent.capabilities.shell.commands[1]: binary must not be empty",
		},
		{
			name: "network egress with empty host",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Capabilities: &Capabilities{
						Network: &NetworkCaps{
							Egress: []EgressRule{
								{Host: "github.com", Port: 443},
								{Host: "", Port: 80},
							},
						},
					},
				},
			},
			wantErr: "agent.capabilities.network.egress[1]: host must not be empty",
		},
		{
			name: "nil agent passes validation",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: nil,
			},
			wantErr: "",
		},
		{
			name: "agent with nil capabilities passes validation",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{},
			},
			wantErr: "",
		},
		{
			name: "accepts agent.policy with valid escalation",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Policy: &PolicyConfig{Escalation: "deny"},
				},
			},
			wantErr: "",
		},
		{
			name: "rejects invalid escalation",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Policy: &PolicyConfig{Escalation: "invalid"},
				},
			},
			wantErr: "agent.policy.escalation: invalid value",
		},
		{
			name: "rejects invalid sessionTimeout",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Policy: &PolicyConfig{SessionTimeout: "not-a-duration"},
				},
			},
			wantErr: "agent.policy.sessionTimeout: invalid duration",
		},
		{
			name: "agent.secrets passes validation",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Secrets: map[string]SecretConfig{
						"github": {Provider: "vault", Path: "/run/secrets/GITHUB_TOKEN"},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "accepts valid agent.provenance",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Provenance: &ProvenanceConfig{
						Require: &ProvenanceRequirements{Signatures: true, SLSALevel: 3},
					},
				},
			},
		},
		{
			name: "accepts valid provenance policy channel",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Provenance: &ProvenanceConfig{
						Policy: &PolicyChannelConfig{Ref: "ghcr.io/acme/agentcontainers-policy:prod"},
					},
				},
			},
		},
		{
			name: "rejects empty provenance policy ref",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Provenance: &ProvenanceConfig{
						Policy: &PolicyChannelConfig{Ref: " \t "},
					},
				},
			},
			wantErr: "agent.provenance.policy.ref: must not be empty",
		},
		{
			name: "rejects invalid slsaLevel",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Provenance: &ProvenanceConfig{
						Require: &ProvenanceRequirements{SLSALevel: 5},
					},
				},
			},
			wantErr: "agent.provenance.require.slsaLevel: must be 0-4",
		},
		{
			name: "rejects unimplemented scriptValidation",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Capabilities: &Capabilities{
						Shell: &ShellCaps{
							Commands: []ShellCommand{
								{Binary: "bash", ScriptValidation: "strict"},
							},
						},
					},
				},
			},
			wantErr: "scriptValidation is not yet implemented",
		},
		{
			name: "rejects unimplemented denyEnv",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Capabilities: &Capabilities{
						Shell: &ShellCaps{
							Commands: []ShellCommand{
								{Binary: "bash", DenyEnv: []string{"SECRET_KEY"}},
							},
						},
					},
				},
			},
			wantErr: "denyEnv is not yet implemented",
		},
		{
			name: "enforcer defaults absent — no error",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{},
			},
			wantErr: "",
		},
		{
			name: "enforcer with image passes validation",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Enforcer: &EnforcerConfig{
						Image: "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:v0.3.0",
					},
				},
			},
			wantErr: "",
		},
		{
			name: "enforcer with addr passes validation",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Enforcer: &EnforcerConfig{
						Addr: "127.0.0.1:50051",
					},
				},
			},
			wantErr: "",
		},
		{
			name: "enforcer required with addr is valid",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Enforcer: &EnforcerConfig{
						Required: boolPtr(true),
						Addr:     "127.0.0.1:50051",
					},
				},
			},
			wantErr: "",
		},
		{
			name: "enforcer required false is valid",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Enforcer: &EnforcerConfig{
						Required: boolPtr(false),
					},
				},
			},
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()

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

func TestValidate_MultipleErrors(t *testing.T) {
	cfg := AgentContainer{
		Name: "test",
		// No image, no build.
		Agent: &AgentConfig{
			Capabilities: &Capabilities{
				Shell: &ShellCaps{
					Commands: []ShellCommand{
						{Binary: ""},
					},
				},
				Network: &NetworkCaps{
					Egress: []EgressRule{
						{Host: ""},
					},
				},
			},
		},
	}

	err := cfg.Validate()
	if err == nil {
		t.Fatal("Validate() expected error, got nil")
	}

	errStr := err.Error()
	expectedErrors := []string{
		"either image or build must be specified",
		"agent.capabilities.shell.commands[0]: binary must not be empty",
		"agent.capabilities.network.egress[0]: host must not be empty",
	}

	for _, expected := range expectedErrors {
		if !strings.Contains(errStr, expected) {
			t.Errorf("Validate() error missing %q in: %s", expected, errStr)
		}
	}
}

// ---------------------------------------------------------------------------
// MCPToolConfig Type and ComponentLimits tests
// ---------------------------------------------------------------------------

func TestParseFile_ComponentTools(t *testing.T) {
	cfg, err := parseFile(filepath.Join("testdata", "component_tools.json"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	tools := cfg.Agent.Tools.MCP

	// Verify component-type tool with limits.
	ts, ok := tools["time-server"]
	if !ok {
		t.Fatal("MCP[\"time-server\"] not found")
	}
	if ts.Type != "component" {
		t.Errorf("time-server.Type = %q, want %q", ts.Type, "component")
	}
	if ts.Image != "ghcr.io/microsoft/time-server-js:latest" {
		t.Errorf("time-server.Image = %q, want %q", ts.Image, "ghcr.io/microsoft/time-server-js:latest")
	}
	if ts.Limits == nil {
		t.Fatal("time-server.Limits is nil, want non-nil")
	}
	if ts.Limits.MemoryMB != 64 {
		t.Errorf("time-server.Limits.MemoryMB = %d, want 64", ts.Limits.MemoryMB)
	}
	if ts.Limits.TimeoutMs != 5000 {
		t.Errorf("time-server.Limits.TimeoutMs = %d, want 5000", ts.Limits.TimeoutMs)
	}
	if ts.Limits.Fuel != 1000000 {
		t.Errorf("time-server.Limits.Fuel = %d, want 1000000", ts.Limits.Fuel)
	}

	// Verify component-type tool without limits.
	gh, ok := tools["github-api"]
	if !ok {
		t.Fatal("MCP[\"github-api\"] not found")
	}
	if gh.Type != "component" {
		t.Errorf("github-api.Type = %q, want %q", gh.Type, "component")
	}
	if gh.Limits != nil {
		t.Errorf("github-api.Limits = %+v, want nil", gh.Limits)
	}
	if len(gh.Secrets) != 1 || gh.Secrets[0] != "github-token" {
		t.Errorf("github-api.Secrets = %v, want [github-token]", gh.Secrets)
	}

	// Verify container-type tool.
	pg, ok := tools["postgres"]
	if !ok {
		t.Fatal("MCP[\"postgres\"] not found")
	}
	if pg.Type != "container" {
		t.Errorf("postgres.Type = %q, want %q", pg.Type, "container")
	}
	if pg.Limits != nil {
		t.Errorf("postgres.Limits = %+v, want nil", pg.Limits)
	}
	if len(pg.Mounts) != 1 {
		t.Errorf("postgres.Mounts = %v, want 1 element", pg.Mounts)
	}
}

func TestRoundTrip_ComponentLimits(t *testing.T) {
	raw := `{
		"name": "test",
		"image": "alpine:3",
		"agent": {
			"tools": {
				"mcp": {
					"echo": {
						"type": "component",
						"image": "ghcr.io/mcp-tools/echo:latest",
						"limits": {
							"memory_mb": 32,
							"timeout_ms": 1000,
							"fuel": 500000
						}
					}
				}
			}
		}
	}`

	var cfg AgentContainer
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("Unmarshal() unexpected error: %v", err)
	}

	echo, ok := cfg.Agent.Tools.MCP["echo"]
	if !ok {
		t.Fatal("MCP[\"echo\"] not found")
	}
	if echo.Type != "component" {
		t.Errorf("Type = %q, want %q", echo.Type, "component")
	}
	if echo.Limits == nil {
		t.Fatal("Limits is nil")
	}
	if echo.Limits.MemoryMB != 32 {
		t.Errorf("MemoryMB = %d, want 32", echo.Limits.MemoryMB)
	}
	if echo.Limits.TimeoutMs != 1000 {
		t.Errorf("TimeoutMs = %d, want 1000", echo.Limits.TimeoutMs)
	}
	if echo.Limits.Fuel != 500000 {
		t.Errorf("Fuel = %d, want 500000", echo.Limits.Fuel)
	}

	// Marshal and unmarshal again.
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal() unexpected error: %v", err)
	}
	var cfg2 AgentContainer
	if err := json.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("Unmarshal() round-trip error: %v", err)
	}
	echo2, ok := cfg2.Agent.Tools.MCP["echo"]
	if !ok {
		t.Fatal("round-trip MCP[\"echo\"] not found")
	}
	if echo2.Limits == nil || echo2.Limits.MemoryMB != 32 || echo2.Limits.TimeoutMs != 1000 || echo2.Limits.Fuel != 500000 {
		t.Errorf("round-trip Limits = %+v, want {32, 1000, 500000}", echo2.Limits)
	}

	// Validate should pass.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_MCPToolType(t *testing.T) {
	tests := []struct {
		name    string
		cfg     AgentContainer
		wantErr string
	}{
		{
			name: "container type with mounts is valid",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"pg": {
								Type:   "container",
								Image:  "postgres:16",
								Mounts: []string{"/data:/var/lib/postgresql/data"},
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "component type without mounts is valid",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"echo": {
								Type:  "component",
								Image: "ghcr.io/mcp-tools/echo:latest",
								Limits: &ComponentLimits{
									MemoryMB: 64,
								},
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "empty type defaults to container (valid with mounts)",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"tool": {
								Image:  "myimage:latest",
								Mounts: []string{"/src:/dst"},
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "invalid type is rejected",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"bad": {
								Type:  "sidecar",
								Image: "myimage:latest",
							},
						},
					},
				},
			},
			wantErr: `agent.tools.mcp["bad"].type: invalid value "sidecar"`,
		},
		{
			name: "component type with mounts is rejected",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"echo": {
								Type:   "component",
								Image:  "ghcr.io/mcp-tools/echo:latest",
								Mounts: []string{"/host:/container"},
							},
						},
					},
				},
			},
			wantErr: `agent.tools.mcp["echo"].mounts: mounts are not valid for component-type tools`,
		},
		{
			name: "container type with limits is rejected",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"pg": {
								Type:   "container",
								Image:  "postgres:16",
								Limits: &ComponentLimits{MemoryMB: 64},
							},
						},
					},
				},
			},
			wantErr: `agent.tools.mcp["pg"].limits: limits are only valid for component-type tools`,
		},
		{
			name: "empty type with limits is rejected",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"tool": {
								Image:  "myimage:latest",
								Limits: &ComponentLimits{MemoryMB: 32},
							},
						},
					},
				},
			},
			wantErr: `agent.tools.mcp["tool"].limits: limits are only valid for component-type tools`,
		},
		{
			name: "component with zero limits is valid",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"echo": {
								Type:   "component",
								Image:  "ghcr.io/mcp-tools/echo:latest",
								Limits: &ComponentLimits{},
							},
						},
					},
				},
			},
			wantErr: "",
		},
		{
			name: "empty image is rejected",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"badtool": {
								Type: "component",
								// Image is missing (empty)
								Limits: &ComponentLimits{
									MemoryMB: 64,
								},
							},
						},
					},
				},
			},
			wantErr: `agent.tools.mcp["badtool"].image: image must not be empty`,
		},
		{
			name: "empty image on container type is rejected",
			cfg: AgentContainer{
				Name:  "test",
				Image: "alpine:3",
				Agent: &AgentConfig{
					Tools: &ToolsConfig{
						MCP: map[string]MCPToolConfig{
							"badcontainer": {
								Type: "container",
								// Image is missing (empty)
								Mounts: []string{"/data:/data"},
							},
						},
					},
				},
			},
			wantErr: `agent.tools.mcp["badcontainer"].image: image must not be empty`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
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

func TestValidate_FromTestdata_ComponentTools(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr string
	}{
		{
			name:    "component_tools.json passes validation",
			file:    "component_tools.json",
			wantErr: "",
		},
		{
			name:    "invalid_component_mounts.json fails validation",
			file:    "invalid_component_mounts.json",
			wantErr: "mounts are not valid for component-type tools",
		},
		{
			name:    "invalid_container_limits.json fails validation",
			file:    "invalid_container_limits.json",
			wantErr: "limits are only valid for component-type tools",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatalf("parseFile() error: %v", err)
			}

			err = cfg.Validate()

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

func boolPtr(v bool) *bool { return &v }

func TestRoundTrip_EnforcerConfig(t *testing.T) {
	raw := `{
		"name": "test",
		"image": "alpine:3",
		"agent": {
			"enforcer": {
				"image": "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:v0.3.0",
				"required": false,
				"addr": "127.0.0.1:50051"
			}
		}
	}`

	var cfg AgentContainer
	if err := json.Unmarshal([]byte(raw), &cfg); err != nil {
		t.Fatalf("Unmarshal() unexpected error: %v", err)
	}

	if cfg.Agent == nil || cfg.Agent.Enforcer == nil {
		t.Fatal("Agent.Enforcer is nil")
	}

	e := cfg.Agent.Enforcer
	if e.Image != "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:v0.3.0" {
		t.Errorf("Image = %q, want %q", e.Image, "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:v0.3.0")
	}
	if e.Required == nil || *e.Required != false {
		t.Errorf("Required = %v, want false", e.Required)
	}
	if e.Addr != "127.0.0.1:50051" {
		t.Errorf("Addr = %q, want %q", e.Addr, "127.0.0.1:50051")
	}

	// Round-trip: marshal and unmarshal again.
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatalf("Marshal() unexpected error: %v", err)
	}

	var cfg2 AgentContainer
	if err := json.Unmarshal(data, &cfg2); err != nil {
		t.Fatalf("Unmarshal() round-trip error: %v", err)
	}

	e2 := cfg2.Agent.Enforcer
	if e2.Image != e.Image {
		t.Errorf("round-trip Image = %q, want %q", e2.Image, e.Image)
	}
	if e2.Required == nil || *e2.Required != *e.Required {
		t.Errorf("round-trip Required mismatch")
	}
	if e2.Addr != e.Addr {
		t.Errorf("round-trip Addr = %q, want %q", e2.Addr, e.Addr)
	}

	// Validate should pass.
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() unexpected error: %v", err)
	}
}

func TestValidate_FromTestdata(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		wantErr string
	}{
		{
			name:    "valid.json passes validation",
			file:    "valid.json",
			wantErr: "",
		},
		{
			name:    "minimal.json passes validation",
			file:    "minimal.json",
			wantErr: "",
		},
		{
			name:    "with_comments.jsonc passes validation",
			file:    "with_comments.jsonc",
			wantErr: "",
		},
		{
			name:    "devcontainer.json passes validation",
			file:    "devcontainer.json",
			wantErr: "",
		},
		{
			name:    "invalid_no_image.json fails validation",
			file:    "invalid_no_image.json",
			wantErr: "either image or build must be specified",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := parseFile(filepath.Join("testdata", tt.file))
			if err != nil {
				t.Fatalf("parseFile() error: %v", err)
			}

			err = cfg.Validate()

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

// ---------------------------------------------------------------------------
// ShellCommand string shorthand tests
// ---------------------------------------------------------------------------

func TestShellCommand_UnmarshalJSON_StringShorthand(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    ShellCommand
		wantErr bool
	}{
		{
			name:  "bare binary",
			input: `"whoami"`,
			want:  ShellCommand{Binary: "whoami"},
		},
		{
			name:  "binary with one subcommand",
			input: `"npm test"`,
			want:  ShellCommand{Binary: "npm", Subcommands: []string{"test"}},
		},
		{
			name:  "binary with multiple subcommand words",
			input: `"npm run build"`,
			want:  ShellCommand{Binary: "npm", Subcommands: []string{"run", "build"}},
		},
		{
			name:  "object form still works",
			input: `{"binary": "git", "subcommands": ["status", "diff"]}`,
			want:  ShellCommand{Binary: "git", Subcommands: []string{"status", "diff"}},
		},
		{
			name:  "object with all fields",
			input: `{"binary": "/usr/bin/npm", "subcommands": ["test"], "denyArgs": ["--script-shell"], "scriptValidation": "ast"}`,
			want: ShellCommand{
				Binary:           "/usr/bin/npm",
				Subcommands:      []string{"test"},
				DenyArgs:         []string{"--script-shell"},
				ScriptValidation: "ast",
			},
		},
		{
			name:    "empty string",
			input:   `""`,
			wantErr: true,
		},
		{
			name:    "whitespace-only string",
			input:   `"  "`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got ShellCommand
			err := json.Unmarshal([]byte(tt.input), &got)
			if tt.wantErr {
				if err == nil {
					t.Errorf("UnmarshalJSON(%s) expected error, got nil", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("UnmarshalJSON(%s) unexpected error: %v", tt.input, err)
			}
			if got.Binary != tt.want.Binary {
				t.Errorf("Binary = %q, want %q", got.Binary, tt.want.Binary)
			}
			if len(got.Subcommands) != len(tt.want.Subcommands) {
				t.Errorf("Subcommands = %v, want %v", got.Subcommands, tt.want.Subcommands)
			} else {
				for i := range got.Subcommands {
					if got.Subcommands[i] != tt.want.Subcommands[i] {
						t.Errorf("Subcommands[%d] = %q, want %q", i, got.Subcommands[i], tt.want.Subcommands[i])
					}
				}
			}
			if len(got.DenyArgs) != len(tt.want.DenyArgs) {
				t.Errorf("DenyArgs = %v, want %v", got.DenyArgs, tt.want.DenyArgs)
			}
			if got.ScriptValidation != tt.want.ScriptValidation {
				t.Errorf("ScriptValidation = %q, want %q", got.ScriptValidation, tt.want.ScriptValidation)
			}
		})
	}
}

func TestShellCaps_UnmarshalJSON_MixedArray(t *testing.T) {
	// A commands array can mix strings and objects.
	input := `{
		"commands": [
			"whoami",
			"npm test",
			{"binary": "git", "subcommands": ["status", "diff"], "denyEnv": ["GIT_SSH_COMMAND"]}
		]
	}`

	var got ShellCaps
	err := json.Unmarshal([]byte(input), &got)
	if err != nil {
		t.Fatalf("UnmarshalJSON() unexpected error: %v", err)
	}

	if len(got.Commands) != 3 {
		t.Fatalf("len(Commands) = %d, want 3", len(got.Commands))
	}

	// "whoami" → bare binary
	if got.Commands[0].Binary != "whoami" {
		t.Errorf("Commands[0].Binary = %q, want %q", got.Commands[0].Binary, "whoami")
	}
	if len(got.Commands[0].Subcommands) != 0 {
		t.Errorf("Commands[0].Subcommands = %v, want empty", got.Commands[0].Subcommands)
	}

	// "npm test" → binary + subcommand
	if got.Commands[1].Binary != "npm" {
		t.Errorf("Commands[1].Binary = %q, want %q", got.Commands[1].Binary, "npm")
	}
	if len(got.Commands[1].Subcommands) != 1 || got.Commands[1].Subcommands[0] != "test" {
		t.Errorf("Commands[1].Subcommands = %v, want [test]", got.Commands[1].Subcommands)
	}

	// object form with denyEnv
	if got.Commands[2].Binary != "git" {
		t.Errorf("Commands[2].Binary = %q, want %q", got.Commands[2].Binary, "git")
	}
	if len(got.Commands[2].DenyEnv) != 1 || got.Commands[2].DenyEnv[0] != "GIT_SSH_COMMAND" {
		t.Errorf("Commands[2].DenyEnv = %v, want [GIT_SSH_COMMAND]", got.Commands[2].DenyEnv)
	}
}

func TestParseFile_StringShorthand(t *testing.T) {
	cfg, err := parseFile(filepath.Join("testdata", "shell_string_shorthand.json"))
	if err != nil {
		t.Fatalf("parseFile() unexpected error: %v", err)
	}

	cmds := cfg.Agent.Capabilities.Shell.Commands
	if len(cmds) != 4 {
		t.Fatalf("len(Shell.Commands) = %d, want 4", len(cmds))
	}

	// String shorthand entries
	if cmds[0].Binary != "ls" {
		t.Errorf("Commands[0].Binary = %q, want %q", cmds[0].Binary, "ls")
	}
	if cmds[1].Binary != "cat" {
		t.Errorf("Commands[1].Binary = %q, want %q", cmds[1].Binary, "cat")
	}
	if cmds[2].Binary != "npm" {
		t.Errorf("Commands[2].Binary = %q, want %q", cmds[2].Binary, "npm")
	}
	if len(cmds[2].Subcommands) != 1 || cmds[2].Subcommands[0] != "test" {
		t.Errorf("Commands[2].Subcommands = %v, want [test]", cmds[2].Subcommands)
	}

	// Object entry
	if cmds[3].Binary != "git" {
		t.Errorf("Commands[3].Binary = %q, want %q", cmds[3].Binary, "git")
	}
	if len(cmds[3].Subcommands) != 2 {
		t.Errorf("Commands[3].Subcommands = %v, want [status diff]", cmds[3].Subcommands)
	}
}
