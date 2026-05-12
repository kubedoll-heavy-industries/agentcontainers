package policy

import (
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

func TestResolve(t *testing.T) {
	tests := []struct {
		name string
		caps *config.Capabilities
		want func(t *testing.T, p *ContainerPolicy)
	}{
		{
			name: "nil capabilities produces strictest defaults",
			caps: nil,
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				assertStringSlice(t, "CapDrop", p.CapDrop, []string{"ALL"})
				assertNilSlice(t, "CapAdd", p.CapAdd)
				assertStringSlice(t, "SecurityOpt", p.SecurityOpt, []string{"no-new-privileges"})
				if !p.ReadonlyRootfs {
					t.Error("ReadonlyRootfs = false, want true")
				}
				assertNilSlice(t, "AllowedMounts", p.AllowedMounts)
				if p.NetworkMode != "none" {
					t.Errorf("NetworkMode = %q, want %q", p.NetworkMode, "none")
				}
				if p.ShellAllowed {
					t.Error("ShellAllowed = true, want false")
				}
				if p.GitAllowed {
					t.Error("GitAllowed = true, want false")
				}
				if p.GitPushAllowed {
					t.Error("GitPushAllowed = true, want false")
				}
			},
		},
		{
			name: "empty capabilities produces strictest defaults",
			caps: &config.Capabilities{},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if !p.ReadonlyRootfs {
					t.Error("ReadonlyRootfs = false, want true")
				}
				if p.NetworkMode != "none" {
					t.Errorf("NetworkMode = %q, want %q", p.NetworkMode, "none")
				}
				if p.ShellAllowed {
					t.Error("ShellAllowed = true, want false")
				}
				if p.GitAllowed {
					t.Error("GitAllowed = true, want false")
				}
			},
		},
		{
			name: "filesystem read patterns produce read-only mounts",
			caps: &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Read: []string{"/home/user/project", "/etc/config"},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if got := len(p.AllowedMounts); got != 2 {
					t.Fatalf("len(AllowedMounts) = %d, want 2", got)
				}
				assertMount(t, p.AllowedMounts[0], "/home/user/project", "/workspace/home/user/project", true)
				assertMount(t, p.AllowedMounts[1], "/etc/config", "/workspace/etc/config", true)
			},
		},
		{
			name: "filesystem write patterns produce read-write mounts",
			caps: &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Write: []string{"/home/user/output"},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if got := len(p.AllowedMounts); got != 1 {
					t.Fatalf("len(AllowedMounts) = %d, want 1", got)
				}
				assertMount(t, p.AllowedMounts[0], "/home/user/output", "/workspace/home/user/output", false)
			},
		},
		{
			name: "filesystem deny patterns exclude from mounts",
			caps: &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Read: []string{"/home/user/project", "/home/user/secrets"},
					Deny: []string{"/home/user/secrets"},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if got := len(p.AllowedMounts); got != 1 {
					t.Fatalf("len(AllowedMounts) = %d, want 1", got)
				}
				assertMount(t, p.AllowedMounts[0], "/home/user/project", "/workspace/home/user/project", true)
			},
		},
		{
			name: "filesystem deny excludes from both read and write",
			caps: &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Read:  []string{"/data/readonly", "/data/blocked"},
					Write: []string{"/data/writable", "/data/blocked"},
					Deny:  []string{"/data/blocked"},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if got := len(p.AllowedMounts); got != 2 {
					t.Fatalf("len(AllowedMounts) = %d, want 2", got)
				}
				assertMount(t, p.AllowedMounts[0], "/data/readonly", "/workspace/data/readonly", true)
				assertMount(t, p.AllowedMounts[1], "/data/writable", "/workspace/data/writable", false)
			},
		},
		{
			name: "filesystem read and write same path deduplicates to read-write",
			caps: &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Read:  []string{"/data/shared", "/data/readonly"},
					Write: []string{"/data/shared", "/data/writable"},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if got := len(p.AllowedMounts); got != 3 {
					t.Fatalf("len(AllowedMounts) = %d, want 3", got)
				}
				// /data/readonly is read-only (only in Read)
				assertMount(t, p.AllowedMounts[0], "/data/readonly", "/workspace/data/readonly", true)
				// /data/shared is read-write (in both Read and Write; Write wins)
				assertMount(t, p.AllowedMounts[1], "/data/shared", "/workspace/data/shared", false)
				// /data/writable is read-write (only in Write)
				assertMount(t, p.AllowedMounts[2], "/data/writable", "/workspace/data/writable", false)
			},
		},
		{
			name: "network egress rules enable bridge mode",
			caps: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "github.com", Port: 443, Protocol: "tcp"},
						{Host: "registry.npmjs.org", Port: 443},
					},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if p.NetworkMode != "bridge" {
					t.Errorf("NetworkMode = %q, want %q", p.NetworkMode, "bridge")
				}
				assertStringSlice(t, "AllowedHosts", p.AllowedHosts, []string{"github.com", "registry.npmjs.org"})
				// Verify AllowedEgressRules are populated with port/protocol.
				if got := len(p.AllowedEgressRules); got != 2 {
					t.Fatalf("len(AllowedEgressRules) = %d, want 2", got)
				}
				if p.AllowedEgressRules[0].Host != "github.com" || p.AllowedEgressRules[0].Port != 443 || p.AllowedEgressRules[0].Protocol != "tcp" {
					t.Errorf("AllowedEgressRules[0] = %+v, want {github.com 443 tcp}", p.AllowedEgressRules[0])
				}
				if p.AllowedEgressRules[1].Host != "registry.npmjs.org" || p.AllowedEgressRules[1].Port != 443 {
					t.Errorf("AllowedEgressRules[1] = %+v, want {registry.npmjs.org 443 ...}", p.AllowedEgressRules[1])
				}
			},
		},
		{
			name: "network nil egress keeps none mode",
			caps: &config.Capabilities{
				Network: &config.NetworkCaps{},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if p.NetworkMode != "none" {
					t.Errorf("NetworkMode = %q, want %q", p.NetworkMode, "none")
				}
				assertNilSlice(t, "AllowedHosts", p.AllowedHosts)
			},
		},
		{
			name: "network explicit empty egress keeps none mode",
			caps: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{},
					Deny:   []string{},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if p.NetworkMode != "none" {
					t.Errorf("NetworkMode = %q, want %q", p.NetworkMode, "none")
				}
				assertNilSlice(t, "AllowedHosts", p.AllowedHosts)
				assertNilSlice(t, "AllowedEgressRules", p.AllowedEgressRules)
			},
		},
		{
			name: "network deny filters allowed hosts and egress rules",
			caps: &config.Capabilities{
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "github.com", Port: 443},
						{Host: "evil.com", Port: 443},
						{Host: "npmjs.org", Port: 443},
					},
					Deny: []string{"evil.com"},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if p.NetworkMode != "bridge" {
					t.Errorf("NetworkMode = %q, want %q", p.NetworkMode, "bridge")
				}
				assertStringSlice(t, "AllowedHosts", p.AllowedHosts, []string{"github.com", "npmjs.org"})
				// Verify AllowedEgressRules also has evil.com filtered out.
				if got := len(p.AllowedEgressRules); got != 2 {
					t.Fatalf("len(AllowedEgressRules) = %d, want 2", got)
				}
				if p.AllowedEgressRules[0].Host != "github.com" {
					t.Errorf("AllowedEgressRules[0].Host = %q, want %q", p.AllowedEgressRules[0].Host, "github.com")
				}
				if p.AllowedEgressRules[1].Host != "npmjs.org" {
					t.Errorf("AllowedEgressRules[1].Host = %q, want %q", p.AllowedEgressRules[1].Host, "npmjs.org")
				}
			},
		},
		{
			name: "shell commands enable shell access",
			caps: &config.Capabilities{
				Shell: &config.ShellCaps{
					Commands: []config.ShellCommand{
						{Binary: "git"},
						{Binary: "npm", Subcommands: []string{"install", "test"}},
						{Binary: "make"},
					},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if !p.ShellAllowed {
					t.Error("ShellAllowed = false, want true")
				}
				assertStringSlice(t, "AllowedCommands", p.AllowedCommands, []string{"git", "npm", "make"})
			},
		},
		{
			name: "empty shell commands keep shell denied",
			caps: &config.Capabilities{
				Shell: &config.ShellCaps{},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if p.ShellAllowed {
					t.Error("ShellAllowed = true, want false")
				}
				assertNilSlice(t, "AllowedCommands", p.AllowedCommands)
			},
		},
		{
			name: "git allowed with push branches",
			caps: &config.Capabilities{
				Git: &config.GitCaps{
					Branches: &config.BranchCaps{
						Push: []string{"feature/*", "fix/*"},
						Deny: []string{"main", "release/*"},
					},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if !p.GitAllowed {
					t.Error("GitAllowed = false, want true")
				}
				if !p.GitPushAllowed {
					t.Error("GitPushAllowed = false, want true")
				}
				assertStringSlice(t, "GitPushBranches", p.GitPushBranches, []string{"feature/*", "fix/*"})
				assertStringSlice(t, "GitDenyBranches", p.GitDenyBranches, []string{"main", "release/*"})
			},
		},
		{
			name: "git allowed without push",
			caps: &config.Capabilities{
				Git: &config.GitCaps{
					Branches: &config.BranchCaps{
						Deny: []string{"main"},
					},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if !p.GitAllowed {
					t.Error("GitAllowed = false, want true")
				}
				if p.GitPushAllowed {
					t.Error("GitPushAllowed = true, want false")
				}
				assertStringSlice(t, "GitDenyBranches", p.GitDenyBranches, []string{"main"})
			},
		},
		{
			name: "git with nil branches still enables git",
			caps: &config.Capabilities{
				Git: &config.GitCaps{},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				if !p.GitAllowed {
					t.Error("GitAllowed = false, want true")
				}
				if p.GitPushAllowed {
					t.Error("GitPushAllowed = true, want false")
				}
			},
		},
		{
			name: "full capabilities set",
			caps: &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Read:  []string{"/project"},
					Write: []string{"/output"},
					Deny:  []string{"/output/.env"},
				},
				Network: &config.NetworkCaps{
					Egress: []config.EgressRule{
						{Host: "api.github.com", Port: 443},
					},
				},
				Shell: &config.ShellCaps{
					Commands: []config.ShellCommand{
						{Binary: "git"},
						{Binary: "go", Subcommands: []string{"build", "test"}},
					},
				},
				Git: &config.GitCaps{
					Branches: &config.BranchCaps{
						Push: []string{"feature/*"},
						Deny: []string{"main"},
					},
				},
			},
			want: func(t *testing.T, p *ContainerPolicy) {
				t.Helper()
				assertStringSlice(t, "CapDrop", p.CapDrop, []string{"ALL"})
				assertStringSlice(t, "SecurityOpt", p.SecurityOpt, []string{"no-new-privileges"})
				if !p.ReadonlyRootfs {
					t.Error("ReadonlyRootfs = false, want true")
				}
				if got := len(p.AllowedMounts); got != 2 {
					t.Fatalf("len(AllowedMounts) = %d, want 2", got)
				}
				assertMount(t, p.AllowedMounts[0], "/project", "/workspace/project", true)
				assertMount(t, p.AllowedMounts[1], "/output", "/workspace/output", false)
				if p.NetworkMode != "bridge" {
					t.Errorf("NetworkMode = %q, want %q", p.NetworkMode, "bridge")
				}
				assertStringSlice(t, "AllowedHosts", p.AllowedHosts, []string{"api.github.com"})
				if !p.ShellAllowed {
					t.Error("ShellAllowed = false, want true")
				}
				assertStringSlice(t, "AllowedCommands", p.AllowedCommands, []string{"git", "go"})
				if !p.GitPushAllowed {
					t.Error("GitPushAllowed = false, want true")
				}
				assertStringSlice(t, "GitPushBranches", p.GitPushBranches, []string{"feature/*"})
				assertStringSlice(t, "GitDenyBranches", p.GitDenyBranches, []string{"main"})
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := Resolve(tt.caps)
			if got == nil {
				t.Fatal("Resolve() returned nil")
			}
			tt.want(t, got)
		})
	}
}

func TestSecretACL(t *testing.T) {
	tests := []struct {
		name string
		acl  SecretACL
	}{
		{
			name: "full ACL with TTL",
			acl: SecretACL{
				Path:         "/run/secrets/GITHUB_TOKEN",
				AllowedTools: []string{"git-tool", "code-review"},
				TTLSeconds:   3600,
			},
		},
		{
			name: "ACL without TTL",
			acl: SecretACL{
				Path:         "/run/secrets/NPM_TOKEN",
				AllowedTools: []string{"npm-publish"},
				TTLSeconds:   0,
			},
		},
		{
			name: "ACL with no allowed tools (deny all)",
			acl: SecretACL{
				Path: "/run/secrets/LOCKED_SECRET",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.acl.Path == "" {
				t.Error("Path should not be empty")
			}
		})
	}
}

func TestResolve_SecretACLsDefaultEmpty(t *testing.T) {
	// SecretACLs should be nil by default (no credential policy).
	p := Resolve(nil)
	if p.SecretACLs != nil {
		t.Errorf("SecretACLs = %v, want nil", p.SecretACLs)
	}

	p = Resolve(&config.Capabilities{})
	if p.SecretACLs != nil {
		t.Errorf("SecretACLs = %v, want nil", p.SecretACLs)
	}
}

func TestContainerPolicy_SecretACLs(t *testing.T) {
	p := &ContainerPolicy{
		SecretACLs: []SecretACL{
			{
				Path:         "/run/secrets/API_KEY",
				AllowedTools: []string{"http-client", "api-tool"},
				TTLSeconds:   7200,
			},
			{
				Path:         "/run/secrets/DB_PASSWORD",
				AllowedTools: []string{"db-query"},
				TTLSeconds:   0,
			},
		},
	}

	if len(p.SecretACLs) != 2 {
		t.Fatalf("len(SecretACLs) = %d, want 2", len(p.SecretACLs))
	}

	if p.SecretACLs[0].Path != "/run/secrets/API_KEY" {
		t.Errorf("SecretACLs[0].Path = %q, want %q", p.SecretACLs[0].Path, "/run/secrets/API_KEY")
	}
	if len(p.SecretACLs[0].AllowedTools) != 2 {
		t.Fatalf("len(SecretACLs[0].AllowedTools) = %d, want 2", len(p.SecretACLs[0].AllowedTools))
	}
	if p.SecretACLs[0].AllowedTools[0] != "http-client" {
		t.Errorf("SecretACLs[0].AllowedTools[0] = %q, want %q", p.SecretACLs[0].AllowedTools[0], "http-client")
	}
	if p.SecretACLs[0].TTLSeconds != 7200 {
		t.Errorf("SecretACLs[0].TTLSeconds = %d, want 7200", p.SecretACLs[0].TTLSeconds)
	}

	if p.SecretACLs[1].Path != "/run/secrets/DB_PASSWORD" {
		t.Errorf("SecretACLs[1].Path = %q, want %q", p.SecretACLs[1].Path, "/run/secrets/DB_PASSWORD")
	}
	if p.SecretACLs[1].TTLSeconds != 0 {
		t.Errorf("SecretACLs[1].TTLSeconds = %d, want 0", p.SecretACLs[1].TTLSeconds)
	}
}

func assertStringSlice[T comparable](t *testing.T, field string, got []T, want []T) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s: len = %d, want %d; got %v", field, len(got), len(want), got)
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("%s[%d] = %v, want %v", field, i, got[i], want[i])
		}
	}
}

func assertNilSlice[T any](t *testing.T, field string, got []T) {
	t.Helper()
	if got != nil {
		t.Errorf("%s = %v, want nil", field, got)
	}
}

func TestResolveSecrets(t *testing.T) {
	tests := []struct {
		name    string
		secrets map[string]config.SecretConfig
		tools   *config.ToolsConfig
		want    func(t *testing.T, acls []SecretACL)
	}{
		{
			name:    "nil secrets returns nil",
			secrets: nil,
			tools:   nil,
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if acls != nil {
					t.Errorf("acls = %v, want nil", acls)
				}
			},
		},
		{
			name:    "empty secrets returns nil",
			secrets: map[string]config.SecretConfig{},
			tools:   nil,
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if acls != nil {
					t.Errorf("acls = %v, want nil", acls)
				}
			},
		},
		{
			name: "secret with no path is skipped",
			secrets: map[string]config.SecretConfig{
				"NO_PATH": {Provider: "vault", TTL: "1h"},
			},
			tools: nil,
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if len(acls) != 0 {
					t.Errorf("len(acls) = %d, want 0", len(acls))
				}
			},
		},
		{
			name: "single secret with MCP tool reference",
			secrets: map[string]config.SecretConfig{
				"GITHUB_TOKEN": {
					Provider: "vault",
					Path:     "/run/secrets/GITHUB_TOKEN",
					TTL:      "1h",
				},
			},
			tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"git-tool": {
						Image:   "ghcr.io/kubedoll/mcp-git:latest",
						Secrets: []string{"GITHUB_TOKEN"},
					},
				},
			},
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if len(acls) != 1 {
					t.Fatalf("len(acls) = %d, want 1", len(acls))
				}
				if acls[0].Path != "/run/secrets/GITHUB_TOKEN" {
					t.Errorf("Path = %q, want %q", acls[0].Path, "/run/secrets/GITHUB_TOKEN")
				}
				assertStringSlice(t, "AllowedTools", acls[0].AllowedTools, []string{"git-tool"})
				if acls[0].TTLSeconds != 3600 {
					t.Errorf("TTLSeconds = %d, want 3600", acls[0].TTLSeconds)
				}
			},
		},
		{
			name: "multiple tools referencing same secret are merged",
			secrets: map[string]config.SecretConfig{
				"API_KEY": {
					Provider: "env",
					Path:     "/run/secrets/API_KEY",
					TTL:      "30m",
				},
			},
			tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"http-client": {
						Image:   "ghcr.io/kubedoll/mcp-http:latest",
						Secrets: []string{"API_KEY"},
					},
					"api-tool": {
						Image:   "ghcr.io/kubedoll/mcp-api:latest",
						Secrets: []string{"API_KEY"},
					},
				},
			},
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if len(acls) != 1 {
					t.Fatalf("len(acls) = %d, want 1", len(acls))
				}
				// Sorted alphabetically.
				assertStringSlice(t, "AllowedTools", acls[0].AllowedTools, []string{"api-tool", "http-client"})
				if acls[0].TTLSeconds != 1800 {
					t.Errorf("TTLSeconds = %d, want 1800", acls[0].TTLSeconds)
				}
			},
		},
		{
			name: "AllowedTools from SecretConfig are merged with MCP references",
			secrets: map[string]config.SecretConfig{
				"DB_PASSWORD": {
					Provider:     "vault",
					Path:         "/run/secrets/DB_PASSWORD",
					TTL:          "2h",
					AllowedTools: []string{"admin-tool"},
				},
			},
			tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"db-query": {
						Image:   "ghcr.io/kubedoll/mcp-db:latest",
						Secrets: []string{"DB_PASSWORD"},
					},
				},
			},
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if len(acls) != 1 {
					t.Fatalf("len(acls) = %d, want 1", len(acls))
				}
				assertStringSlice(t, "AllowedTools", acls[0].AllowedTools, []string{"admin-tool", "db-query"})
				if acls[0].TTLSeconds != 7200 {
					t.Errorf("TTLSeconds = %d, want 7200", acls[0].TTLSeconds)
				}
			},
		},
		{
			name: "secret with nil tools config uses AllowedTools from SecretConfig only",
			secrets: map[string]config.SecretConfig{
				"STANDALONE": {
					Provider:     "env",
					Path:         "/run/secrets/STANDALONE",
					AllowedTools: []string{"my-tool"},
				},
			},
			tools: nil,
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if len(acls) != 1 {
					t.Fatalf("len(acls) = %d, want 1", len(acls))
				}
				assertStringSlice(t, "AllowedTools", acls[0].AllowedTools, []string{"my-tool"})
				if acls[0].TTLSeconds != 0 {
					t.Errorf("TTLSeconds = %d, want 0", acls[0].TTLSeconds)
				}
			},
		},
		{
			name: "MCP tool referencing undefined secret is ignored",
			secrets: map[string]config.SecretConfig{
				"DEFINED": {
					Provider: "vault",
					Path:     "/run/secrets/DEFINED",
				},
			},
			tools: &config.ToolsConfig{
				MCP: map[string]config.MCPToolConfig{
					"tool-a": {
						Image:   "img",
						Secrets: []string{"DEFINED", "UNDEFINED"},
					},
				},
			},
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if len(acls) != 1 {
					t.Fatalf("len(acls) = %d, want 1", len(acls))
				}
				assertStringSlice(t, "AllowedTools", acls[0].AllowedTools, []string{"tool-a"})
			},
		},
		{
			name: "invalid TTL is treated as zero",
			secrets: map[string]config.SecretConfig{
				"BAD_TTL": {
					Provider: "vault",
					Path:     "/run/secrets/BAD_TTL",
					TTL:      "not-a-duration",
				},
			},
			tools: nil,
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if len(acls) != 1 {
					t.Fatalf("len(acls) = %d, want 1", len(acls))
				}
				if acls[0].TTLSeconds != 0 {
					t.Errorf("TTLSeconds = %d, want 0", acls[0].TTLSeconds)
				}
			},
		},
		{
			name: "multiple secrets sorted by path",
			secrets: map[string]config.SecretConfig{
				"ZEBRA": {
					Provider: "vault",
					Path:     "/run/secrets/ZEBRA",
					TTL:      "10m",
				},
				"ALPHA": {
					Provider: "vault",
					Path:     "/run/secrets/ALPHA",
					TTL:      "5m",
				},
			},
			tools: nil,
			want: func(t *testing.T, acls []SecretACL) {
				t.Helper()
				if len(acls) != 2 {
					t.Fatalf("len(acls) = %d, want 2", len(acls))
				}
				if acls[0].Path != "/run/secrets/ALPHA" {
					t.Errorf("acls[0].Path = %q, want %q", acls[0].Path, "/run/secrets/ALPHA")
				}
				if acls[0].TTLSeconds != 300 {
					t.Errorf("acls[0].TTLSeconds = %d, want 300", acls[0].TTLSeconds)
				}
				if acls[1].Path != "/run/secrets/ZEBRA" {
					t.Errorf("acls[1].Path = %q, want %q", acls[1].Path, "/run/secrets/ZEBRA")
				}
				if acls[1].TTLSeconds != 600 {
					t.Errorf("acls[1].TTLSeconds = %d, want 600", acls[1].TTLSeconds)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			acls := ResolveSecrets(tt.secrets, tt.tools)
			tt.want(t, acls)
		})
	}
}

func assertMount(t *testing.T, got MountPolicy, wantSource, wantTarget string, wantReadOnly bool) {
	t.Helper()
	if got.Source != wantSource {
		t.Errorf("Mount.Source = %q, want %q", got.Source, wantSource)
	}
	if got.Target != wantTarget {
		t.Errorf("Mount.Target = %q, want %q", got.Target, wantTarget)
	}
	if got.ReadOnly != wantReadOnly {
		t.Errorf("Mount.ReadOnly = %v, want %v", got.ReadOnly, wantReadOnly)
	}
}
