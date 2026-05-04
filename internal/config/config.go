// Package config defines the agentcontainer.json schema types and configuration loader.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/tailscale/hujson"
)

// Resolution order for finding configuration files.
var configPaths = []string{
	"agentcontainer.json",
	".devcontainer/agentcontainer.json",
	".devcontainer/devcontainer.json",
}

// AgentContainer represents the agentcontainer.json configuration.
// It is a strict superset of devcontainer.json — any valid devcontainer.json
// is a valid agentcontainer.json with agent capabilities set to default-deny.
type AgentContainer struct {
	// Standard devcontainer fields.
	Name     string         `json:"name,omitempty"`
	Image    string         `json:"image,omitempty"`
	Build    *BuildConfig   `json:"build,omitempty"`
	Features map[string]any `json:"features,omitempty"`
	Mounts   []string       `json:"mounts,omitempty"`

	// Agent-specific extensions.
	Agent *AgentConfig `json:"agent,omitempty"`
}

// BuildConfig holds container build settings.
type BuildConfig struct {
	Dockerfile string            `json:"dockerfile,omitempty"`
	Context    string            `json:"context,omitempty"`
	Args       map[string]string `json:"args,omitempty"`
}

// AgentConfig holds all agent-specific configuration under the "agent" key.
type AgentConfig struct {
	Capabilities *Capabilities           `json:"capabilities,omitempty"`
	Tools        *ToolsConfig            `json:"tools,omitempty"`
	Secrets      map[string]SecretConfig `json:"secrets,omitempty"`
	Policy       *PolicyConfig           `json:"policy,omitempty"`
	Provenance   *ProvenanceConfig       `json:"provenance,omitempty"`
	Enforcer     *EnforcerConfig         `json:"enforcer,omitempty"`
}

// EnforcerConfig controls sidecar discovery and lifecycle behavior.
type EnforcerConfig struct {
	// Image is the OCI reference for the agentcontainer-enforcer container.
	// Default: "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:latest"
	Image string `json:"image,omitempty"`

	// Required causes agentcontainer run to fail if the sidecar cannot start or is
	// unreachable. Default: true (fail-closed). Set to false only for
	// local development where enforcement is explicitly not needed.
	Required *bool `json:"required,omitempty"`

	// Addr is the gRPC address of a pre-existing sidecar. When set,
	// auto-start is skipped entirely. Overridden by AC_ENFORCER_ADDR env var.
	// Example: "127.0.0.1:50051" or "unix:///run/agentcontainer-enforcer.sock"
	Addr string `json:"addr,omitempty"`
}

// Capabilities declares what the agent is allowed to do.
type Capabilities struct {
	Filesystem *FilesystemCaps `json:"filesystem,omitempty"`
	Network    *NetworkCaps    `json:"network,omitempty"`
	Shell      *ShellCaps      `json:"shell,omitempty"`
	Git        *GitCaps        `json:"git,omitempty"`
}

// FilesystemCaps controls file access.
type FilesystemCaps struct {
	Read  []string `json:"read,omitempty"`
	Write []string `json:"write,omitempty"`
	Deny  []string `json:"deny,omitempty"`
}

// NetworkCaps controls network access.
type NetworkCaps struct {
	Egress []EgressRule `json:"egress,omitempty"`
	Deny   []string     `json:"deny,omitempty"`
}

// EgressRule defines an allowed outbound connection.
type EgressRule struct {
	Host     string `json:"host"`
	Port     int    `json:"port,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// ShellCaps controls which shell commands the agent can execute.
type ShellCaps struct {
	Commands []ShellCommand `json:"commands,omitempty"`
}

// ShellCommand defines a permitted binary with optional subcommand and argument restrictions.
//
// Supports a string shorthand for convenience:
//
//	"whoami"         → {"binary": "whoami"}
//	"npm test"       → {"binary": "npm", "subcommands": ["test"]}
//	"npm run build"  → {"binary": "npm", "subcommands": ["run", "build"]}
type ShellCommand struct {
	Binary           string   `json:"binary"`
	Subcommands      []string `json:"subcommands,omitempty"`
	Args             []string `json:"args,omitempty"`
	DenyArgs         []string `json:"denyArgs,omitempty"`
	DenyEnv          []string `json:"denyEnv,omitempty"`
	ScriptValidation string   `json:"scriptValidation,omitempty"`
}

// UnmarshalJSON implements custom unmarshaling so that ShellCommand accepts
// either a JSON string (shorthand) or a full JSON object.
func (sc *ShellCommand) UnmarshalJSON(data []byte) error {
	// Try string first.
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		s = strings.TrimSpace(s)
		if s == "" {
			return fmt.Errorf("shell command string must not be empty")
		}
		parts := strings.Fields(s)
		sc.Binary = parts[0]
		if len(parts) > 1 {
			sc.Subcommands = parts[1:]
		}
		return nil
	}

	// Fall back to object form. Use an alias to avoid infinite recursion.
	type shellCommandAlias ShellCommand
	var alias shellCommandAlias
	if err := json.Unmarshal(data, &alias); err != nil {
		return err
	}
	*sc = ShellCommand(alias)
	return nil
}

// GitCaps controls git operations.
type GitCaps struct {
	Operations []string    `json:"operations,omitempty"`
	Branches   *BranchCaps `json:"branches,omitempty"`
}

// BranchCaps controls which branches the agent can push to.
type BranchCaps struct {
	Push []string `json:"push,omitempty"`
	Deny []string `json:"deny,omitempty"`
}

// ToolsConfig declares MCP servers and skills available to the agent.
type ToolsConfig struct {
	MCP    map[string]MCPToolConfig `json:"mcp,omitempty"`
	Skills map[string]SkillConfig   `json:"skills,omitempty"`
}

// MCPToolConfig declares an MCP server tool.
type MCPToolConfig struct {
	// Type is the tool hosting model: "container" (default) or "component" (WASM Component).
	// When empty, "container" is assumed.
	Type string `json:"type,omitempty"`

	// Image is the OCI reference. For "container" type, this is a Docker image.
	// For "component" type, this is a WASM Component OCI artifact.
	Image        string   `json:"image"`
	Capabilities []string `json:"capabilities,omitempty"`
	Secrets      []string `json:"secrets,omitempty"`
	// Mounts is only valid for container-type tools. It is rejected on component-type tools.
	Mounts []string `json:"mounts,omitempty"`

	// Limits applies resource constraints to WASM Components.
	// Only valid when Type is "component"; rejected for container-type tools.
	Limits *ComponentLimits `json:"limits,omitempty"`
}

// ComponentLimits constrains WASM Component resource usage per tool invocation.
type ComponentLimits struct {
	// MemoryMB is the maximum linear memory the component may allocate, in mebibytes.
	// Zero means no limit.
	MemoryMB int `json:"memory_mb,omitempty"`
	// TimeoutMs is the wall-clock timeout per tool call, in milliseconds.
	// Zero means no limit.
	TimeoutMs int `json:"timeout_ms,omitempty"`
	// Fuel is the Wasmtime instruction budget per tool call (fuel units).
	// Zero means unlimited.
	Fuel int `json:"fuel,omitempty"`
}

// SkillConfig declares an agent skill.
type SkillConfig struct {
	Artifact string   `json:"artifact"`
	Trust    string   `json:"trust,omitempty"`
	Requires []string `json:"requires,omitempty"`
}

// SecretConfig declares how a secret is obtained.
type SecretConfig struct {
	Provider     string   `json:"provider"`
	Audience     string   `json:"audience,omitempty"`
	TTL          string   `json:"ttl,omitempty"`
	Rotation     string   `json:"rotation,omitempty"`
	Role         string   `json:"role,omitempty"`
	Path         string   `json:"path,omitempty"`
	Key          string   `json:"key,omitempty"`
	Mount        string   `json:"mount,omitempty"`
	AllowedTools []string `json:"allowedTools,omitempty"`
}

// PolicyConfig controls runtime behavior and escalation handling.
type PolicyConfig struct {
	Escalation            string `json:"escalation,omitempty"`
	AuditLog              bool   `json:"auditLog,omitempty"`
	SessionTimeout        string `json:"sessionTimeout,omitempty"`
	MaxConcurrentTools    int    `json:"maxConcurrentTools,omitempty"`
	OnCapabilityViolation string `json:"onCapabilityViolation,omitempty"`
}

// ProvenanceConfig declares supply chain verification requirements.
type ProvenanceConfig struct {
	Require *ProvenanceRequirements `json:"require,omitempty"`
	Policy  *PolicyChannelConfig    `json:"policy,omitempty"`
}

// PolicyChannelConfig points at the org-controlled mutable OCI policy channel.
type PolicyChannelConfig struct {
	Ref string `json:"ref"`
}

// ProvenanceRequirements specifies what must be verified before a session starts.
type ProvenanceRequirements struct {
	Signatures        bool     `json:"signatures,omitempty"`
	SBOM              bool     `json:"sbom,omitempty"`
	SLSALevel         int      `json:"slsaLevel,omitempty"`
	TrustedBuilders   []string `json:"trustedBuilders,omitempty"`
	TrustedRegistries []string `json:"trustedRegistries,omitempty"`
}

// Load finds and parses the agentcontainer configuration from the given
// working directory. It follows the resolution order:
//  1. agentcontainer.json in workspace root
//  2. .devcontainer/agentcontainer.json
//  3. .devcontainer/devcontainer.json (with default-deny agent caps)
func Load(workdir string) (*AgentContainer, string, error) {
	for _, rel := range configPaths {
		path := filepath.Join(workdir, rel)
		if _, err := os.Stat(path); err == nil {
			cfg, err := parseFile(path)
			if err != nil {
				return nil, path, fmt.Errorf("parsing %s: %w", rel, err)
			}
			return cfg, path, nil
		}
	}
	return nil, "", errors.New("no agentcontainer.json or devcontainer.json found")
}

// ParseFile parses the agentcontainer.json (or devcontainer.json) at the given
// path, handling JSONC comments and trailing commas. This is the exported
// variant used when a caller has a specific config file path (e.g. via --config).
func ParseFile(path string) (*AgentContainer, error) {
	return parseFile(path)
}

func parseFile(path string) (*AgentContainer, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading file: %w", err)
	}

	// Standardize JSONC to plain JSON by stripping comments and trailing commas.
	// This works for both .json and .jsonc files — valid JSON passes through unchanged.
	standardized, err := hujson.Standardize(data)
	if err != nil {
		return nil, fmt.Errorf("standardizing JSONC: %w", err)
	}

	var cfg AgentContainer
	if err := json.Unmarshal(standardized, &cfg); err != nil {
		return nil, fmt.Errorf("unmarshaling config: %w", err)
	}

	return &cfg, nil
}

// Validate checks the AgentContainer configuration for structural correctness.
// It collects all validation errors and returns them joined via errors.Join.
func (c *AgentContainer) Validate() error {
	var errs []error

	// Image or Build must be specified, but not both.
	hasImage := c.Image != ""
	hasBuild := c.Build != nil
	if !hasImage && !hasBuild {
		errs = append(errs, errors.New("either image or build must be specified"))
	}
	if hasImage && hasBuild {
		errs = append(errs, errors.New("image and build are mutually exclusive"))
	}

	// Reject unimplemented config sections to prevent misconfiguration.
	// Users must not assume security features are enforced when they are not.
	if c.Agent != nil {
		if c.Agent.Policy != nil {
			p := c.Agent.Policy
			switch p.Escalation {
			case "", "prompt", "deny", "allow":
				// Valid values.
			default:
				errs = append(errs, fmt.Errorf("agent.policy.escalation: invalid value %q (must be prompt, deny, or allow)", p.Escalation))
			}
			if p.SessionTimeout != "" {
				if _, err := time.ParseDuration(p.SessionTimeout); err != nil {
					errs = append(errs, fmt.Errorf("agent.policy.sessionTimeout: invalid duration %q: %w", p.SessionTimeout, err))
				}
			}
			if p.MaxConcurrentTools < 0 {
				errs = append(errs, fmt.Errorf("agent.policy.maxConcurrentTools: must be >= 0, got %d", p.MaxConcurrentTools))
			}
		}
		if c.Agent.Provenance != nil {
			if c.Agent.Provenance.Require != nil {
				req := c.Agent.Provenance.Require
				if req.SLSALevel < 0 || req.SLSALevel > 4 {
					errs = append(errs, fmt.Errorf("agent.provenance.require.slsaLevel: must be 0-4, got %d", req.SLSALevel))
				}
			}
			if c.Agent.Provenance.Policy != nil {
				if strings.TrimSpace(c.Agent.Provenance.Policy.Ref) == "" {
					errs = append(errs, errors.New("agent.provenance.policy.ref: must not be empty"))
				}
			}
		}
		// Note: c.Agent.Enforcer is validated at runtime — OCI image parse
		// validation is deferred to pull time, and Addr reachability is
		// checked when the sidecar is resolved.
	}

	// Validate agent capabilities if present.
	if c.Agent != nil && c.Agent.Capabilities != nil {
		caps := c.Agent.Capabilities

		// Validate shell commands: each must have a non-empty binary.
		if caps.Shell != nil {
			for i, cmd := range caps.Shell.Commands {
				if cmd.Binary == "" {
					errs = append(errs, fmt.Errorf("agent.capabilities.shell.commands[%d]: binary must not be empty", i))
				}
				if cmd.ScriptValidation != "" {
					errs = append(errs, fmt.Errorf("agent.capabilities.shell.commands[%d].scriptValidation is not yet implemented", i))
				}
				if len(cmd.DenyEnv) > 0 {
					errs = append(errs, fmt.Errorf("agent.capabilities.shell.commands[%d].denyEnv is not yet implemented", i))
				}
			}
		}

		// Validate network egress: each rule must have a non-empty host.
		if caps.Network != nil {
			for i, rule := range caps.Network.Egress {
				if rule.Host == "" {
					errs = append(errs, fmt.Errorf("agent.capabilities.network.egress[%d]: host must not be empty", i))
				}
			}
		}
	}

	// Validate secrets: Rotation must be a valid duration string if set.
	if c.Agent != nil {
		for name, sc := range c.Agent.Secrets {
			if sc.Rotation != "" {
				if _, err := time.ParseDuration(sc.Rotation); err != nil {
					errs = append(errs, fmt.Errorf("agent.secrets[%q].rotation: invalid duration %q: %w", name, sc.Rotation, err))
				}
			}
		}
	}

	// Validate MCP tool entries.
	if c.Agent != nil && c.Agent.Tools != nil {
		for name, tool := range c.Agent.Tools.MCP {
			if tool.Image == "" {
				errs = append(errs, fmt.Errorf("agent.tools.mcp[%q].image: image must not be empty", name))
			}
			switch tool.Type {
			case "", "container", "component":
				// Valid values.
			default:
				errs = append(errs, fmt.Errorf("agent.tools.mcp[%q].type: invalid value %q (must be \"container\" or \"component\")", name, tool.Type))
			}
			isComponent := tool.Type == "component"
			if isComponent && len(tool.Mounts) > 0 {
				errs = append(errs, fmt.Errorf("agent.tools.mcp[%q].mounts: mounts are not valid for component-type tools", name))
			}
			if !isComponent && tool.Limits != nil {
				errs = append(errs, fmt.Errorf("agent.tools.mcp[%q].limits: limits are only valid for component-type tools", name))
			}
			if tool.Limits != nil {
				if tool.Limits.MemoryMB < 0 {
					errs = append(errs, fmt.Errorf("agent.tools.mcp[%q].limits.memory_mb: must be >= 0", name))
				}
				if tool.Limits.TimeoutMs < 0 {
					errs = append(errs, fmt.Errorf("agent.tools.mcp[%q].limits.timeout_ms: must be >= 0", name))
				}
				if tool.Limits.Fuel < 0 {
					errs = append(errs, fmt.Errorf("agent.tools.mcp[%q].limits.fuel: must be >= 0", name))
				}
			}
		}
	}

	return errors.Join(errs...)
}
