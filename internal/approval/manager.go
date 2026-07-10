package approval

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
)

// Manager tracks approved capabilities for a session and handles persistence.
// It checks whether capabilities are already approved and prompts for approval
// when needed, accumulating session approvals and persisting permanent ones.
type Manager struct {
	approver   Approver
	configPath string
	baseline   *config.Capabilities // from config file
	session    *config.Capabilities // accumulated session approvals
	mu         sync.Mutex
	escalation string // "prompt" (default), "deny", or "allow"
}

// ManagerOption configures the approval manager.
type ManagerOption func(*Manager)

// WithEscalation sets the escalation policy.
func WithEscalation(mode string) ManagerOption {
	return func(m *Manager) {
		m.escalation = mode
	}
}

// NewManager creates a new approval manager.
//
// Parameters:
//   - approver: The approver implementation to use for prompting (e.g., TerminalApprover).
//   - configPath: Path to the agentcontainer.json file for persisting approvals.
//   - baseline: The current capabilities from the config file. May be nil for default-deny.
func NewManager(approver Approver, configPath string, baseline *config.Capabilities, opts ...ManagerOption) *Manager {
	// Initialize baseline and session to non-nil empty structs to simplify checks.
	if baseline == nil {
		baseline = &config.Capabilities{}
	}

	m := &Manager{
		approver:   approver,
		configPath: configPath,
		baseline:   baseline,
		session:    &config.Capabilities{},
		escalation: "prompt",
	}
	for _, opt := range opts {
		opt(m)
	}
	return m
}

// Check returns true if the capability described by req is already approved
// (in baseline or session). If not approved, it prompts the user and updates
// the session or persists the approval based on the response.
//
// Returns:
//   - true if the capability is approved (was already approved or user approved it)
//   - false if the capability is denied
//   - error if the prompt fails
func (m *Manager) Check(req Request) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	// Check if already approved in baseline.
	if m.isApprovedInBaseline(req) {
		return true, nil
	}

	// Check if already approved in session.
	if m.isApprovedInSession(req) {
		return true, nil
	}

	// Apply escalation policy only to requests outside the declared baseline
	// and current session. "deny" means no new privilege escalation, not
	// default-deny for explicitly configured capabilities.
	switch m.escalation {
	case "deny":
		return false, nil
	case "allow":
		return true, nil
	}
	// "prompt" or empty: fall through to interactive approval.

	// Prompt user for approval.
	resp, err := m.approver.Prompt(req)
	if err != nil {
		return false, fmt.Errorf("approval prompt: %w", err)
	}

	switch resp {
	case Deny:
		return false, nil

	case AllowOnce:
		// No tracking needed; just return approved for this call.
		return true, nil

	case AllowSession:
		m.addToSession(req)
		return true, nil

	case AllowPersist:
		m.addToSession(req)
		// Persist to config file.
		if err := m.persistCapability(req); err != nil {
			return true, fmt.Errorf("persisting capability: %w", err)
		}
		return true, nil

	default:
		return false, nil
	}
}

// SessionCapabilities returns the combined baseline + session capabilities.
// This represents all capabilities that are currently approved for this session.
func (m *Manager) SessionCapabilities() *config.Capabilities {
	m.mu.Lock()
	defer m.mu.Unlock()

	return m.mergeCapabilities(m.baseline, m.session)
}

// Persist saves any pending approvals to the config file.
// This is typically called when the session ends.
func (m *Manager) Persist() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	merged := m.mergeCapabilities(m.baseline, m.session)
	return config.SaveCapabilities(m.configPath, merged)
}

// isApprovedInBaseline checks if the capability is covered by baseline config.
// This is a simplified check that looks at the category. A full implementation
// would do detailed matching against patterns, hosts, commands, etc.
func (m *Manager) isApprovedInBaseline(req Request) bool {
	return m.capabilityExistsIn(req, m.baseline)
}

// isApprovedInSession checks if the capability was approved during this session.
func (m *Manager) isApprovedInSession(req Request) bool {
	return m.capabilityExistsIn(req, m.session)
}

// capabilityExistsIn checks if a capability exists in the given capability set.
// For shell capabilities, it matches the specific binary name. For filesystem
// capabilities, it matches requested paths against allowed read/write globs
// with deny-list precedence. For network capabilities, it matches requested
// hosts and ports against allowed egress rules with deny-list precedence.
func (m *Manager) capabilityExistsIn(req Request, caps *config.Capabilities) bool {
	if caps == nil {
		return false
	}

	switch req.Category {
	case "filesystem":
		return m.filesystemPathApproved(req, caps)
	case "network":
		return m.networkHostApproved(req, caps)
	case "shell":
		return m.shellBinaryApproved(req, caps)
	case "git":
		return caps.Git != nil && caps.Git.Branches != nil && len(caps.Git.Branches.Push) > 0
	default:
		return false
	}
}

// shellBinaryApproved checks if the specific binary in the request is in the
// approved commands list. This prevents a baseline of ["git"] from implicitly
// approving ["rm"]. It also enforces subcommand restrictions and denied
// arguments when configured on the matching ShellCommand.
func (m *Manager) shellBinaryApproved(req Request, caps *config.Capabilities) bool {
	if caps.Shell == nil || len(caps.Shell.Commands) == 0 {
		return false
	}

	reqCaps, ok := req.Capability.(*config.ShellCaps)
	if !ok || reqCaps == nil || len(reqCaps.Commands) == 0 {
		return false
	}

	requestedBinary := reqCaps.Commands[0].Binary

	for _, cmd := range caps.Shell.Commands {
		if cmd.Binary != requestedBinary {
			continue
		}

		// Binary matches. If the command has subcommand or deny-arg
		// restrictions, enforce them against the full command line.
		if !m.shellArgsAllowed(cmd, req.FullCmd) {
			return false
		}
		return true
	}
	return false
}

// shellArgsAllowed checks that the full command satisfies the subcommand
// whitelist and denied-argument blacklist on a ShellCommand. If neither
// restriction is set, the command is allowed. The FullCmd slice is
// [binary, arg0, arg1, ...]. If fullCmd is nil or has only the binary
// (no arguments), subcommand restrictions cause denial while deny-arg
// checks pass vacuously.
func (m *Manager) shellArgsAllowed(cmd config.ShellCommand, fullCmd []string) bool {
	// No restrictions configured; allow.
	if len(cmd.Subcommands) == 0 && len(cmd.DenyArgs) == 0 {
		return true
	}

	var args []string
	if len(fullCmd) > 1 {
		args = fullCmd[1:]
	}

	// Enforce subcommand restriction: if Subcommands is non-empty, the
	// first argument must be one of the allowed subcommands.
	if len(cmd.Subcommands) > 0 {
		if len(args) == 0 {
			return false
		}
		found := false
		for _, sub := range cmd.Subcommands {
			if args[0] == sub {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	// Enforce denied arguments: if any argument matches a deny pattern,
	// reject the command.
	if len(cmd.DenyArgs) > 0 {
		denied := make(map[string]bool, len(cmd.DenyArgs))
		for _, d := range cmd.DenyArgs {
			denied[d] = true
		}
		for _, arg := range args {
			if denied[arg] {
				return false
			}
		}
	}

	return true
}

// filesystemPathApproved checks if all requested paths are covered by the
// approved filesystem paths. Deny paths take precedence over allow paths.
// Read requests are checked against both Read and Write lists (write implies
// read). Write requests are only checked against the Write list.
func (m *Manager) filesystemPathApproved(req Request, caps *config.Capabilities) bool {
	if caps.Filesystem == nil {
		return false
	}

	reqCaps, ok := req.Capability.(*config.FilesystemCaps)
	if !ok || reqCaps == nil {
		return false
	}

	// Check each requested read path.
	for _, reqPath := range reqCaps.Read {
		if pathDenied(reqPath, caps.Filesystem.Deny) {
			return false
		}
		// Read access is covered by either Read or Write allowlists.
		if !pathAllowed(reqPath, caps.Filesystem.Read) && !pathAllowed(reqPath, caps.Filesystem.Write) {
			return false
		}
	}

	// Check each requested write path.
	for _, reqPath := range reqCaps.Write {
		if pathDenied(reqPath, caps.Filesystem.Deny) {
			return false
		}
		if !pathAllowed(reqPath, caps.Filesystem.Write) {
			return false
		}
	}

	// At least one path must have been requested to count as a match.
	return len(reqCaps.Read) > 0 || len(reqCaps.Write) > 0
}

// pathDenied returns true if the requested path matches any pattern in the
// deny list. Uses glob matching and prefix matching.
func pathDenied(reqPath string, denyPatterns []string) bool {
	for _, pattern := range denyPatterns {
		if pathMatches(reqPath, pattern) {
			return true
		}
	}
	return false
}

// pathAllowed returns true if the requested path matches any pattern in the
// allow list. Uses glob matching and prefix matching.
func pathAllowed(reqPath string, allowPatterns []string) bool {
	for _, pattern := range allowPatterns {
		if pathMatches(reqPath, pattern) {
			return true
		}
	}
	return false
}

// pathMatches returns true if reqPath is covered by the given pattern.
// It checks:
//  1. Exact filepath.Match glob matching (e.g., /home/* matches /home/user)
//  2. Prefix matching for directory patterns (e.g., /home/user covers /home/user/file)
//  3. Double-star suffix: /workspace/** matches anything under /workspace/
//
// Both reqPath and pattern are cleaned via filepath.Clean before comparison
// to prevent path traversal attacks (e.g., "../../etc/passwd").
func pathMatches(reqPath, pattern string) bool {
	// Normalize both paths to prevent traversal attacks.
	cleanReq := filepath.Clean(reqPath)
	cleanPattern := filepath.Clean(pattern)

	// Handle double-star glob: /workspace/** matches everything under /workspace/.
	if strings.HasSuffix(pattern, "/**") {
		raw := strings.TrimSuffix(pattern, "/**")
		if raw == "" {
			raw = "/"
		}
		prefix := filepath.Clean(raw)
		// Special case: /** (root) matches everything with an absolute path.
		if prefix == "/" {
			if strings.HasPrefix(cleanReq, "/") {
				return true
			}
		} else if cleanReq == prefix || strings.HasPrefix(cleanReq, prefix+"/") {
			return true
		}
	}

	// Try standard glob match (handles single * wildcards).
	// Use cleaned pattern for non-glob portion but preserve the glob character.
	if matched, err := filepath.Match(cleanPattern, cleanReq); err == nil && matched {
		return true
	}

	// Prefix match: a directory pattern covers everything beneath it.
	// e.g., pattern "/home/user" covers "/home/user/project/file.go".
	if cleanReq == cleanPattern || strings.HasPrefix(cleanReq, cleanPattern+"/") {
		return true
	}

	return false
}

// networkHostApproved checks if all requested egress rules are covered by
// the approved egress rules. Deny hosts take precedence.
func (m *Manager) networkHostApproved(req Request, caps *config.Capabilities) bool {
	if caps.Network == nil {
		return false
	}

	reqCaps, ok := req.Capability.(*config.NetworkCaps)
	if !ok || reqCaps == nil || len(reqCaps.Egress) == 0 {
		return false
	}

	for _, reqRule := range reqCaps.Egress {
		// Check deny list first.
		if hostDenied(reqRule.Host, caps.Network.Deny) {
			return false
		}

		if !egressRuleAllowed(reqRule, caps.Network.Egress) {
			return false
		}
	}

	return true
}

// hostDenied returns true if the host matches any pattern in the deny list.
func hostDenied(host string, denyPatterns []string) bool {
	for _, pattern := range denyPatterns {
		if hostMatches(host, pattern) {
			return true
		}
	}
	return false
}

// egressRuleAllowed returns true if the requested egress rule matches any
// approved egress rule. Port 0 in the baseline means any port is allowed.
func egressRuleAllowed(reqRule config.EgressRule, approvedRules []config.EgressRule) bool {
	for _, approved := range approvedRules {
		if !hostMatches(reqRule.Host, approved.Host) {
			continue
		}
		// If the approved rule has no port restriction (0), any port is allowed.
		// Otherwise, the requested port must match exactly.
		if approved.Port == 0 || approved.Port == reqRule.Port {
			return true
		}
	}
	return false
}

// hostMatches returns true if the host matches the pattern. Supports:
//   - Exact match (case-insensitive): "api.github.com" matches "api.github.com"
//   - Wildcard prefix: "*.github.com" matches "api.github.com" and "raw.github.com"
//   - Bare wildcard: "*" matches everything
func hostMatches(host, pattern string) bool {
	host = strings.ToLower(host)
	pattern = strings.ToLower(pattern)

	if pattern == "*" {
		return true
	}

	if host == pattern {
		return true
	}

	// Wildcard prefix: *.example.com matches sub.example.com
	if strings.HasPrefix(pattern, "*.") {
		suffix := pattern[1:] // e.g., ".example.com"
		if strings.HasSuffix(host, suffix) {
			return true
		}
	}

	return false
}

// addToSession adds the requested capability to the session approvals.
func (m *Manager) addToSession(req Request) {
	// Type-assert the capability and add to the appropriate section.
	switch req.Category {
	case "filesystem":
		if caps, ok := req.Capability.(*config.FilesystemCaps); ok && caps != nil {
			if m.session.Filesystem == nil {
				m.session.Filesystem = &config.FilesystemCaps{}
			}
			m.session.Filesystem.Read = append(m.session.Filesystem.Read, caps.Read...)
			m.session.Filesystem.Write = append(m.session.Filesystem.Write, caps.Write...)
		}

	case "network":
		if caps, ok := req.Capability.(*config.NetworkCaps); ok && caps != nil {
			if m.session.Network == nil {
				m.session.Network = &config.NetworkCaps{}
			}
			m.session.Network.Egress = append(m.session.Network.Egress, caps.Egress...)
		}

	case "shell":
		if caps, ok := req.Capability.(*config.ShellCaps); ok && caps != nil {
			if m.session.Shell == nil {
				m.session.Shell = &config.ShellCaps{}
			}
			m.session.Shell.Commands = append(m.session.Shell.Commands, caps.Commands...)
		}

	case "git":
		if caps, ok := req.Capability.(*config.GitCaps); ok && caps != nil {
			if m.session.Git == nil {
				m.session.Git = &config.GitCaps{}
			}
			if caps.Branches != nil {
				if m.session.Git.Branches == nil {
					m.session.Git.Branches = &config.BranchCaps{}
				}
				m.session.Git.Branches.Push = append(m.session.Git.Branches.Push, caps.Branches.Push...)
			}
		}
	}
}

// persistCapability saves a single capability to the config file immediately.
func (m *Manager) persistCapability(req Request) error {
	merged := m.mergeCapabilities(m.baseline, m.session)
	return config.SaveCapabilities(m.configPath, merged)
}

// mergeCapabilities combines two capability sets, with additions appended.
func (m *Manager) mergeCapabilities(base, additions *config.Capabilities) *config.Capabilities {
	result := &config.Capabilities{}

	// Merge filesystem capabilities.
	if base.Filesystem != nil || additions.Filesystem != nil {
		result.Filesystem = &config.FilesystemCaps{}
		if base.Filesystem != nil {
			result.Filesystem.Read = append(result.Filesystem.Read, base.Filesystem.Read...)
			result.Filesystem.Write = append(result.Filesystem.Write, base.Filesystem.Write...)
			result.Filesystem.Deny = append(result.Filesystem.Deny, base.Filesystem.Deny...)
		}
		if additions.Filesystem != nil {
			result.Filesystem.Read = append(result.Filesystem.Read, additions.Filesystem.Read...)
			result.Filesystem.Write = append(result.Filesystem.Write, additions.Filesystem.Write...)
			result.Filesystem.Deny = append(result.Filesystem.Deny, additions.Filesystem.Deny...)
		}
	}

	// Merge network capabilities.
	if base.Network != nil || additions.Network != nil {
		result.Network = &config.NetworkCaps{}
		if base.Network != nil {
			result.Network.Egress = append(result.Network.Egress, base.Network.Egress...)
			result.Network.Deny = append(result.Network.Deny, base.Network.Deny...)
		}
		if additions.Network != nil {
			result.Network.Egress = append(result.Network.Egress, additions.Network.Egress...)
			result.Network.Deny = append(result.Network.Deny, additions.Network.Deny...)
		}
	}

	// Merge shell capabilities.
	if base.Shell != nil || additions.Shell != nil {
		result.Shell = &config.ShellCaps{}
		if base.Shell != nil {
			result.Shell.Commands = append(result.Shell.Commands, base.Shell.Commands...)
		}
		if additions.Shell != nil {
			result.Shell.Commands = append(result.Shell.Commands, additions.Shell.Commands...)
		}
	}

	// Merge git capabilities.
	if base.Git != nil || additions.Git != nil {
		result.Git = &config.GitCaps{}
		baseBranches := base.Git != nil && base.Git.Branches != nil
		addBranches := additions.Git != nil && additions.Git.Branches != nil
		if baseBranches || addBranches {
			result.Git.Branches = &config.BranchCaps{}
			if baseBranches {
				result.Git.Branches.Push = append(result.Git.Branches.Push, base.Git.Branches.Push...)
				result.Git.Branches.Deny = append(result.Git.Branches.Deny, base.Git.Branches.Deny...)
			}
			if addBranches {
				result.Git.Branches.Push = append(result.Git.Branches.Push, additions.Git.Branches.Push...)
				result.Git.Branches.Deny = append(result.Git.Branches.Deny, additions.Git.Branches.Deny...)
			}
		}
	}

	return result
}
