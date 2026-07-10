package approval

import (
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

// knownInterpreters lists binaries that can execute arbitrary code via
// command-line flags. The BPF process enforcer checks inodes but not argv,
// so this Go-side check provides defense-in-depth (M3 mitigation).
var knownInterpreters = map[string]bool{
	"python":  true,
	"python3": true,
	"node":    true,
	"ruby":    true,
	"perl":    true,
	"bash":    true,
	"sh":      true,
}

// interpreterCodeFlags lists flags that cause interpreters to execute inline
// code from the command line rather than from a file.
var interpreterCodeFlags = map[string]bool{
	"-c": true,
	"-e": true,
}

// Broker wraps a container.Runtime and gates Exec calls through the approval
// manager. Before executing a command, the broker checks whether the shell
// capability covers it. If not, the manager prompts the user for approval.
//
// For M0 this performs basic command-name matching against the shell.commands
// allowlist. Filesystem, network, and AST-level interception are deferred to M3.
type Broker struct {
	runtime container.Runtime
	manager *Manager
}

// Compile-time check that Broker satisfies the Runtime interface.
var _ container.Runtime = (*Broker)(nil)

// NewBroker creates a Broker that wraps the given runtime with capability
// checks from the approval manager. If manager is nil, all calls pass through.
func NewBroker(runtime container.Runtime, manager *Manager) *Broker {
	return &Broker{
		runtime: runtime,
		manager: manager,
	}
}

// Start delegates to the wrapped runtime.
func (b *Broker) Start(ctx context.Context, cfg *config.AgentContainer, opts container.StartOptions) (*container.Session, error) {
	return b.runtime.Start(ctx, cfg, opts)
}

// Stop delegates to the wrapped runtime.
func (b *Broker) Stop(ctx context.Context, session *container.Session) error {
	return b.runtime.Stop(ctx, session)
}

// Exec checks whether the command is allowed by the shell capability set before
// delegating to the wrapped runtime. If the command binary is not in the
// allowlist and the manager denies the request, it returns an error.
func (b *Broker) Exec(ctx context.Context, session *container.Session, cmd []string) (*container.ExecResult, error) {
	if err := b.checkExecAllowed(cmd); err != nil {
		return nil, err
	}

	return b.runtime.Exec(ctx, session, cmd)
}

// ExecInteractive checks approval and then delegates to runtimes that support
// attached stdio.
func (b *Broker) ExecInteractive(ctx context.Context, session *container.Session, cmd []string, execIO container.ExecIO) (int, error) {
	if err := b.checkExecAllowed(cmd); err != nil {
		return 0, err
	}

	rt, ok := b.runtime.(container.InteractiveExecutor)
	if !ok {
		return 0, fmt.Errorf("broker: runtime does not support interactive exec")
	}
	return rt.ExecInteractive(ctx, session, cmd, execIO)
}

func (b *Broker) checkExecAllowed(cmd []string) error {
	if len(cmd) == 0 {
		return fmt.Errorf("broker: empty command rejected")
	}

	if b.manager == nil {
		return nil
	}

	binary := extractBinary(cmd[0])

	// M3 defense-in-depth: block known interpreters with code-execution flags.
	if knownInterpreters[binary] && len(cmd) > 1 && interpreterCodeFlags[cmd[1]] {
		return fmt.Errorf("broker: interpreter %q with %s flag denied (M3 defense-in-depth); use a script file instead", binary, cmd[1])
	}

	// Build the request with the full command so the manager can check
	// subcommands and denied arguments, not just the binary name.
	req := Request{
		Category: "shell",
		Action:   fmt.Sprintf("execute %s", strings.Join(cmd, " ")),
		Details:  fmt.Sprintf("The agent wants to run: %s", strings.Join(cmd, " ")),
		Capability: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: binary}},
		},
		FullCmd: cmd,
	}

	approved, err := b.manager.Check(req)
	if err != nil {
		return fmt.Errorf("broker: checking shell capability: %w", err)
	}
	if !approved {
		return fmt.Errorf("broker: command %q denied by capability policy", binary)
	}

	return nil
}

// Logs delegates to the wrapped runtime.
func (b *Broker) Logs(ctx context.Context, session *container.Session) (io.ReadCloser, error) {
	return b.runtime.Logs(ctx, session)
}

// List delegates to the wrapped runtime.
func (b *Broker) List(ctx context.Context, all bool) ([]*container.Session, error) {
	return b.runtime.List(ctx, all)
}

// EnforcementEvents proxies to the wrapped runtime if it implements
// container.EventStreamer. Returns nil otherwise.
func (b *Broker) EnforcementEvents(containerID string) <-chan enforcement.Event {
	if es, ok := b.runtime.(container.EventStreamer); ok {
		return es.EnforcementEvents(containerID)
	}
	return nil
}

// extractBinary returns the base name of the command binary, stripping any
// path prefix. For example, "/usr/bin/git" becomes "git".
func extractBinary(cmd string) string {
	return filepath.Base(cmd)
}
