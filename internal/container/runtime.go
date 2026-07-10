// Package container defines the Runtime interface for managing agent container
// lifecycles across multiple backends (Docker, Compose, Sandbox).
package container

import (
	"context"
	"io"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// RuntimeType identifies which container backend is in use.
type RuntimeType string

const (
	// RuntimeDocker is the single-container Docker Engine backend (M0 baseline).
	RuntimeDocker RuntimeType = "docker"

	// RuntimeCompose is the multi-container Docker Compose backend for MCP
	// server sidecars and complex service topologies.
	RuntimeCompose RuntimeType = "compose"

	// RuntimeSandbox is the Docker Sandbox microVM backend for full agent
	// isolation with a private Docker daemon.
	RuntimeSandbox RuntimeType = "sandbox"
)

// Runtime is the core abstraction for managing agent container lifecycles.
// Every backend (Docker, Compose, Sandbox) implements this interface, allowing
// the CLI and orchestration layers to remain backend-agnostic.
type Runtime interface {
	// Start creates and starts a container (or set of containers) from the
	// given agent configuration. It returns a Session handle for subsequent
	// operations.
	Start(ctx context.Context, cfg *config.AgentContainer, opts StartOptions) (*Session, error)

	// Stop gracefully stops the container(s) associated with the session and
	// removes them. The implementation should honour a graceful shutdown period
	// before force-killing.
	Stop(ctx context.Context, session *Session) error

	// Exec runs a command inside the primary container of the session and
	// returns the result once the command completes.
	Exec(ctx context.Context, session *Session, cmd []string) (*ExecResult, error)

	// Logs returns a stream of container logs. The caller is responsible for
	// closing the returned ReadCloser.
	Logs(ctx context.Context, session *Session) (io.ReadCloser, error)

	// List returns all sessions managed by agentcontainers. When all is true,
	// stopped sessions are included.
	//
	// IMPORTANT: Implementations MUST filter to only agentcontainer-managed
	// containers. For Docker, this means filtering by the dev.agentcontainer/managed=true
	// label. Other runtimes must use equivalent mechanisms to prevent gc from
	// accidentally removing unrelated containers.
	List(ctx context.Context, all bool) ([]*Session, error)
}

// Session represents a running container session. It is returned by
// Runtime.Start and passed to all subsequent operations.
type Session struct {
	// ContainerID is the primary container identifier (Docker container ID,
	// Compose project name, or Sandbox ID depending on backend).
	ContainerID string

	// Name is the human-readable name of the session.
	Name string

	// Image is the container image reference.
	Image string

	// RuntimeType identifies which backend created this session.
	RuntimeType RuntimeType

	// Status is the current session status (e.g. "running", "stopped").
	Status string

	// CreatedAt is the time the session was created.
	CreatedAt time.Time

	// EnforcerAddr is the gRPC address of the enforcement sidecar, if any.
	// For Sandbox VMs, this is derived from the VM's IP address.
	EnforcerAddr string
}

// StartOptions configures how a container session is started.
type StartOptions struct {
	// Detach, when true, starts the container in the background without
	// attaching stdin/stdout.
	Detach bool

	// Timeout is the maximum duration for the session. A zero value means
	// no timeout (or the backend's default).
	Timeout time.Duration

	// WorkspacePath is the host path to the project workspace that will be
	// bind-mounted into the container.
	WorkspacePath string

	// Policy is the resolved container security policy derived from agent
	// capability declarations. If nil, the runtime applies default-deny
	// security settings.
	Policy *policy.ContainerPolicy

	// ResolvedSecrets carries resolved secret values. The enforcement strategy
	// (InjectSecrets) writes them into the container via the enforcer sidecar
	// after Apply. Sandbox also uses this to build CredentialSources and
	// ServiceAuthConfig on the VMCreateRequest. Keyed by secret name.
	ResolvedSecrets map[string]*secrets.Secret

	// PinnedImageRef is a content-addressed reference (image:tag@sha256:...)
	// derived from the lockfile. When set, the runtime MUST use this reference
	// for the image pull instead of cfg.Image, preventing TOCTOU tag-swap
	// attacks (F-4 dual-resolution): both policy extraction and Docker pull
	// must reference the same immutable manifest.
	PinnedImageRef string
}

// EventStreamer is an optional interface that runtimes can implement to
// expose enforcement event channels. Callers should type-assert the runtime
// to check for support:
//
//	if es, ok := rt.(EventStreamer); ok {
//	    ch := es.EnforcementEvents(containerID)
//	}
type EventStreamer interface {
	EnforcementEvents(containerID string) <-chan enforcement.Event
}

// ExecIO configures an attached exec session.
type ExecIO struct {
	Stdin  io.Reader
	Stdout io.Writer
	Stderr io.Writer
	TTY    bool
}

// InteractiveExecutor is implemented by runtimes that can attach local stdio
// to an exec session. It is optional so non-interactive runtimes can still
// satisfy Runtime.
type InteractiveExecutor interface {
	ExecInteractive(ctx context.Context, session *Session, cmd []string, io ExecIO) (int, error)
}

// ExecResult holds the output of an executed command.
type ExecResult struct {
	// ExitCode is the process exit code. Zero indicates success.
	ExitCode int

	// Stdout contains the standard output of the command.
	Stdout []byte

	// Stderr contains the standard error output of the command.
	Stderr []byte
}
