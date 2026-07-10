// Package sidecar provides lifecycle management for the agentcontainer-enforcer sidecar
// container. It handles pulling, starting, health-checking, discovering, and
// stopping the enforcer container that provides BPF-based enforcement via gRPC.
package sidecar

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
)

const (
	// DefaultEnforcerImage is the default OCI image for the agentcontainer-enforcer sidecar.
	DefaultEnforcerImage = "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:latest"

	// DefaultPort is the default gRPC port for the agentcontainer-enforcer sidecar.
	DefaultPort = 50051

	// DefaultHealthTimeout is how long to wait for the enforcer to become healthy.
	DefaultHealthTimeout = 15 * time.Second

	// DefaultHealthInterval is how often to poll health during startup.
	DefaultHealthInterval = 500 * time.Millisecond

	// ContainerName is the well-known container name for the agentcontainer-enforcer sidecar.
	ContainerName = "agentcontainer-enforcer"

	// LabelComponent identifies the container as an enforcer component.
	LabelComponent = "dev.agentcontainer/component"

	// LabelManaged indicates the container was started by agentcontainer (not pre-existing).
	LabelManaged = "dev.agentcontainer/managed"
)

// SidecarHandle represents a running or pre-existing sidecar instance.
type SidecarHandle struct {
	// ContainerID is the Docker container ID. Empty for external sidecars.
	ContainerID string

	// Addr is the gRPC endpoint address (e.g., "127.0.0.1:50051").
	Addr string

	// Managed is true if this sidecar was started by agentcontainer (not pre-existing).
	// Only managed sidecars are stopped during teardown.
	Managed bool

	// SocketPath is the host Unix socket path for UDS sidecars.
	SocketPath string
}

// StartOptions configures sidecar startup behavior.
type StartOptions struct {
	// Image is the OCI reference to pull and run.
	// Default: DefaultEnforcerImage
	Image string

	// Port is the container gRPC listen port (default: 50051).
	// If HostPort is unset, this is also used as the host-published port for
	// compatibility with earlier releases.
	Port int

	// HostPort is the host TCP port to publish. If unset, defaults to Port.
	HostPort int

	// RandomHostPort publishes Port to an ephemeral Docker-assigned host port.
	RandomHostPort bool

	// SocketPath is a host Unix socket path for gRPC. When set, the sidecar
	// bind-mounts its parent directory and does not publish a TCP port.
	SocketPath string

	// HealthTimeout is how long to wait for SERVING (default: 15s).
	HealthTimeout time.Duration

	// HealthInterval is the polling interval (default: 500ms).
	HealthInterval time.Duration

	// Required: if true (default), return an error when health check fails
	// or image cannot be pulled. If false, return (nil, nil) and log a warning.
	Required bool

	// HealthCheckAddr overrides the default health check target address.
	// If empty, defaults to "127.0.0.1:<Port>" (suitable for host-local sidecars).
	// For in-VM sidecars, set this to "<vm_ip>:<port>" so the host can reach
	// the enforcer inside the VM.
	HealthCheckAddr string
}

func (o *StartOptions) applyDefaults() {
	if o.Image == "" {
		o.Image = DefaultEnforcerImage
	}
	if o.Port == 0 {
		o.Port = DefaultPort
	}
	if o.HostPort == 0 && !o.RandomHostPort {
		o.HostPort = o.Port
	}
	if o.HealthTimeout == 0 {
		o.HealthTimeout = DefaultHealthTimeout
	}
	if o.HealthInterval == 0 {
		o.HealthInterval = DefaultHealthInterval
	}
}

// DiscoverOptions configures external sidecar discovery.
type DiscoverOptions struct {
	// ConfigAddr is from agent.enforcer.addr in agentcontainer.json.
	// Empty string means not configured.
	ConfigAddr string
}

// DiscoverResult describes how the sidecar was found.
type DiscoverResult struct {
	// Addr is the gRPC endpoint to use. Empty if no sidecar found.
	Addr string

	// Source is "env", "config", or "" (not found).
	Source string
}

// HealthProber is a function that checks if a gRPC endpoint is healthy.
// This allows injection of a mock for testing.
type HealthProber func(target string) bool

// defaultHealthProber uses the enforcement package's health probe.
var defaultHealthProber HealthProber = enforcement.ProbeEnforcerHealth

// StartSidecar pulls (if necessary) and starts the agentcontainer-enforcer container,
// then polls the gRPC health endpoint until SERVING or timeout.
// Returns a SidecarHandle with Managed: true.
//
// Error behavior:
//   - If Required is true (default): any failure returns a non-nil error.
//   - If Required is false (explicit opt-out): failures return (nil, nil).
func StartSidecar(ctx context.Context, dockerClient client.APIClient, opts StartOptions) (*SidecarHandle, error) {
	opts.applyDefaults()

	// 1. Ensure image is available locally.
	if err := EnsureImage(ctx, dockerClient, opts.Image); err != nil {
		if opts.Required {
			return nil, fmt.Errorf("pulling image %s: %w", opts.Image, err)
		}
		return nil, nil
	}

	// 2. Create the container.
	containerPortStr := fmt.Sprintf("%d", opts.Port)
	hostPortStr := fmt.Sprintf("%d", opts.HostPort)
	if opts.RandomHostPort {
		hostPortStr = ""
	}
	exposedPort := network.MustParsePort(containerPortStr + "/tcp")
	socketPath := opts.SocketPath
	socketDir := ""
	containerSocketPath := ""
	if socketPath != "" {
		var err error
		socketPath, err = filepath.Abs(socketPath)
		if err != nil {
			if opts.Required {
				return nil, fmt.Errorf("resolving socket path: %w", err)
			}
			return nil, nil
		}
		socketDir = filepath.Dir(socketPath)
		if err := os.MkdirAll(socketDir, 0700); err != nil {
			if opts.Required {
				return nil, fmt.Errorf("creating socket directory %s: %w", socketDir, err)
			}
			return nil, nil
		}
		if err := os.Remove(socketPath); err != nil && !os.IsNotExist(err) {
			if opts.Required {
				return nil, fmt.Errorf("removing stale socket %s: %w", socketPath, err)
			}
			return nil, nil
		}
		containerSocketPath = "/run/agentcontainer-enforcer/" + filepath.Base(socketPath)
	}

	containerCfg := &container.Config{
		Image: opts.Image,
		ExposedPorts: network.PortSet{
			exposedPort: {},
		},
		Labels: map[string]string{
			LabelComponent: "enforcer",
			LabelManaged:   "true",
		},
	}
	if socketPath != "" {
		containerCfg.Cmd = []string{
			"--listen", "127.0.0.1:" + containerPortStr,
			"--socket", containerSocketPath,
		}
	}

	hostCfg := &container.HostConfig{
		CapAdd: []string{
			"BPF",
			"NET_ADMIN",
			"SYS_ADMIN",
			"SYS_PTRACE",
			"SYS_RESOURCE",
		},
		PidMode: container.PidMode("host"),
		Mounts: []mount.Mount{
			{
				Type:     mount.TypeBind,
				Source:   "/sys/fs/cgroup",
				Target:   "/sys/fs/cgroup",
				ReadOnly: true,
			},
			{
				Type:   mount.TypeBind,
				Source: "/sys/fs/bpf",
				Target: "/sys/fs/bpf",
			},
		},
		RestartPolicy: container.RestartPolicy{
			Name: container.RestartPolicyUnlessStopped,
		},
	}
	if socketPath == "" {
		hostCfg.PortBindings = network.PortMap{
			exposedPort: {
				{HostPort: hostPortStr},
			},
		}
	} else {
		hostCfg.Mounts = append(hostCfg.Mounts, mount.Mount{
			Type:   mount.TypeBind,
			Source: socketDir,
			Target: "/run/agentcontainer-enforcer",
		})
	}

	resp, err := dockerClient.ContainerCreate(ctx, client.ContainerCreateOptions{
		Config:     containerCfg,
		HostConfig: hostCfg,
		Name:       ContainerName,
	})
	if err != nil {
		// Handle name conflict: a container named "agentcontainer-enforcer" already exists
		// (e.g., from a previous crash or concurrent agentcontainer run). Try to adopt it.
		if isNameConflict(err) {
			addr := fmt.Sprintf("127.0.0.1:%d", opts.Port)
			if socketPath != "" {
				addr = "unix://" + socketPath
			}
			if !opts.RandomHostPort && defaultHealthProber(addr) {
				// Existing container is healthy — adopt it as unmanaged.
				return &SidecarHandle{Addr: addr, Managed: false, SocketPath: socketPath}, nil
			}
			// Existing container is unhealthy — remove it and retry once.
			_ = removeByName(ctx, dockerClient, ContainerName)
			resp, err = dockerClient.ContainerCreate(ctx, client.ContainerCreateOptions{
				Config:     containerCfg,
				HostConfig: hostCfg,
				Name:       ContainerName,
			})
			if err != nil {
				if opts.Required {
					return nil, fmt.Errorf("creating container (retry after conflict): %w", err)
				}
				return nil, nil
			}
			// Fall through to start the freshly created container.
		} else {
			if opts.Required {
				return nil, fmt.Errorf("creating container: %w", err)
			}
			return nil, nil
		}
	}

	// 3. Start the container.
	if _, err := dockerClient.ContainerStart(ctx, resp.ID, client.ContainerStartOptions{}); err != nil {
		// Best-effort cleanup on start failure.
		_, _ = dockerClient.ContainerRemove(ctx, resp.ID, client.ContainerRemoveOptions{Force: true})
		cleanupSocket(socketPath)
		if opts.Required {
			return nil, fmt.Errorf("starting container: %w", err)
		}
		return nil, nil
	}

	// 4. Wait for health check.
	addr := opts.HealthCheckAddr
	if addr == "" {
		if socketPath != "" {
			addr = "unix://" + socketPath
		} else if opts.RandomHostPort {
			publishedPort, err := publishedHostPort(ctx, dockerClient, resp.ID, exposedPort)
			if err != nil {
				cleanupContainer(ctx, dockerClient, resp.ID)
				if opts.Required {
					return nil, fmt.Errorf("resolving random host port: %w", err)
				}
				return nil, nil
			}
			addr = "127.0.0.1:" + publishedPort
		} else {
			addr = fmt.Sprintf("127.0.0.1:%d", opts.HostPort)
		}
	}
	if err := WaitHealthy(ctx, addr, opts.HealthTimeout, opts.HealthInterval); err != nil {
		// Health check failed — clean up the container.
		cleanupContainer(ctx, dockerClient, resp.ID)
		cleanupSocket(socketPath)
		if opts.Required {
			return nil, fmt.Errorf("enforcer failed to reach SERVING: %w", err)
		}
		return nil, nil
	}

	return &SidecarHandle{
		ContainerID: resp.ID,
		Addr:        addr,
		Managed:     true,
		SocketPath:  socketPath,
	}, nil
}

func publishedHostPort(ctx context.Context, dockerClient client.APIClient, containerID string, port network.Port) (string, error) {
	result, err := dockerClient.ContainerInspect(ctx, containerID, client.ContainerInspectOptions{})
	if err != nil {
		return "", fmt.Errorf("inspecting container %s: %w", containerID, err)
	}
	if result.Container.NetworkSettings == nil {
		return "", fmt.Errorf("container %s has no network settings", containerID)
	}
	bindings := result.Container.NetworkSettings.Ports[port]
	for _, binding := range bindings {
		if binding.HostPort != "" {
			return binding.HostPort, nil
		}
	}
	return "", fmt.Errorf("container %s has no host port for %s", containerID, port)
}

// StopSidecar gracefully stops and removes the managed sidecar container.
// If handle.Managed is false (external sidecar), it returns immediately.
func StopSidecar(ctx context.Context, dockerClient client.APIClient, handle *SidecarHandle) error {
	if handle == nil || !handle.Managed {
		return nil
	}

	if _, err := dockerClient.ContainerStop(ctx, handle.ContainerID, client.ContainerStopOptions{}); err != nil {
		// Best-effort: try to force remove even if stop failed.
		_, _ = dockerClient.ContainerRemove(ctx, handle.ContainerID, client.ContainerRemoveOptions{
			Force:         true,
			RemoveVolumes: true,
		})
		return fmt.Errorf("stopping sidecar: %w", err)
	}

	if _, err := dockerClient.ContainerRemove(ctx, handle.ContainerID, client.ContainerRemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	}); err != nil {
		return fmt.Errorf("removing sidecar: %w", err)
	}

	if handle.SocketPath != "" {
		cleanupSocket(handle.SocketPath)
	}

	return nil
}

func cleanupSocket(path string) {
	if path != "" {
		_ = os.Remove(path)
	}
}

// WaitHealthy polls the gRPC health endpoint at target until the service
// reports SERVING or the timeout expires.
func WaitHealthy(ctx context.Context, target string, timeout, interval time.Duration) error {
	return WaitHealthyWithProber(ctx, target, timeout, interval, defaultHealthProber)
}

// WaitHealthyWithProber polls the gRPC health endpoint using the provided
// prober function. This is useful for testing with mock probers.
func WaitHealthyWithProber(ctx context.Context, target string, timeout, interval time.Duration, prober HealthProber) error {
	deadline := time.After(timeout)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline:
			return fmt.Errorf("timed out waiting for agentcontainer-enforcer health on %s", target)
		case <-ticker.C:
			if prober(target) {
				return nil
			}
		}
	}
}

// DiscoverExternalSidecar checks whether a pre-existing sidecar is reachable.
// Priority order: AC_ENFORCER_ADDR env var > config addr.
// Returns a result with empty Addr if no sidecar is found.
func DiscoverExternalSidecar(opts DiscoverOptions) DiscoverResult {
	return DiscoverExternalSidecarWithProber(opts, defaultHealthProber)
}

// DiscoverExternalSidecarWithProber checks for a pre-existing sidecar using
// the provided health prober. This is useful for testing.
func DiscoverExternalSidecarWithProber(opts DiscoverOptions, prober HealthProber) DiscoverResult {
	// 1. Check AC_ENFORCER_ADDR env var.
	if envAddr := os.Getenv("AC_ENFORCER_ADDR"); envAddr != "" {
		if prober(envAddr) {
			return DiscoverResult{Addr: envAddr, Source: "env"}
		}
	}

	// 2. Check config addr.
	if opts.ConfigAddr != "" {
		if prober(opts.ConfigAddr) {
			return DiscoverResult{Addr: opts.ConfigAddr, Source: "config"}
		}
	}

	// 3. Not found.
	return DiscoverResult{}
}

// EnsureImage pulls the image if it is not already present locally.
func EnsureImage(ctx context.Context, dockerClient client.APIClient, ref string) error {
	if _, err := dockerClient.ImageInspect(ctx, ref); err == nil {
		return nil
	}

	reader, err := dockerClient.ImagePull(ctx, ref, client.ImagePullOptions{})
	if err != nil {
		return fmt.Errorf("pulling image %s: %w", ref, err)
	}
	defer reader.Close() //nolint:errcheck

	// Drain the pull output to ensure the pull completes.
	if _, err := io.Copy(io.Discard, reader); err != nil {
		return fmt.Errorf("reading pull response for %s: %w", ref, err)
	}
	return nil
}

// isNameConflict returns true if the error indicates a container name conflict.
func isNameConflict(err error) bool {
	return strings.Contains(err.Error(), "is already in use")
}

// removeByName force-removes a container by name, best-effort.
func removeByName(ctx context.Context, dockerClient client.APIClient, name string) error {
	_, err := dockerClient.ContainerRemove(ctx, name, client.ContainerRemoveOptions{Force: true})
	return err
}

// cleanupContainer stops and removes a container, best-effort.
func cleanupContainer(ctx context.Context, dockerClient client.APIClient, containerID string) {
	_, _ = dockerClient.ContainerStop(ctx, containerID, client.ContainerStopOptions{})
	_, _ = dockerClient.ContainerRemove(ctx, containerID, client.ContainerRemoveOptions{
		Force:         true,
		RemoveVolumes: true,
	})
}
