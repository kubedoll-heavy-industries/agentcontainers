package container

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/mount"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

// ---------------------------------------------------------------------------
// Unit tests — no Docker daemon required
// ---------------------------------------------------------------------------

func TestNewDockerRuntime_Defaults(t *testing.T) {
	// NewDockerRuntime without a mock client will try to connect to a real
	// Docker daemon, which we skip in unit tests. Instead, we verify the
	// options layer directly.
	opts := defaultDockerOptions()

	assert.NotNil(t, opts.logger, "logger should default to nop logger")
	assert.Equal(t, defaultStopTimeout, opts.stopTimeout)
	assert.Nil(t, opts.client, "client should be nil by default")
}

func TestDockerOptions_WithLogger(t *testing.T) {
	opts := defaultDockerOptions()
	logger := zap.NewExample()
	WithDockerLogger(logger)(opts)

	assert.Equal(t, logger, opts.logger)
}

func TestDockerOptions_WithLoggerNilIgnored(t *testing.T) {
	opts := defaultDockerOptions()
	original := opts.logger
	WithDockerLogger(nil)(opts)

	assert.Equal(t, original, opts.logger)
}

func TestDockerOptions_WithStopTimeout(t *testing.T) {
	t.Run("positive duration", func(t *testing.T) {
		opts := defaultDockerOptions()
		WithStopTimeout(30 * time.Second)(opts)
		assert.Equal(t, 30*time.Second, opts.stopTimeout)
	})

	t.Run("zero duration ignored", func(t *testing.T) {
		opts := defaultDockerOptions()
		WithStopTimeout(0)(opts)
		assert.Equal(t, defaultStopTimeout, opts.stopTimeout)
	})

	t.Run("negative duration ignored", func(t *testing.T) {
		opts := defaultDockerOptions()
		WithStopTimeout(-5 * time.Second)(opts)
		assert.Equal(t, defaultStopTimeout, opts.stopTimeout)
	})
}

func TestDockerOptions_WithClient(t *testing.T) {
	opts := defaultDockerOptions()
	assert.Nil(t, opts.client)

	// WithDockerClient(nil) should be a no-op.
	WithDockerClient(nil)(opts)
	assert.Nil(t, opts.client)
}

func TestBuildContainerConfig_SecurityDefaults(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "test-agent",
		Image: "ubuntu:22.04",
	}
	opts := StartOptions{}

	containerCfg, hostCfg, networkCfg := rt.buildContainerConfig(cfg, opts)

	// Verify container config.
	assert.Equal(t, "ubuntu:22.04", containerCfg.Image)
	assert.Equal(t, "true", containerCfg.Labels[labelPrefix+"/managed"])
	assert.Equal(t, "test-agent", containerCfg.Labels[labelPrefix+"/name"])

	// Verify security defaults.
	assert.Equal(t, []string{"ALL"}, hostCfg.CapDrop, "should drop all capabilities")
	assert.Contains(t, hostCfg.SecurityOpt, "no-new-privileges", "should set no-new-privileges")
	assert.True(t, hostCfg.ReadonlyRootfs, "should have read-only root filesystem")

	// Verify networking config is present (even if empty).
	assert.NotNil(t, networkCfg)
}

// TestBuildContainerConfig_PinnedImageRef verifies that when StartOptions
// carries a PinnedImageRef, buildContainerConfig uses it instead of cfg.Image.
// This is the F-4 dual-resolution fix: both policy extraction and Docker pull
// must use the same content-addressed manifest.
func TestBuildContainerConfig_PinnedImageRef(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "pinned-test",
		Image: "myrepo/myimage:v1",
	}

	pinnedRef := "myrepo/myimage:v1@sha256:" + strings.Repeat("a", 64)
	opts := StartOptions{
		PinnedImageRef: pinnedRef,
	}

	containerCfg, _, _ := rt.buildContainerConfig(cfg, opts)

	// The container must be created from the pinned digest ref, not the mutable tag.
	assert.Equal(t, pinnedRef, containerCfg.Image,
		"buildContainerConfig must use PinnedImageRef when set (F-4 dual-resolution fix)")
}

// TestBuildContainerConfig_NoPinnedRefFallsBackToCfgImage verifies that when
// PinnedImageRef is empty, buildContainerConfig falls back to cfg.Image.
func TestBuildContainerConfig_NoPinnedRefFallsBackToCfgImage(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "fallback-test",
		Image: "myrepo/myimage:v1",
	}

	opts := StartOptions{} // PinnedImageRef is empty

	containerCfg, _, _ := rt.buildContainerConfig(cfg, opts)

	assert.Equal(t, "myrepo/myimage:v1", containerCfg.Image,
		"buildContainerConfig should fall back to cfg.Image when PinnedImageRef is empty")
}

func TestBuildContainerConfig_WorkspaceMount(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "ws-test",
		Image: "node:20",
	}
	opts := StartOptions{
		WorkspacePath: "/home/user/project",
	}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	require.Len(t, hostCfg.Mounts, 1)
	m := hostCfg.Mounts[0]
	assert.Equal(t, mount.TypeBind, m.Type)
	assert.Equal(t, "/home/user/project", m.Source)
	assert.Equal(t, defaultWorkspaceTarget, m.Target)
	assert.False(t, m.ReadOnly, "workspace should be read-write")
}

func TestBuildContainerConfig_WorkspaceMountPropagation(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "ws-prop-test",
		Image: "node:20",
	}
	opts := StartOptions{
		WorkspacePath: "/home/user/project",
	}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	require.Len(t, hostCfg.Mounts, 1)
	m := hostCfg.Mounts[0]
	require.NotNil(t, m.BindOptions, "workspace bind mount should have BindOptions")
	assert.Equal(t, mount.PropagationRPrivate, m.BindOptions.Propagation,
		"workspace mount should use rprivate propagation")
}

func TestBuildContainerConfig_PolicyMountPropagation(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "policy-prop-test",
		Image: "alpine:3.19",
	}

	p := &policy.ContainerPolicy{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		ReadonlyRootfs: true,
		NetworkMode:    "none",
		AllowedMounts: []policy.MountPolicy{
			{Source: "/host/data", Target: "/data", ReadOnly: true},
		},
	}

	opts := StartOptions{Policy: p}
	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	require.Len(t, hostCfg.Mounts, 1)
	m := hostCfg.Mounts[0]
	require.NotNil(t, m.BindOptions, "policy bind mount should have BindOptions")
	assert.Equal(t, mount.PropagationRPrivate, m.BindOptions.Propagation,
		"policy mount should use rprivate propagation")
}

func TestBuildContainerConfig_NoWorkspace(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "no-ws",
		Image: "alpine:3.19",
	}
	opts := StartOptions{}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	assert.Empty(t, hostCfg.Mounts, "no mounts when workspace is empty")
}

func TestBuildContainerConfig_ConfigMounts(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "mount-test",
		Image: "alpine:3.19",
		Mounts: []string{
			"type=bind,source=/host/data,target=/data,readonly",
			"type=volume,source=myvolume,target=/vol",
		},
	}
	opts := StartOptions{
		WorkspacePath: "/workspace-host",
	}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	// 2 config mounts + 1 workspace mount = 3 total.
	require.Len(t, hostCfg.Mounts, 3)

	// First mount: bind with readonly.
	assert.Equal(t, mount.TypeBind, hostCfg.Mounts[0].Type)
	assert.Equal(t, "/host/data", hostCfg.Mounts[0].Source)
	assert.Equal(t, "/data", hostCfg.Mounts[0].Target)
	assert.True(t, hostCfg.Mounts[0].ReadOnly)

	// Second mount: volume.
	assert.Equal(t, mount.TypeVolume, hostCfg.Mounts[1].Type)
	assert.Equal(t, "myvolume", hostCfg.Mounts[1].Source)
	assert.Equal(t, "/vol", hostCfg.Mounts[1].Target)
	assert.False(t, hostCfg.Mounts[1].ReadOnly)

	// Third mount: workspace.
	assert.Equal(t, mount.TypeBind, hostCfg.Mounts[2].Type)
	assert.Equal(t, "/workspace-host", hostCfg.Mounts[2].Source)
	assert.Equal(t, defaultWorkspaceTarget, hostCfg.Mounts[2].Target)
}

func TestParseMount_BindReadonly(t *testing.T) {
	m := parseMount("type=bind,source=/a,target=/b,readonly")
	require.NotNil(t, m)

	assert.Equal(t, mount.TypeBind, m.Type)
	assert.Equal(t, "/a", m.Source)
	assert.Equal(t, "/b", m.Target)
	assert.True(t, m.ReadOnly)
}

func TestParseMount_Volume(t *testing.T) {
	m := parseMount("type=volume,source=data,target=/data")
	require.NotNil(t, m)

	assert.Equal(t, mount.TypeVolume, m.Type)
	assert.Equal(t, "data", m.Source)
	assert.Equal(t, "/data", m.Target)
	assert.False(t, m.ReadOnly)
}

func TestParseMount_Tmpfs(t *testing.T) {
	m := parseMount("type=tmpfs,source=none,target=/tmp")
	require.NotNil(t, m)

	assert.Equal(t, mount.TypeTmpfs, m.Type)
	assert.Equal(t, "/tmp", m.Target)
}

func TestParseMount_TmpfsOptions(t *testing.T) {
	m := parseMount("type=tmpfs,target=/home/node,tmpfs-mode=0777")
	require.NotNil(t, m)
	require.NotNil(t, m.TmpfsOptions)

	assert.Equal(t, mount.TypeTmpfs, m.Type)
	assert.Equal(t, os.FileMode(0o777), m.TmpfsOptions.Mode)
	assert.Empty(t, m.TmpfsOptions.Options)
}

func TestParseMount_AlternateKeys(t *testing.T) {
	m := parseMount("type=bind,src=/host,dst=/container")
	require.NotNil(t, m)

	assert.Equal(t, "/host", m.Source)
	assert.Equal(t, "/container", m.Target)
}

func TestParseMount_DestinationKey(t *testing.T) {
	m := parseMount("type=bind,source=/host,destination=/container")
	require.NotNil(t, m)

	assert.Equal(t, "/container", m.Target)
}

func TestParseMount_MissingSource(t *testing.T) {
	m := parseMount("type=bind,target=/b")
	assert.Nil(t, m, "should return nil when source is missing")
}

func TestParseMount_MissingTarget(t *testing.T) {
	m := parseMount("type=bind,source=/a")
	assert.Nil(t, m, "should return nil when target is missing")
}

func TestParseMount_EmptyString(t *testing.T) {
	m := parseMount("")
	assert.Nil(t, m)
}

func TestParseMount_DefaultTypeBind(t *testing.T) {
	m := parseMount("source=/a,target=/b")
	require.NotNil(t, m)

	assert.Equal(t, mount.TypeBind, m.Type, "default type should be bind")
}

func TestParseMount_ReadonlyTrueValue(t *testing.T) {
	m := parseMount("type=bind,source=/a,target=/b,readonly=true")
	require.NotNil(t, m)

	assert.True(t, m.ReadOnly)
}

func TestParseMount_WithPropagation(t *testing.T) {
	tests := []struct {
		name        string
		raw         string
		wantProp    mount.Propagation
		wantBindOpt bool
	}{
		{"rprivate", "type=bind,source=/a,target=/b,propagation=rprivate", mount.PropagationRPrivate, true},
		{"private", "type=bind,source=/a,target=/b,propagation=private", mount.PropagationPrivate, true},
		{"rshared", "type=bind,source=/a,target=/b,propagation=rshared", mount.PropagationRShared, true},
		{"shared", "type=bind,source=/a,target=/b,propagation=shared", mount.PropagationShared, true},
		{"rslave", "type=bind,source=/a,target=/b,propagation=rslave", mount.PropagationRSlave, true},
		{"slave", "type=bind,source=/a,target=/b,propagation=slave", mount.PropagationSlave, true},
		{"unknown ignored", "type=bind,source=/a,target=/b,propagation=bogus", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := parseMount(tt.raw)
			require.NotNil(t, m)
			if tt.wantBindOpt {
				require.NotNil(t, m.BindOptions, "BindOptions should be set")
				assert.Equal(t, tt.wantProp, m.BindOptions.Propagation)
			} else {
				assert.Nil(t, m.BindOptions, "BindOptions should be nil for unknown propagation")
			}
		})
	}
}

func TestParseMount_DefaultPropagation(t *testing.T) {
	// Without an explicit propagation key, BindOptions should be nil
	// (Docker defaults to rprivate).
	m := parseMount("type=bind,source=/a,target=/b")
	require.NotNil(t, m)
	assert.Nil(t, m.BindOptions, "BindOptions should be nil when no propagation specified")
}

func TestParseMount_PropagationIgnoredForNonBind(t *testing.T) {
	// Propagation only applies to bind mounts; volume and tmpfs should ignore it.
	m := parseMount("type=volume,source=vol,target=/vol,propagation=rprivate")
	require.NotNil(t, m)
	assert.Nil(t, m.BindOptions, "BindOptions should be nil for volume mounts")

	m = parseMount("type=tmpfs,source=none,target=/tmp,propagation=rprivate")
	require.NotNil(t, m)
	assert.Nil(t, m.BindOptions, "BindOptions should be nil for tmpfs mounts")
}

func TestParseMounts_Multiple(t *testing.T) {
	raw := []string{
		"type=bind,source=/a,target=/b",
		"type=volume,source=vol,target=/vol",
		"invalid-no-target",
	}

	mounts := parseMounts(raw)
	assert.Len(t, mounts, 2, "should skip invalid mounts")
}

func TestParseMounts_Empty(t *testing.T) {
	mounts := parseMounts(nil)
	assert.Empty(t, mounts)

	mounts = parseMounts([]string{})
	assert.Empty(t, mounts)
}

// ---------------------------------------------------------------------------
// Policy application tests
// ---------------------------------------------------------------------------

func TestBuildContainerConfig_PolicyCapDrop(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "policy-cap-test",
		Image: "alpine:3.19",
	}

	p := &policy.ContainerPolicy{
		CapDrop:        []string{"NET_ADMIN", "SYS_ADMIN"},
		CapAdd:         []string{"NET_BIND_SERVICE"},
		SecurityOpt:    []string{"no-new-privileges", "seccomp=unconfined"},
		ReadonlyRootfs: true,
		NetworkMode:    "bridge",
	}

	opts := StartOptions{
		Policy: p,
	}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	assert.Equal(t, []string{"NET_ADMIN", "SYS_ADMIN"}, hostCfg.CapDrop, "should apply CapDrop from policy")
	assert.Equal(t, []string{"NET_BIND_SERVICE"}, hostCfg.CapAdd, "should apply CapAdd from policy")
	assert.Equal(t, []string{"no-new-privileges", "seccomp=unconfined"}, hostCfg.SecurityOpt, "should apply SecurityOpt from policy")
	assert.True(t, hostCfg.ReadonlyRootfs, "should apply ReadonlyRootfs from policy")
}

func TestBuildContainerConfig_PolicyReadonlyRootfs(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "policy-rootfs-test",
		Image: "alpine:3.19",
	}

	t.Run("readonly true", func(t *testing.T) {
		opts := StartOptions{
			Policy: &policy.ContainerPolicy{
				CapDrop:        []string{"ALL"},
				SecurityOpt:    []string{"no-new-privileges"},
				ReadonlyRootfs: true,
				NetworkMode:    "none",
			},
		}

		_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)
		assert.True(t, hostCfg.ReadonlyRootfs, "should apply read-only root filesystem")
	})

	t.Run("readonly false", func(t *testing.T) {
		opts := StartOptions{
			Policy: &policy.ContainerPolicy{
				CapDrop:        []string{"ALL"},
				SecurityOpt:    []string{"no-new-privileges"},
				ReadonlyRootfs: false,
				NetworkMode:    "none",
			},
		}

		_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)
		assert.False(t, hostCfg.ReadonlyRootfs, "should allow writable root filesystem when policy specifies")
	})
}

func TestBuildContainerConfig_PolicyNetworkMode(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "policy-network-test",
		Image: "alpine:3.19",
	}

	tests := []struct {
		name         string
		networkMode  string
		expectedMode container.NetworkMode
	}{
		{
			name:         "none mode for isolation",
			networkMode:  "none",
			expectedMode: container.NetworkMode("none"),
		},
		{
			name:         "bridge mode for network access",
			networkMode:  "bridge",
			expectedMode: container.NetworkMode("bridge"),
		},
		{
			name:         "host mode",
			networkMode:  "host",
			expectedMode: container.NetworkMode("host"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := StartOptions{
				Policy: &policy.ContainerPolicy{
					CapDrop:        []string{"ALL"},
					SecurityOpt:    []string{"no-new-privileges"},
					ReadonlyRootfs: true,
					NetworkMode:    tt.networkMode,
				},
			}

			_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)
			assert.Equal(t, tt.expectedMode, hostCfg.NetworkMode, "should apply network mode from policy")
		})
	}
}

func TestBuildContainerConfig_PolicyAllowedMounts(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "policy-mounts-test",
		Image: "alpine:3.19",
	}

	p := &policy.ContainerPolicy{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		ReadonlyRootfs: true,
		NetworkMode:    "none",
		AllowedMounts: []policy.MountPolicy{
			{Source: "/host/readonly", Target: "/container/readonly", ReadOnly: true},
			{Source: "/host/readwrite", Target: "/container/readwrite", ReadOnly: false},
		},
	}

	opts := StartOptions{
		Policy: p,
	}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	require.Len(t, hostCfg.Mounts, 2, "should have 2 policy mounts")

	// First mount: read-only.
	assert.Equal(t, mount.TypeBind, hostCfg.Mounts[0].Type)
	assert.Equal(t, "/host/readonly", hostCfg.Mounts[0].Source)
	assert.Equal(t, "/container/readonly", hostCfg.Mounts[0].Target)
	assert.True(t, hostCfg.Mounts[0].ReadOnly)

	// Second mount: read-write.
	assert.Equal(t, mount.TypeBind, hostCfg.Mounts[1].Type)
	assert.Equal(t, "/host/readwrite", hostCfg.Mounts[1].Source)
	assert.Equal(t, "/container/readwrite", hostCfg.Mounts[1].Target)
	assert.False(t, hostCfg.Mounts[1].ReadOnly)
}

func TestBuildContainerConfig_PolicyMountsWithWorkspace(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "policy-combined-mounts-test",
		Image: "alpine:3.19",
		Mounts: []string{
			"type=bind,source=/config,target=/etc/app,readonly",
		},
	}

	p := &policy.ContainerPolicy{
		CapDrop:        []string{"ALL"},
		SecurityOpt:    []string{"no-new-privileges"},
		ReadonlyRootfs: true,
		NetworkMode:    "none",
		AllowedMounts: []policy.MountPolicy{
			{Source: "/data", Target: "/workspace/data", ReadOnly: false},
		},
	}

	opts := StartOptions{
		Policy:        p,
		WorkspacePath: "/home/user/project",
	}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	// Should have: 1 config mount + 1 policy mount + 1 workspace mount = 3 total.
	require.Len(t, hostCfg.Mounts, 3, "should combine config, policy, and workspace mounts")

	// Config mount first.
	assert.Equal(t, "/config", hostCfg.Mounts[0].Source)
	assert.Equal(t, "/etc/app", hostCfg.Mounts[0].Target)
	assert.True(t, hostCfg.Mounts[0].ReadOnly)

	// Policy mount second.
	assert.Equal(t, "/data", hostCfg.Mounts[1].Source)
	assert.Equal(t, "/workspace/data", hostCfg.Mounts[1].Target)
	assert.False(t, hostCfg.Mounts[1].ReadOnly)

	// Workspace mount last.
	assert.Equal(t, "/home/user/project", hostCfg.Mounts[2].Source)
	assert.Equal(t, defaultWorkspaceTarget, hostCfg.Mounts[2].Target)
	assert.False(t, hostCfg.Mounts[2].ReadOnly)
}

func TestBuildContainerConfig_NilPolicyUsesDefaults(t *testing.T) {
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "nil-policy-test",
		Image: "alpine:3.19",
	}

	opts := StartOptions{
		Policy: nil,
	}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	// Should apply default-deny security settings.
	assert.Equal(t, []string{"ALL"}, hostCfg.CapDrop, "nil policy should drop all capabilities")
	assert.Contains(t, hostCfg.SecurityOpt, "no-new-privileges", "nil policy should set no-new-privileges")
	assert.True(t, hostCfg.ReadonlyRootfs, "nil policy should have read-only root filesystem")
	assert.Equal(t, container.NetworkMode("none"), hostCfg.NetworkMode, "nil policy should isolate network")
}

func TestDefaultContainerPolicy(t *testing.T) {
	p := defaultContainerPolicy()

	assert.Equal(t, []string{"ALL"}, p.CapDrop, "default policy should drop all capabilities")
	assert.Nil(t, p.CapAdd, "default policy should not add any capabilities")
	assert.Equal(t, []string{"no-new-privileges"}, p.SecurityOpt, "default policy should set no-new-privileges")
	assert.True(t, p.ReadonlyRootfs, "default policy should have read-only root filesystem")
	assert.Equal(t, "none", p.NetworkMode, "default policy should isolate network")
	assert.Nil(t, p.AllowedMounts, "default policy should not have any mounts")
}

// --- P0-4: Docker socket rejection tests (ESC-2 finding) ---

func TestValidateMounts_RejectsDockerSocket(t *testing.T) {
	tests := []struct {
		name         string
		socketPath   string
		expectReject bool
	}{
		// Docker
		{"docker.sock in /var/run", "/var/run/docker.sock", true},
		{"docker.sock in /run", "/run/docker.sock", true},
		// containerd
		{"containerd.sock in /var/run", "/var/run/containerd/containerd.sock", true},
		{"containerd.sock in /run", "/run/containerd/containerd.sock", true},
		// CRI-O (MEDIUM-4 fix)
		{"crio.sock in /var/run", "/var/run/crio/crio.sock", true},
		{"crio.sock in /run", "/run/crio/crio.sock", true},
		// Podman (MEDIUM-4 fix)
		{"podman.sock in /var/run", "/var/run/podman/podman.sock", true},
		{"podman.sock in /run", "/run/podman/podman.sock", true},
		// Docker Desktop (MEDIUM-4 fix)
		{"docker.raw.sock", "/var/run/docker.raw.sock", true},
		// Basename matching (MEDIUM-4 fix: non-standard paths)
		{"docker.sock in custom path", "/opt/custom/docker.sock", true},
		{"containerd.sock in custom path", "/custom/containerd.sock", true},
		{"dockershim.sock", "/var/run/dockershim.sock", true},
		// Safe paths
		{"safe bind mount", "/home/user/data", false},
		{"root filesystem", "/", false},
		{"file ending in sock", "/home/user/my.sock", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mounts := []mount.Mount{
				{
					Type:   mount.TypeBind,
					Source: tt.socketPath,
					Target: "/mnt/host",
				},
			}

			err := validateMounts(mounts)
			if tt.expectReject {
				require.Error(t, err, "should reject mount of %s", tt.socketPath)
				assert.Contains(t, err.Error(), "forbidden mount")
				assert.Contains(t, err.Error(), tt.socketPath)
			} else {
				require.NoError(t, err, "should allow mount of %s", tt.socketPath)
			}
		})
	}
}

func TestValidateMounts_IgnoresVolumeAndTmpfs(t *testing.T) {
	// Volume and tmpfs mounts don't expose host paths, so no validation needed.
	mounts := []mount.Mount{
		{
			Type:   mount.TypeVolume,
			Source: "/var/run/docker.sock", // Would be rejected if TypeBind.
			Target: "/mnt/vol",
		},
		{
			Type:   mount.TypeTmpfs,
			Target: "/tmp/scratch",
		},
	}

	err := validateMounts(mounts)
	require.NoError(t, err, "volume and tmpfs mounts should not trigger socket validation")
}

func TestValidateMounts_EmptyList(t *testing.T) {
	err := validateMounts(nil)
	require.NoError(t, err, "nil mount list should be valid")

	err = validateMounts([]mount.Mount{})
	require.NoError(t, err, "empty mount list should be valid")
}

func TestBuildContainerConfig_PanicsOnForbiddenMount(t *testing.T) {
	// P0-4: buildContainerConfig should panic if it encounters a forbidden mount.
	// This is a defense-in-depth measure: it should never happen in practice
	// because policy resolution should prevent it, but we catch it anyway.
	rt := &DockerRuntime{logger: zap.NewNop()}

	cfg := &config.AgentContainer{
		Name:  "socket-escape-attempt",
		Image: "alpine:3.19",
	}

	opts := StartOptions{
		Policy: &policy.ContainerPolicy{
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges"},
			ReadonlyRootfs: true,
			NetworkMode:    "none",
			AllowedMounts: []policy.MountPolicy{
				{
					Source:   "/var/run/docker.sock",
					Target:   "/var/run/docker.sock",
					ReadOnly: false,
				},
			},
		},
	}

	assert.Panics(t, func() {
		rt.buildContainerConfig(cfg, opts)
	}, "should panic when attempting to mount Docker socket")
}

func TestStartOptions_PolicyField(t *testing.T) {
	p := &policy.ContainerPolicy{
		CapDrop:        []string{"ALL"},
		NetworkMode:    "none",
		ReadonlyRootfs: true,
	}

	opts := StartOptions{
		Detach:        true,
		Timeout:       30 * time.Minute,
		WorkspacePath: "/tmp/workspace",
		Policy:        p,
	}

	assert.True(t, opts.Detach)
	assert.Equal(t, 30*time.Minute, opts.Timeout)
	assert.Equal(t, "/tmp/workspace", opts.WorkspacePath)
	assert.Equal(t, p, opts.Policy)
}

// ---------------------------------------------------------------------------
// Compile-time interface satisfaction checks
// ---------------------------------------------------------------------------

func TestComposeRuntime_ImplementsRuntime(t *testing.T) {
	var _ Runtime = (*ComposeRuntime)(nil)
}

// ---------------------------------------------------------------------------
// Enforcement strategy tests
// ---------------------------------------------------------------------------

// mockStrategy implements enforcement.Strategy for testing.
type mockStrategy struct {
	level enforcement.Level
}

var _ enforcement.Strategy = (*mockStrategy)(nil)

func (m *mockStrategy) Apply(_ context.Context, _ string, _ uint32, _ *policy.ContainerPolicy) error {
	return nil
}
func (m *mockStrategy) Update(_ context.Context, _ string, _ *policy.ContainerPolicy) error {
	return nil
}
func (m *mockStrategy) Remove(_ context.Context, _ string) error { return nil }
func (m *mockStrategy) InjectSecrets(_ context.Context, _ string, _ map[string]*secrets.Secret) error {
	return nil
}
func (m *mockStrategy) Events(_ string) <-chan enforcement.Event { return nil }
func (m *mockStrategy) Level() enforcement.Level                 { return m.level }

func TestDockerOptions_WithEnforcementLevel(t *testing.T) {
	opts := defaultDockerOptions()
	assert.Nil(t, opts.enforcementLevel, "enforcement level should be nil by default")

	level := enforcement.LevelGRPC
	WithEnforcementLevel(level)(opts)

	require.NotNil(t, opts.enforcementLevel, "enforcement level should be set")
	assert.Equal(t, enforcement.LevelGRPC, *opts.enforcementLevel)
}

func TestBuildContainerConfig_Enforcement_NoCapsAdded(t *testing.T) {
	rt := &DockerRuntime{
		logger:   zap.NewNop(),
		strategy: &mockStrategy{level: enforcement.LevelGRPC},
	}

	cfg := &config.AgentContainer{
		Name:  "enforce-test",
		Image: "alpine:3.19",
	}
	opts := StartOptions{
		Policy: &policy.ContainerPolicy{
			CapDrop:        []string{"ALL"},
			SecurityOpt:    []string{"no-new-privileges"},
			ReadonlyRootfs: true,
			NetworkMode:    "bridge",
			AllowedHosts:   []string{"example.com"},
		},
	}

	_, hostCfg, _ := rt.buildContainerConfig(cfg, opts)

	// Enforcement should NOT inject NET_ADMIN or NET_RAW.
	assert.NotContains(t, hostCfg.CapAdd, "NET_ADMIN",
		"enforcement should not add NET_ADMIN capability")
	assert.NotContains(t, hostCfg.CapAdd, "NET_RAW",
		"enforcement should not add NET_RAW capability")
}
