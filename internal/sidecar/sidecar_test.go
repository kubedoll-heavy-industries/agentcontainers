package sidecar

import (
	"context"
	"errors"
	"io"
	"iter"
	"strings"
	"testing"
	"time"

	dockercontainer "github.com/moby/moby/api/types/container"
	"github.com/moby/moby/api/types/jsonstream"
	"github.com/moby/moby/api/types/network"
	"github.com/moby/moby/client"
)

// mockDockerClient implements the subset of client.APIClient used by the sidecar
// package. Unimplemented methods panic to surface unexpected calls.
type mockDockerClient struct {
	client.APIClient

	imageInspectFn     func(ctx context.Context, ref string, opts ...client.ImageInspectOption) (client.ImageInspectResult, error)
	imagePullFn        func(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error)
	containerCreateFn  func(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error)
	containerStartFn   func(ctx context.Context, id string, opts client.ContainerStartOptions) (client.ContainerStartResult, error)
	containerInspectFn func(ctx context.Context, id string, opts client.ContainerInspectOptions) (client.ContainerInspectResult, error)
	containerStopFn    func(ctx context.Context, id string, opts client.ContainerStopOptions) (client.ContainerStopResult, error)
	containerRemoveFn  func(ctx context.Context, id string, opts client.ContainerRemoveOptions) (client.ContainerRemoveResult, error)
}

func (m *mockDockerClient) ImageInspect(ctx context.Context, ref string, opts ...client.ImageInspectOption) (client.ImageInspectResult, error) {
	if m.imageInspectFn != nil {
		return m.imageInspectFn(ctx, ref, opts...)
	}
	return client.ImageInspectResult{}, errors.New("image not found")
}

func (m *mockDockerClient) ImagePull(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
	if m.imagePullFn != nil {
		return m.imagePullFn(ctx, ref, opts)
	}
	return &mockImagePullResponse{}, nil
}

func (m *mockDockerClient) ContainerCreate(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
	if m.containerCreateFn != nil {
		return m.containerCreateFn(ctx, opts)
	}
	return client.ContainerCreateResult{ID: "mock-container-id"}, nil
}

func (m *mockDockerClient) ContainerStart(ctx context.Context, id string, opts client.ContainerStartOptions) (client.ContainerStartResult, error) {
	if m.containerStartFn != nil {
		return m.containerStartFn(ctx, id, opts)
	}
	return client.ContainerStartResult{}, nil
}

func (m *mockDockerClient) ContainerInspect(ctx context.Context, id string, opts client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
	if m.containerInspectFn != nil {
		return m.containerInspectFn(ctx, id, opts)
	}
	return client.ContainerInspectResult{}, errors.New("container not found")
}

func (m *mockDockerClient) ContainerStop(ctx context.Context, id string, opts client.ContainerStopOptions) (client.ContainerStopResult, error) {
	if m.containerStopFn != nil {
		return m.containerStopFn(ctx, id, opts)
	}
	return client.ContainerStopResult{}, nil
}

func (m *mockDockerClient) ContainerRemove(ctx context.Context, id string, opts client.ContainerRemoveOptions) (client.ContainerRemoveResult, error) {
	if m.containerRemoveFn != nil {
		return m.containerRemoveFn(ctx, id, opts)
	}
	return client.ContainerRemoveResult{}, nil
}

// mockImagePullResponse implements client.ImagePullResponse.
type mockImagePullResponse struct{}

func (m *mockImagePullResponse) Read(_ []byte) (int, error)   { return 0, io.EOF }
func (m *mockImagePullResponse) Close() error                 { return nil }
func (m *mockImagePullResponse) Wait(_ context.Context) error { return nil }
func (m *mockImagePullResponse) JSONMessages(_ context.Context) iter.Seq2[jsonstream.Message, error] {
	return func(yield func(jsonstream.Message, error) bool) {}
}

// alwaysHealthy is a HealthProber that always returns true.
func alwaysHealthy(_ string) bool { return true }

// neverHealthy is a HealthProber that always returns false.
func neverHealthy(_ string) bool { return false }

// ---------------------------------------------------------------------------
// StartSidecar tests
// ---------------------------------------------------------------------------

func TestStartSidecar_Success(t *testing.T) {
	mock := &mockDockerClient{}

	origProber := defaultHealthProber
	defaultHealthProber = alwaysHealthy
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Image:          "test-enforcer:v1",
		Port:           50051,
		HealthTimeout:  1 * time.Second,
		HealthInterval: 10 * time.Millisecond,
		Required:       true,
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if handle == nil {
		t.Fatal("StartSidecar() returned nil handle")
	}
	if !handle.Managed {
		t.Error("handle.Managed = false, want true")
	}
	if handle.ContainerID != "mock-container-id" {
		t.Errorf("handle.ContainerID = %q, want %q", handle.ContainerID, "mock-container-id")
	}
	if handle.Addr != "127.0.0.1:50051" {
		t.Errorf("handle.Addr = %q, want %q", handle.Addr, "127.0.0.1:50051")
	}
}

func TestStartSidecar_HealthCheckAddrOverride(t *testing.T) {
	var probeTarget string
	mock := &mockDockerClient{}

	origProber := defaultHealthProber
	defaultHealthProber = func(target string) bool {
		probeTarget = target
		return true
	}
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Image:           "test-enforcer:v1",
		Port:            50051,
		HealthTimeout:   1 * time.Second,
		HealthInterval:  10 * time.Millisecond,
		Required:        true,
		HealthCheckAddr: "192.168.1.50:50051",
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if handle == nil {
		t.Fatal("StartSidecar() returned nil handle")
	}
	if handle.Addr != "192.168.1.50:50051" {
		t.Errorf("handle.Addr = %q, want %q", handle.Addr, "192.168.1.50:50051")
	}
	if probeTarget != "192.168.1.50:50051" {
		t.Errorf("health probe target = %q, want %q", probeTarget, "192.168.1.50:50051")
	}
	if !handle.Managed {
		t.Error("handle.Managed = false, want true")
	}
}

func TestStartSidecar_HealthCheckAddrEmpty_DefaultsToLocalhost(t *testing.T) {
	var probeTarget string
	mock := &mockDockerClient{}

	origProber := defaultHealthProber
	defaultHealthProber = func(target string) bool {
		probeTarget = target
		return true
	}
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Port:           9999,
		HealthTimeout:  1 * time.Second,
		HealthInterval: 10 * time.Millisecond,
		Required:       true,
		// HealthCheckAddr intentionally empty
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if handle == nil {
		t.Fatal("StartSidecar() returned nil handle")
	}
	if handle.Addr != "127.0.0.1:9999" {
		t.Errorf("handle.Addr = %q, want %q", handle.Addr, "127.0.0.1:9999")
	}
	if probeTarget != "127.0.0.1:9999" {
		t.Errorf("health probe target = %q, want %q", probeTarget, "127.0.0.1:9999")
	}
}

func TestStartSidecar_RandomHostPort(t *testing.T) {
	var hostPort string
	mock := &mockDockerClient{
		containerCreateFn: func(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
			port := network.MustParsePort("50051/tcp")
			bindings := opts.HostConfig.PortBindings[port]
			if len(bindings) != 1 {
				t.Fatalf("port bindings = %d, want 1", len(bindings))
			}
			hostPort = bindings[0].HostPort
			return client.ContainerCreateResult{ID: "random-port-id"}, nil
		},
		containerInspectFn: func(ctx context.Context, id string, opts client.ContainerInspectOptions) (client.ContainerInspectResult, error) {
			return client.ContainerInspectResult{
				Container: dockercontainer.InspectResponse{
					NetworkSettings: &dockercontainer.NetworkSettings{
						Ports: network.PortMap{
							network.MustParsePort("50051/tcp"): {
								{HostPort: "32791"},
							},
						},
					},
				},
			}, nil
		},
	}

	origProber := defaultHealthProber
	defaultHealthProber = alwaysHealthy
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		RandomHostPort: true,
		HealthTimeout:  1 * time.Second,
		HealthInterval: 10 * time.Millisecond,
		Required:       true,
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if hostPort != "" {
		t.Errorf("host port binding = %q, want empty for Docker-assigned port", hostPort)
	}
	if handle.Addr != "127.0.0.1:32791" {
		t.Errorf("handle.Addr = %q, want %q", handle.Addr, "127.0.0.1:32791")
	}
}

func TestStartSidecar_GrantsProcRootInspectionCapability(t *testing.T) {
	var capAdd []string
	mock := &mockDockerClient{
		containerCreateFn: func(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
			capAdd = append([]string(nil), opts.HostConfig.CapAdd...)
			return client.ContainerCreateResult{ID: "caps-id"}, nil
		},
	}

	origProber := defaultHealthProber
	defaultHealthProber = alwaysHealthy
	defer func() { defaultHealthProber = origProber }()

	_, err := StartSidecar(context.Background(), mock, StartOptions{
		HealthTimeout:  1 * time.Second,
		HealthInterval: 10 * time.Millisecond,
		Required:       true,
	})
	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if !containsString(capAdd, "SYS_PTRACE") {
		t.Fatalf("CapAdd = %#v, want SYS_PTRACE for /proc/<pid>/root access across container UIDs", capAdd)
	}
}

func TestStartSidecar_UnixSocket(t *testing.T) {
	socketPath := t.TempDir() + "/agentcontainer-enforcer.sock"
	var createdCmd []string
	var publishedPorts int
	var socketMountSource string
	mock := &mockDockerClient{
		containerCreateFn: func(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
			createdCmd = append([]string(nil), opts.Config.Cmd...)
			publishedPorts = len(opts.HostConfig.PortBindings)
			for _, m := range opts.HostConfig.Mounts {
				if m.Target == "/run/agentcontainer-enforcer" {
					socketMountSource = m.Source
				}
			}
			return client.ContainerCreateResult{ID: "socket-id"}, nil
		},
	}

	var probeTarget string
	origProber := defaultHealthProber
	defaultHealthProber = func(target string) bool {
		probeTarget = target
		return true
	}
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		SocketPath:     socketPath,
		HealthTimeout:  1 * time.Second,
		HealthInterval: 10 * time.Millisecond,
		Required:       true,
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	wantAddr := "unix://" + socketPath
	if handle.Addr != wantAddr {
		t.Errorf("handle.Addr = %q, want %q", handle.Addr, wantAddr)
	}
	if handle.SocketPath != socketPath {
		t.Errorf("handle.SocketPath = %q, want %q", handle.SocketPath, socketPath)
	}
	if probeTarget != wantAddr {
		t.Errorf("health probe target = %q, want %q", probeTarget, wantAddr)
	}
	if publishedPorts != 0 {
		t.Errorf("published ports = %d, want 0 for UDS sidecar", publishedPorts)
	}
	if socketMountSource == "" {
		t.Fatal("missing /run/agentcontainer-enforcer bind mount")
	}
	wantCmd := []string{"--listen", "127.0.0.1:50051", "--socket", "/run/agentcontainer-enforcer/agentcontainer-enforcer.sock"}
	if strings.Join(createdCmd, " ") != strings.Join(wantCmd, " ") {
		t.Errorf("cmd = %#v, want %#v", createdCmd, wantCmd)
	}
}

func containsString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestStartSidecar_DefaultOptions(t *testing.T) {
	var createdImage string
	mock := &mockDockerClient{
		containerCreateFn: func(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
			createdImage = opts.Config.Image
			return client.ContainerCreateResult{ID: "default-id"}, nil
		},
	}

	origProber := defaultHealthProber
	defaultHealthProber = alwaysHealthy
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Required: true,
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if handle == nil {
		t.Fatal("StartSidecar() returned nil handle")
	}
	if createdImage != DefaultEnforcerImage {
		t.Errorf("image = %q, want default %q", createdImage, DefaultEnforcerImage)
	}
	if handle.Addr != "127.0.0.1:50051" {
		t.Errorf("addr = %q, want %q", handle.Addr, "127.0.0.1:50051")
	}
}

func TestStartSidecar_PullFails_Required(t *testing.T) {
	mock := &mockDockerClient{
		imagePullFn: func(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
			return nil, errors.New("pull failed: unauthorized")
		},
	}

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Required: true,
	})

	if err == nil {
		t.Fatal("StartSidecar() expected error, got nil")
	}
	if handle != nil {
		t.Errorf("handle = %+v, want nil", handle)
	}
	if !strings.Contains(err.Error(), "pull failed") {
		t.Errorf("error = %v, want error containing %q", err, "pull failed")
	}
}

func TestStartSidecar_PullFails_NotRequired(t *testing.T) {
	mock := &mockDockerClient{
		imagePullFn: func(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
			return nil, errors.New("pull failed: unauthorized")
		},
	}

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Required: false,
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if handle != nil {
		t.Errorf("handle = %+v, want nil (soft failure)", handle)
	}
}

func TestStartSidecar_ContainerCreateFails_Required(t *testing.T) {
	mock := &mockDockerClient{
		containerCreateFn: func(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
			return client.ContainerCreateResult{}, errors.New("name already in use")
		},
	}

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Required: true,
	})

	if err == nil {
		t.Fatal("StartSidecar() expected error, got nil")
	}
	if handle != nil {
		t.Errorf("handle = %+v, want nil", handle)
	}
	if !strings.Contains(err.Error(), "creating container") {
		t.Errorf("error = %v, want error containing %q", err, "creating container")
	}
}

func TestStartSidecar_ContainerStartFails(t *testing.T) {
	var removeCalled bool
	mock := &mockDockerClient{
		containerStartFn: func(ctx context.Context, id string, opts client.ContainerStartOptions) (client.ContainerStartResult, error) {
			return client.ContainerStartResult{}, errors.New("start failed")
		},
		containerRemoveFn: func(ctx context.Context, id string, opts client.ContainerRemoveOptions) (client.ContainerRemoveResult, error) {
			removeCalled = true
			return client.ContainerRemoveResult{}, nil
		},
	}

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Required: true,
	})

	if err == nil {
		t.Fatal("StartSidecar() expected error, got nil")
	}
	if handle != nil {
		t.Errorf("handle = %+v, want nil", handle)
	}
	if !removeCalled {
		t.Error("expected ContainerRemove to be called for cleanup")
	}
	if !strings.Contains(err.Error(), "starting container") {
		t.Errorf("error = %v, want error containing %q", err, "starting container")
	}
}

func TestStartSidecar_HealthTimeout_Required(t *testing.T) {
	var removeCalled bool
	mock := &mockDockerClient{
		containerRemoveFn: func(ctx context.Context, id string, opts client.ContainerRemoveOptions) (client.ContainerRemoveResult, error) {
			removeCalled = true
			return client.ContainerRemoveResult{}, nil
		},
	}

	origProber := defaultHealthProber
	defaultHealthProber = neverHealthy
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Required:       true,
		HealthTimeout:  100 * time.Millisecond,
		HealthInterval: 10 * time.Millisecond,
	})

	if err == nil {
		t.Fatal("StartSidecar() expected error, got nil")
	}
	if handle != nil {
		t.Errorf("handle = %+v, want nil", handle)
	}
	if !removeCalled {
		t.Error("expected container cleanup after health timeout")
	}
	if !strings.Contains(err.Error(), "SERVING") {
		t.Errorf("error = %v, want error containing %q", err, "SERVING")
	}
}

func TestStartSidecar_HealthTimeout_NotRequired(t *testing.T) {
	var removeCalled bool
	mock := &mockDockerClient{
		containerRemoveFn: func(ctx context.Context, id string, opts client.ContainerRemoveOptions) (client.ContainerRemoveResult, error) {
			removeCalled = true
			return client.ContainerRemoveResult{}, nil
		},
	}

	origProber := defaultHealthProber
	defaultHealthProber = neverHealthy
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Required:       false,
		HealthTimeout:  100 * time.Millisecond,
		HealthInterval: 10 * time.Millisecond,
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if handle != nil {
		t.Errorf("handle = %+v, want nil (soft failure)", handle)
	}
	if !removeCalled {
		t.Error("expected container cleanup after health timeout")
	}
}

func TestStartSidecar_ImageExistsLocally(t *testing.T) {
	var pullCalled bool
	mock := &mockDockerClient{
		imageInspectFn: func(ctx context.Context, ref string, opts ...client.ImageInspectOption) (client.ImageInspectResult, error) {
			return client.ImageInspectResult{}, nil // image exists
		},
		imagePullFn: func(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
			pullCalled = true
			return &mockImagePullResponse{}, nil
		},
	}

	origProber := defaultHealthProber
	defaultHealthProber = alwaysHealthy
	defer func() { defaultHealthProber = origProber }()

	handle, err := StartSidecar(context.Background(), mock, StartOptions{
		Required: true,
	})

	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}
	if handle == nil {
		t.Fatal("StartSidecar() returned nil handle")
	}
	if pullCalled {
		t.Error("ImagePull should not be called when image exists locally")
	}
}

func TestStartSidecar_ContainerLabels(t *testing.T) {
	var labels map[string]string
	mock := &mockDockerClient{
		containerCreateFn: func(ctx context.Context, opts client.ContainerCreateOptions) (client.ContainerCreateResult, error) {
			labels = opts.Config.Labels
			return client.ContainerCreateResult{ID: "labeled-id"}, nil
		},
	}

	origProber := defaultHealthProber
	defaultHealthProber = alwaysHealthy
	defer func() { defaultHealthProber = origProber }()

	_, err := StartSidecar(context.Background(), mock, StartOptions{
		Required: true,
	})
	if err != nil {
		t.Fatalf("StartSidecar() unexpected error: %v", err)
	}

	if labels[LabelComponent] != "enforcer" {
		t.Errorf("label %q = %q, want %q", LabelComponent, labels[LabelComponent], "enforcer")
	}
	if labels[LabelManaged] != "true" {
		t.Errorf("label %q = %q, want %q", LabelManaged, labels[LabelManaged], "true")
	}
}

// ---------------------------------------------------------------------------
// StopSidecar tests
// ---------------------------------------------------------------------------

func TestStopSidecar_Managed(t *testing.T) {
	var stopCalled, removeCalled bool
	mock := &mockDockerClient{
		containerStopFn: func(ctx context.Context, id string, opts client.ContainerStopOptions) (client.ContainerStopResult, error) {
			stopCalled = true
			if id != "test-container" {
				t.Errorf("ContainerStop called with id %q, want %q", id, "test-container")
			}
			return client.ContainerStopResult{}, nil
		},
		containerRemoveFn: func(ctx context.Context, id string, opts client.ContainerRemoveOptions) (client.ContainerRemoveResult, error) {
			removeCalled = true
			return client.ContainerRemoveResult{}, nil
		},
	}

	err := StopSidecar(context.Background(), mock, &SidecarHandle{
		ContainerID: "test-container",
		Managed:     true,
	})

	if err != nil {
		t.Fatalf("StopSidecar() unexpected error: %v", err)
	}
	if !stopCalled {
		t.Error("expected ContainerStop to be called")
	}
	if !removeCalled {
		t.Error("expected ContainerRemove to be called")
	}
}

func TestStopSidecar_External(t *testing.T) {
	mock := &mockDockerClient{
		containerStopFn: func(ctx context.Context, id string, opts client.ContainerStopOptions) (client.ContainerStopResult, error) {
			t.Error("ContainerStop should not be called for external sidecar")
			return client.ContainerStopResult{}, nil
		},
		containerRemoveFn: func(ctx context.Context, id string, opts client.ContainerRemoveOptions) (client.ContainerRemoveResult, error) {
			t.Error("ContainerRemove should not be called for external sidecar")
			return client.ContainerRemoveResult{}, nil
		},
	}

	err := StopSidecar(context.Background(), mock, &SidecarHandle{
		ContainerID: "external-container",
		Managed:     false,
	})

	if err != nil {
		t.Fatalf("StopSidecar() unexpected error: %v", err)
	}
}

func TestStopSidecar_NilHandle(t *testing.T) {
	mock := &mockDockerClient{}
	err := StopSidecar(context.Background(), mock, nil)
	if err != nil {
		t.Fatalf("StopSidecar(nil) unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// WaitHealthy tests
// ---------------------------------------------------------------------------

func TestWaitHealthy_ImmediateServing(t *testing.T) {
	err := WaitHealthyWithProber(
		context.Background(),
		"127.0.0.1:50051",
		1*time.Second,
		10*time.Millisecond,
		alwaysHealthy,
	)

	if err != nil {
		t.Fatalf("WaitHealthy() unexpected error: %v", err)
	}
}

func TestWaitHealthy_Timeout(t *testing.T) {
	err := WaitHealthyWithProber(
		context.Background(),
		"127.0.0.1:50051",
		100*time.Millisecond,
		10*time.Millisecond,
		neverHealthy,
	)

	if err == nil {
		t.Fatal("WaitHealthy() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "timed out") {
		t.Errorf("error = %v, want error containing %q", err, "timed out")
	}
}

func TestWaitHealthy_ContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	err := WaitHealthyWithProber(
		ctx,
		"127.0.0.1:50051",
		5*time.Second,
		10*time.Millisecond,
		neverHealthy,
	)

	if err == nil {
		t.Fatal("WaitHealthy() expected error on canceled context, got nil")
	}
}

func TestWaitHealthy_EventuallyHealthy(t *testing.T) {
	calls := 0
	eventualProber := func(_ string) bool {
		calls++
		return calls >= 3 // becomes healthy on 3rd poll
	}

	err := WaitHealthyWithProber(
		context.Background(),
		"127.0.0.1:50051",
		5*time.Second,
		10*time.Millisecond,
		eventualProber,
	)

	if err != nil {
		t.Fatalf("WaitHealthy() unexpected error: %v", err)
	}
	if calls < 3 {
		t.Errorf("expected at least 3 probe calls, got %d", calls)
	}
}

// ---------------------------------------------------------------------------
// DiscoverExternalSidecar tests
// ---------------------------------------------------------------------------

func TestDiscoverExternalSidecar_EnvVar(t *testing.T) {
	t.Setenv("AC_ENFORCER_ADDR", "10.0.0.5:50051")

	result := DiscoverExternalSidecarWithProber(
		DiscoverOptions{},
		alwaysHealthy,
	)

	if result.Addr != "10.0.0.5:50051" {
		t.Errorf("Addr = %q, want %q", result.Addr, "10.0.0.5:50051")
	}
	if result.Source != "env" {
		t.Errorf("Source = %q, want %q", result.Source, "env")
	}
}

func TestDiscoverExternalSidecar_ConfigAddr(t *testing.T) {
	t.Setenv("AC_ENFORCER_ADDR", "")

	result := DiscoverExternalSidecarWithProber(
		DiscoverOptions{ConfigAddr: "192.168.1.100:50051"},
		alwaysHealthy,
	)

	if result.Addr != "192.168.1.100:50051" {
		t.Errorf("Addr = %q, want %q", result.Addr, "192.168.1.100:50051")
	}
	if result.Source != "config" {
		t.Errorf("Source = %q, want %q", result.Source, "config")
	}
}

func TestDiscoverExternalSidecar_EnvPriorityOverConfig(t *testing.T) {
	t.Setenv("AC_ENFORCER_ADDR", "env-addr:50051")

	result := DiscoverExternalSidecarWithProber(
		DiscoverOptions{ConfigAddr: "config-addr:50051"},
		alwaysHealthy,
	)

	if result.Addr != "env-addr:50051" {
		t.Errorf("Addr = %q, want env addr", result.Addr)
	}
	if result.Source != "env" {
		t.Errorf("Source = %q, want %q", result.Source, "env")
	}
}

func TestDiscoverExternalSidecar_NotFound(t *testing.T) {
	t.Setenv("AC_ENFORCER_ADDR", "")

	result := DiscoverExternalSidecarWithProber(
		DiscoverOptions{},
		neverHealthy,
	)

	if result.Addr != "" {
		t.Errorf("Addr = %q, want empty", result.Addr)
	}
	if result.Source != "" {
		t.Errorf("Source = %q, want empty", result.Source)
	}
}

func TestDiscoverExternalSidecar_EnvSetButUnhealthy(t *testing.T) {
	t.Setenv("AC_ENFORCER_ADDR", "dead-addr:50051")

	result := DiscoverExternalSidecarWithProber(
		DiscoverOptions{ConfigAddr: "config-addr:50051"},
		func(target string) bool {
			return target == "config-addr:50051"
		},
	)

	if result.Addr != "config-addr:50051" {
		t.Errorf("Addr = %q, want config addr (env is unhealthy)", result.Addr)
	}
	if result.Source != "config" {
		t.Errorf("Source = %q, want %q", result.Source, "config")
	}
}

// ---------------------------------------------------------------------------
// EnsureImage tests
// ---------------------------------------------------------------------------

func TestEnsureImage_AlreadyPresent(t *testing.T) {
	var pullCalled bool
	mock := &mockDockerClient{
		imageInspectFn: func(ctx context.Context, ref string, opts ...client.ImageInspectOption) (client.ImageInspectResult, error) {
			return client.ImageInspectResult{}, nil
		},
		imagePullFn: func(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
			pullCalled = true
			return &mockImagePullResponse{}, nil
		},
	}

	err := EnsureImage(context.Background(), mock, "test:latest")
	if err != nil {
		t.Fatalf("EnsureImage() unexpected error: %v", err)
	}
	if pullCalled {
		t.Error("ImagePull should not be called when image exists")
	}
}

func TestEnsureImage_PullSuccess(t *testing.T) {
	var pullCalled bool
	mock := &mockDockerClient{
		imagePullFn: func(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
			pullCalled = true
			return &mockImagePullResponse{}, nil
		},
	}

	err := EnsureImage(context.Background(), mock, "test:latest")
	if err != nil {
		t.Fatalf("EnsureImage() unexpected error: %v", err)
	}
	if !pullCalled {
		t.Error("ImagePull should be called when image is not present")
	}
}

func TestEnsureImage_PullError(t *testing.T) {
	mock := &mockDockerClient{
		imagePullFn: func(ctx context.Context, ref string, opts client.ImagePullOptions) (client.ImagePullResponse, error) {
			return nil, errors.New("registry unreachable")
		},
	}

	err := EnsureImage(context.Background(), mock, "test:latest")
	if err == nil {
		t.Fatal("EnsureImage() expected error, got nil")
	}
	if !strings.Contains(err.Error(), "registry unreachable") {
		t.Errorf("error = %v, want error containing %q", err, "registry unreachable")
	}
}

// ---------------------------------------------------------------------------
// Constants tests
// ---------------------------------------------------------------------------

func TestConstants(t *testing.T) {
	if DefaultEnforcerImage != "ghcr.io/kubedoll-heavy-industries/agentcontainer-enforcer:latest" {
		t.Errorf("DefaultEnforcerImage = %q, unexpected value", DefaultEnforcerImage)
	}
	if DefaultPort != 50051 {
		t.Errorf("DefaultPort = %d, want 50051", DefaultPort)
	}
	if ContainerName != "agentcontainer-enforcer" {
		t.Errorf("ContainerName = %q, want %q", ContainerName, "agentcontainer-enforcer")
	}
}
