package cli

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

func TestExecFlagParsing(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		wantErr string
	}{
		{
			name:    "no args",
			args:    []string{"exec"},
			wantErr: "requires at least 1 arg(s)",
		},
		{
			name:    "container id only",
			args:    []string{"exec", "abc123"},
			wantErr: "no command specified",
		},
		{
			name:    "unknown runtime",
			args:    []string{"exec", "--runtime", "podman", "abc123", "--", "ls"},
			wantErr: "unknown runtime",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd := newRootCmd("test", "abc", "now")
			cmd.SetArgs(tt.args)

			err := cmd.Execute()
			if err == nil {
				t.Fatalf("expected error containing %q", tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Errorf("expected error containing %q, got: %v", tt.wantErr, err)
			}
		})
	}
}

func TestExecNoConfig_DefaultDeny(t *testing.T) {
	// When no config file exists, exec proceeds with default-deny approval.
	// The broker denies all commands because there are no declared capabilities.
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"exec", "abc123", "--", "ls"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error from default-deny broker")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected denial error, got: %v", err)
	}
}

func TestExecBrokerBlocksInterpreterFlags(t *testing.T) {
	// The approval broker should deny interpreter -c/-e flags.
	tmp := t.TempDir()
	cfgPath := filepath.Join(tmp, "agentcontainer.json")
	cfg := `{
		"name": "test",
		"image": "ubuntu",
		"agent": {
			"capabilities": {
				"shell": {
					"commands": [{"binary": "bash"}]
				}
			}
		}
	}`
	if err := os.WriteFile(cfgPath, []byte(cfg), 0o644); err != nil {
		t.Fatal(err)
	}

	cmd := newRootCmd("test", "abc", "now")
	cmd.SetArgs([]string{"exec", "--config", cfgPath, "abc123", "--", "bash", "-c", "echo pwned"})

	err := cmd.Execute()
	if err == nil {
		t.Fatal("expected error for interpreter with -c flag")
	}
	if !strings.Contains(err.Error(), "denied") {
		t.Errorf("expected denial error, got: %v", err)
	}
}

func TestExecRuntimeDefault(t *testing.T) {
	cmd := newExecCmd()
	if err := cmd.ParseFlags([]string{"abc123", "--", "ls"}); err != nil {
		t.Fatalf("unexpected error parsing flags: %v", err)
	}

	runtimeVal, err := cmd.Flags().GetString("runtime")
	if err != nil {
		t.Fatalf("unexpected error getting runtime flag: %v", err)
	}
	if runtimeVal != "docker" {
		t.Errorf("expected default runtime %q, got %q", "docker", runtimeVal)
	}
}

func TestResolveSecretOnDemand_EnvProvider(t *testing.T) {
	t.Setenv("MY_TEST_SECRET", "supersecret")

	ref := secrets.SecretRef{
		Name:     "test-secret",
		Provider: "env",
		Params:   map[string]string{"env_var": "MY_TEST_SECRET"},
	}

	secret, err := resolveSecretOnDemand(context.Background(), ref)
	if err != nil {
		t.Fatalf("resolveSecretOnDemand() error = %v", err)
	}
	if string(secret.Value) != "supersecret" {
		t.Errorf("Value = %q, want %q", secret.Value, "supersecret")
	}
}

func TestResolveSecretOnDemand_UnsupportedProvider(t *testing.T) {
	ref := secrets.SecretRef{
		Name:     "test",
		Provider: "nonexistent-provider",
		Params:   map[string]string{},
	}

	_, err := resolveSecretOnDemand(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for unsupported provider")
	}
	if !strings.Contains(err.Error(), "unsupported provider") {
		t.Errorf("error = %q, want contains 'unsupported provider'", err.Error())
	}
}

func TestResolveSecretOnDemand_VaultEnvVars(t *testing.T) {
	// Verify that VAULT_ADDR and VAULT_TOKEN env vars are wired through.
	// We don't actually connect to Vault; just confirm no panic and expected error type.
	t.Setenv("VAULT_ADDR", "http://127.0.0.1:18200")
	t.Setenv("VAULT_TOKEN", "test-token")

	ref := secrets.SecretRef{
		Name:     "my-secret",
		Provider: "vault",
		Params:   map[string]string{"path": "myapp/config"},
	}

	// The request will fail (no Vault server), but the provider must be wired correctly.
	_, err := resolveSecretOnDemand(context.Background(), ref)
	if err == nil {
		t.Fatal("expected connection error, got nil")
	}
	// Should not be "unsupported provider" — that would indicate wrong routing.
	if strings.Contains(err.Error(), "unsupported provider") {
		t.Errorf("vault provider should be supported, got: %v", err)
	}
}

func TestResolveSecretOnDemand_InfisicalXORValidation(t *testing.T) {
	// INFISICAL_CLIENT_ID set but INFISICAL_CLIENT_SECRET unset — must error.
	t.Setenv("INFISICAL_CLIENT_ID", "client-id")
	t.Setenv("INFISICAL_CLIENT_SECRET", "")

	ref := secrets.SecretRef{
		Name:     "my-secret",
		Provider: "infisical",
		Params:   map[string]string{},
	}

	_, err := resolveSecretOnDemand(context.Background(), ref)
	if err == nil {
		t.Fatal("expected error for mismatched Infisical credentials")
	}
	if !strings.Contains(err.Error(), "must both be set") {
		t.Errorf("error = %q, want contains 'must both be set'", err.Error())
	}
}

func TestRunExec_InvalidDiscoveredConfigDoesNotFallback(t *testing.T) {
	tmp := t.TempDir()
	origDir, _ := os.Getwd()
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	cfgPath := filepath.Join(tmp, "agentcontainer.json")
	if err := os.WriteFile(cfgPath, []byte("{invalid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	restoreExecRuntimeFactory(t, func(string, *zap.Logger, enforcement.Level) (container.Runtime, error) {
		return &recordingRuntime{}, nil
	})

	cmd := newExecCmd()
	err := runExec(cmd, "abc123", []string{"ls"}, "docker", "", nil, false)
	if err == nil {
		t.Fatal("expected config parse error")
	}
	if !strings.Contains(err.Error(), "parsing agentcontainer.json") {
		t.Fatalf("expected parse error, got %v", err)
	}
	if strings.Contains(err.Error(), "denied") {
		t.Fatalf("expected parse error, got fallback denial: %v", err)
	}
}

func TestRunExec_BareEnvUsesHostValue(t *testing.T) {
	t.Setenv("INHERITED_KEY", "expected-value")

	cfgPath := writeExecConfig(t, `{
		"name": "test",
		"image": "ubuntu",
		"agent": {
			"capabilities": {
				"shell": {
					"commands": [{"binary": "env"}]
				}
			},
			"policy": {
				"escalation": "allow"
			}
		}
	}`)

	rt := &recordingRuntime{
		execResult: &container.ExecResult{ExitCode: 0},
	}
	restoreExecRuntimeFactory(t, func(string, *zap.Logger, enforcement.Level) (container.Runtime, error) {
		return rt, nil
	})

	cmd := newExecCmd()
	if err := runExec(cmd, "abc123", []string{"printenv", "INHERITED_KEY"}, "docker", cfgPath, []string{"INHERITED_KEY"}, false); err != nil {
		t.Fatalf("runExec() error = %v", err)
	}

	want := []string{"env", "INHERITED_KEY=expected-value", "printenv", "INHERITED_KEY"}
	if !reflect.DeepEqual(rt.execCmd, want) {
		t.Fatalf("exec cmd = %v, want %v", rt.execCmd, want)
	}
}

func TestRunExec_BareEnvMissingHostValueErrors(t *testing.T) {
	cfgPath := writeExecConfig(t, `{
		"name": "test",
		"image": "ubuntu",
		"agent": {
			"capabilities": {
				"shell": {
					"commands": [{"binary": "env"}]
				}
			},
			"policy": {
				"escalation": "allow"
			}
		}
	}`)

	restoreExecRuntimeFactory(t, func(string, *zap.Logger, enforcement.Level) (container.Runtime, error) {
		return &recordingRuntime{}, nil
	})

	cmd := newExecCmd()
	err := runExec(cmd, "abc123", []string{"printenv", "MISSING_KEY"}, "docker", cfgPath, []string{"MISSING_KEY"}, false)
	if err == nil {
		t.Fatal("expected missing env error")
	}
	if !strings.Contains(err.Error(), `environment variable "MISSING_KEY" is not set`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

type recordingRuntime struct {
	execCmd    []string
	execResult *container.ExecResult
	startErr   error
}

func (r *recordingRuntime) Start(context.Context, *config.AgentContainer, container.StartOptions) (*container.Session, error) {
	if r.startErr != nil {
		return nil, r.startErr
	}
	return &container.Session{ContainerID: "session-123", RuntimeType: container.RuntimeDocker}, nil
}

func (r *recordingRuntime) Stop(context.Context, *container.Session) error { return nil }

func (r *recordingRuntime) Exec(_ context.Context, _ *container.Session, cmd []string) (*container.ExecResult, error) {
	r.execCmd = append([]string(nil), cmd...)
	if r.execResult != nil {
		return r.execResult, nil
	}
	return &container.ExecResult{ExitCode: 0}, nil
}

func (r *recordingRuntime) Logs(context.Context, *container.Session) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader("")), nil
}

func (r *recordingRuntime) List(context.Context, bool) ([]*container.Session, error) { return nil, nil }

func restoreExecRuntimeFactory(t *testing.T, fn func(string, *zap.Logger, enforcement.Level) (container.Runtime, error)) {
	t.Helper()
	prev := execRuntimeFactory
	execRuntimeFactory = fn
	t.Cleanup(func() {
		execRuntimeFactory = prev
	})
}

func writeExecConfig(t *testing.T, contents string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "agentcontainer.json")
	if err := os.WriteFile(path, []byte(contents), 0o644); err != nil {
		t.Fatalf("write config: %v", err)
	}
	return path
}
