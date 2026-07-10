package approval

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"sync"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
)

// mockRuntime is a minimal container.Runtime for testing the broker.
type mockRuntime struct {
	execResult *container.ExecResult
	execErr    error
	execCalls  [][]string
}

func (m *mockRuntime) Start(_ context.Context, _ *config.AgentContainer, _ container.StartOptions) (*container.Session, error) {
	return &container.Session{ContainerID: "mock-id", RuntimeType: container.RuntimeDocker}, nil
}

func (m *mockRuntime) Stop(_ context.Context, _ *container.Session) error {
	return nil
}

func (m *mockRuntime) Exec(_ context.Context, _ *container.Session, cmd []string) (*container.ExecResult, error) {
	m.execCalls = append(m.execCalls, cmd)
	if m.execErr != nil {
		return nil, m.execErr
	}
	if m.execResult != nil {
		return m.execResult, nil
	}
	return &container.ExecResult{ExitCode: 0}, nil
}

func (m *mockRuntime) Logs(_ context.Context, _ *container.Session) (io.ReadCloser, error) {
	return io.NopCloser(&bytes.Buffer{}), nil
}

func (m *mockRuntime) List(_ context.Context, _ bool) ([]*container.Session, error) {
	return nil, nil
}

func TestBroker_Exec_PreApprovedCommand(t *testing.T) {
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "git"}},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0, Stdout: []byte("ok")}}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}
	result, err := broker.Exec(context.Background(), session, []string{"git", "status"})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("Exec() exit code = %d, want 0", result.ExitCode)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
	if strings.Contains(out.String(), "Capability Request") {
		t.Error("should not prompt for pre-approved command")
	}
}

func TestBroker_Exec_DeniedCommand(t *testing.T) {
	in := strings.NewReader("d\n")
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", nil)

	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}
	_, err := broker.Exec(context.Background(), session, []string{"rm", "-rf", "/"})
	if err == nil {
		t.Fatal("expected error for denied command")
	}
	if !strings.Contains(err.Error(), "denied by capability policy") {
		t.Errorf("expected 'denied by capability policy' in error, got: %v", err)
	}
	if len(mock.execCalls) != 0 {
		t.Errorf("expected 0 exec calls after denial, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_DeniedCommand_WithOtherBaseline(t *testing.T) {
	// Baseline allows "git" but NOT "rm". rm must still be denied.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "git"}},
		},
	}

	in := strings.NewReader("d\n")
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}
	_, err := broker.Exec(context.Background(), session, []string{"rm", "-rf", "/"})
	if err == nil {
		t.Fatal("expected error: baseline allows git but not rm")
	}
	if !strings.Contains(err.Error(), "denied by capability policy") {
		t.Errorf("expected 'denied by capability policy' in error, got: %v", err)
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime should not have been called for denied command")
	}
}

func TestBroker_Exec_ApprovedOnce(t *testing.T) {
	in := strings.NewReader("o\n")
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", nil)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}
	result, err := broker.Exec(context.Background(), session, []string{"npm", "install"})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("Exec() exit code = %d, want 0", result.ExitCode)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_ApprovedSession(t *testing.T) {
	in := strings.NewReader("s\n")
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", nil)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}

	// First exec: prompts and approves for session.
	_, err := broker.Exec(context.Background(), session, []string{"npm", "install"})
	if err != nil {
		t.Fatalf("first Exec() error: %v", err)
	}

	// Second exec with same binary: should not prompt.
	out2 := &bytes.Buffer{}
	mgr.approver = NewTerminalApprover(WithOutput(out2))

	_, err = broker.Exec(context.Background(), session, []string{"npm", "test"})
	if err != nil {
		t.Fatalf("second Exec() error: %v", err)
	}
	if strings.Contains(out2.String(), "Capability Request") {
		t.Error("should not prompt for session-approved command")
	}
	if len(mock.execCalls) != 2 {
		t.Errorf("expected 2 exec calls, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_NilManager(t *testing.T) {
	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, nil)

	session := &container.Session{ContainerID: "test-id"}
	result, err := broker.Exec(context.Background(), session, []string{"any", "command"})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("Exec() exit code = %d, want 0", result.ExitCode)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call with nil manager, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_EmptyCommand(t *testing.T) {
	mock := &mockRuntime{}
	broker := NewBroker(mock, nil)

	session := &container.Session{ContainerID: "test-id"}
	_, err := broker.Exec(context.Background(), session, []string{})
	if err == nil {
		t.Fatal("expected error for empty command, got nil")
	}
	if !strings.Contains(err.Error(), "empty command rejected") {
		t.Errorf("expected 'empty command rejected' in error, got: %v", err)
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime should not have been called for empty command")
	}
}

func TestBroker_Exec_DenyArgs(t *testing.T) {
	// Baseline allows git with clone/pull subcommands and denies --force.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{
				{Binary: "git", Subcommands: []string{"clone", "pull", "push"}, DenyArgs: []string{"--force"}},
			},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	// git push --force should be denied by DenyArgs.
	_, err := broker.Exec(context.Background(), session, []string{"git", "push", "--force"})
	if err == nil {
		t.Fatal("expected error for denied arg --force, got nil")
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime should not execute command with denied arg")
	}
}

func TestBroker_Exec_SubcommandRestriction(t *testing.T) {
	// Baseline allows git with only clone/pull subcommands.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{
				{Binary: "git", Subcommands: []string{"clone", "pull"}},
			},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	// git clone should be allowed.
	_, err := broker.Exec(context.Background(), session, []string{"git", "clone", "https://example.com/repo"})
	if err != nil {
		t.Fatalf("git clone should be allowed: %v", err)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call for git clone, got %d", len(mock.execCalls))
	}

	// git push is NOT in Subcommands, should be denied.
	_, err = broker.Exec(context.Background(), session, []string{"git", "push", "origin", "main"})
	if err == nil {
		t.Fatal("expected error for git push (not in allowed subcommands)")
	}
	if len(mock.execCalls) != 1 {
		t.Error("runtime should not execute disallowed subcommand")
	}
}

func TestBroker_Exec_ArgumentInjection(t *testing.T) {
	// Regression test: git allowed, but attacker passes pager injection.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{
				{Binary: "git", DenyArgs: []string{"-c"}},
			},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	// Attempted pager injection via git -c.
	_, err := broker.Exec(context.Background(), session, []string{"git", "-c", "core.pager=curl attacker.com", "log"})
	if err == nil {
		t.Fatal("expected error for git -c argument injection")
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime should not execute command with denied -c arg")
	}
}

func TestBroker_Exec_FullPathBinary(t *testing.T) {
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "git"}},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}
	_, err := broker.Exec(context.Background(), session, []string{"/usr/bin/git", "log"})
	if err != nil {
		t.Fatalf("Exec() error: %v", err)
	}
	if strings.Contains(out.String(), "Capability Request") {
		t.Error("should not prompt for pre-approved binary invoked with full path")
	}
}

func TestBroker_Exec_NonInteractiveMode(t *testing.T) {
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithNonInteractive(true), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", nil)

	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}
	_, err := broker.Exec(context.Background(), session, []string{"curl", "http://evil.com"})
	if err == nil {
		t.Fatal("expected error in non-interactive mode with no baseline")
	}
	if !strings.Contains(err.Error(), "denied by capability policy") {
		t.Errorf("expected 'denied by capability policy' in error, got: %v", err)
	}
}

func TestBroker_DelegatesStartStopLogs(t *testing.T) {
	mock := &mockRuntime{}
	broker := NewBroker(mock, nil)

	ctx := context.Background()

	session, err := broker.Start(ctx, &config.AgentContainer{Image: "test"}, container.StartOptions{})
	if err != nil {
		t.Fatalf("Start() error: %v", err)
	}
	if session.ContainerID != "mock-id" {
		t.Errorf("Start() container ID = %q, want %q", session.ContainerID, "mock-id")
	}

	if err := broker.Stop(ctx, session); err != nil {
		t.Fatalf("Stop() error: %v", err)
	}

	reader, err := broker.Logs(ctx, session)
	if err != nil {
		t.Fatalf("Logs() error: %v", err)
	}
	_ = reader.Close()
}

// --- Adversarial security tests ---
// These tests validate DENIAL paths, not just happy paths. A test that only
// checks "allowed command works" creates false confidence — what matters for
// security is that disallowed commands are REJECTED.

func TestBroker_Exec_FullPathDifferentBinary_Denied(t *testing.T) {
	// T-CRIT-05: extractBinary uses filepath.Base, so /usr/bin/curl becomes
	// "curl". When baseline only allows "git", curl must be denied even when
	// invoked with an absolute path.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "git"}},
		},
	}

	in := strings.NewReader("d\n")
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	// /usr/bin/curl should be denied: basename "curl" != "git".
	_, err := broker.Exec(context.Background(), session, []string{"/usr/bin/curl", "http://evil.com"})
	if err == nil {
		t.Fatal("expected error: /usr/bin/curl should be denied when only git is allowed")
	}
	if !strings.Contains(err.Error(), "denied by capability policy") {
		t.Errorf("expected denial error, got: %v", err)
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime must not execute denied binary even with absolute path")
	}
}

func TestBroker_Exec_SameNameDifferentPath_Allowed(t *testing.T) {
	// Counterpart to above: /tmp/git should still be allowed because
	// extractBinary("/tmp/git") == "git" and baseline allows "git".
	// This is intentional behavior (basename matching), not a bug.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "git"}},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	// /tmp/git is allowed because basename matches. This is a known
	// limitation of M0 basename matching — M3 will use inode-based checks.
	_, err := broker.Exec(context.Background(), session, []string{"/tmp/git", "status"})
	if err != nil {
		t.Fatalf("Exec() error: %v (basename 'git' should match baseline)", err)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_PathTraversal_DeniedIfDifferentBinary(t *testing.T) {
	// Paths like "../../bin/bash" resolve to basename "bash" which should
	// not match "git".
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "git"}},
		},
	}

	in := strings.NewReader("d\n")
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"../../bin/bash", "-c", "curl evil.com"})
	if err == nil {
		t.Fatal("expected error: ../../bin/bash basename is 'bash', not 'git'")
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime must not execute path-traversal binary that doesn't match allowlist")
	}
}

func TestManager_Check_FilesystemPathLevel_Denial(t *testing.T) {
	// Path-level enforcement: approving /workspace/** must NOT approve /etc/passwd.
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithNonInteractive(true), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	req := Request{
		Category: "filesystem",
		Action:   "read /etc/passwd",
		Capability: &config.FilesystemCaps{
			Read: []string{"/etc/passwd"},
		},
	}

	// /etc/passwd is NOT under /workspace/**, so this must be denied.
	approved, _ := mgr.Check(req)
	if approved {
		t.Error("should deny /etc/passwd when baseline only allows /workspace/**")
	}
}

func TestManager_Check_NetworkHostLevel_Denial(t *testing.T) {
	// Host+port-level enforcement: approving api.github.com:443 must NOT approve evil.com:80.
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 443}},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithNonInteractive(true), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	req := Request{
		Category: "network",
		Action:   "connect to evil.com:80",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "evil.com", Port: 80}},
		},
	}

	// evil.com is NOT api.github.com, so this must be denied.
	approved, _ := mgr.Check(req)
	if approved {
		t.Error("should deny evil.com:80 when baseline only allows api.github.com:443")
	}
}

func TestExtractBinary(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"git", "git"},
		{"/usr/bin/git", "git"},
		{"/usr/local/bin/npm", "npm"},
		{"./script.sh", "script.sh"},
		{"../bin/tool", "tool"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := extractBinary(tt.input)
			if got != tt.want {
				t.Errorf("extractBinary(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- Fine-grained filesystem path matching tests ---

// nonInteractiveDenyApprover is a helper that returns a non-interactive approver
// which auto-denies any prompt. Used in tests where the check should either
// pass at the baseline level (never reaching the approver) or fall through
// to denial without requiring user input.
func nonInteractiveDenyApprover() Approver {
	return NewTerminalApprover(WithNonInteractive(true), WithOutput(&bytes.Buffer{}))
}

func TestManager_Check_FilesystemGlobMatch(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/home/*"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// /home/user matches /home/*
	req := Request{
		Category:   "filesystem",
		Action:     "read /home/user",
		Capability: &config.FilesystemCaps{Read: []string{"/home/user"}},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve /home/user against /home/* glob")
	}
}

func TestManager_Check_FilesystemDoubleStarGlob(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	tests := []struct {
		name     string
		path     string
		approved bool
	}{
		{"exact dir", "/workspace", true},
		{"direct child", "/workspace/file.go", true},
		{"nested deep", "/workspace/src/pkg/main.go", true},
		{"outside prefix", "/home/user/file.go", false},
		{"similar prefix", "/workspace2/file.go", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Request{
				Category:   "filesystem",
				Action:     "read " + tt.path,
				Capability: &config.FilesystemCaps{Read: []string{tt.path}},
			}
			got, _ := mgr.Check(req)
			if got != tt.approved {
				t.Errorf("path %q: approved=%v, want %v", tt.path, got, tt.approved)
			}
		})
	}
}

func TestManager_Check_FilesystemPrefixMatch(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/home/user"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// /home/user/project is under /home/user (prefix match).
	req := Request{
		Category:   "filesystem",
		Action:     "read /home/user/project",
		Capability: &config.FilesystemCaps{Read: []string{"/home/user/project"}},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve /home/user/project under /home/user prefix")
	}

	// /home/other is NOT under /home/user.
	req2 := Request{
		Category:   "filesystem",
		Action:     "read /home/other",
		Capability: &config.FilesystemCaps{Read: []string{"/home/other"}},
	}
	approved2, _ := mgr.Check(req2)
	if approved2 {
		t.Error("should deny /home/other (not under /home/user)")
	}
}

func TestManager_Check_FilesystemDenyTakesPrecedence(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
			Deny: []string{"/workspace/.env"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// Regular file under /workspace: allowed.
	req := Request{
		Category:   "filesystem",
		Action:     "read /workspace/main.go",
		Capability: &config.FilesystemCaps{Read: []string{"/workspace/main.go"}},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve /workspace/main.go")
	}

	// /workspace/.env is explicitly denied.
	reqDeny := Request{
		Category:   "filesystem",
		Action:     "read /workspace/.env",
		Capability: &config.FilesystemCaps{Read: []string{"/workspace/.env"}},
	}
	approvedDeny, _ := mgr.Check(reqDeny)
	if approvedDeny {
		t.Error("should deny /workspace/.env (explicit deny takes precedence)")
	}
}

func TestManager_Check_FilesystemWriteNotCoveredByRead(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// Write request is NOT covered by read-only allowlist.
	req := Request{
		Category:   "filesystem",
		Action:     "write /workspace/file.go",
		Capability: &config.FilesystemCaps{Write: []string{"/workspace/file.go"}},
	}
	approved, _ := mgr.Check(req)
	if approved {
		t.Error("should deny write when only read is allowed")
	}
}

func TestManager_Check_FilesystemReadCoveredByWrite(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Write: []string{"/workspace/**"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// Read request IS covered by write allowlist (write implies read).
	req := Request{
		Category:   "filesystem",
		Action:     "read /workspace/file.go",
		Capability: &config.FilesystemCaps{Read: []string{"/workspace/file.go"}},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve read when write is allowed (write implies read)")
	}
}

func TestManager_Check_FilesystemNilCapability(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// Nil capability should not be approved.
	req := Request{
		Category:   "filesystem",
		Action:     "read something",
		Capability: nil,
	}
	approved, _ := mgr.Check(req)
	if approved {
		t.Error("should deny when capability is nil")
	}
}

func TestManager_Check_FilesystemDenyGlob(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
			Deny: []string{"/workspace/secrets/**"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	req := Request{
		Category:   "filesystem",
		Action:     "read /workspace/secrets/key.pem",
		Capability: &config.FilesystemCaps{Read: []string{"/workspace/secrets/key.pem"}},
	}
	approved, _ := mgr.Check(req)
	if approved {
		t.Error("should deny /workspace/secrets/key.pem (matched by deny glob /workspace/secrets/**)")
	}
}

// --- Fine-grained network host+port matching tests ---

func TestManager_Check_NetworkExactHostMatch(t *testing.T) {
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 443}},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	req := Request{
		Category: "network",
		Action:   "connect to api.github.com:443",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 443}},
		},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve exact host+port match")
	}
}

func TestManager_Check_NetworkWrongPort(t *testing.T) {
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 443}},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	req := Request{
		Category: "network",
		Action:   "connect to api.github.com:80",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 80}},
		},
	}
	approved, _ := mgr.Check(req)
	if approved {
		t.Error("should deny api.github.com:80 when only :443 is allowed")
	}
}

func TestManager_Check_NetworkAnyPort(t *testing.T) {
	// Port 0 in baseline means any port is allowed for that host.
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 0}},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	req := Request{
		Category: "network",
		Action:   "connect to api.github.com:8080",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 8080}},
		},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve any port when baseline has port=0")
	}
}

func TestManager_Check_NetworkWildcardHost(t *testing.T) {
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "*.github.com", Port: 443}},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	tests := []struct {
		name     string
		host     string
		port     int
		approved bool
	}{
		{"subdomain match", "api.github.com", 443, true},
		{"another subdomain", "raw.github.com", 443, true},
		{"bare domain no match", "github.com", 443, false},
		{"wrong domain", "github.io", 443, false},
		{"wrong port", "api.github.com", 80, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := Request{
				Category: "network",
				Action:   "connect",
				Capability: &config.NetworkCaps{
					Egress: []config.EgressRule{{Host: tt.host, Port: tt.port}},
				},
			}
			got, _ := mgr.Check(req)
			if got != tt.approved {
				t.Errorf("host=%q port=%d: approved=%v, want %v", tt.host, tt.port, got, tt.approved)
			}
		})
	}
}

func TestManager_Check_NetworkDenyTakesPrecedence(t *testing.T) {
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "*.example.com", Port: 0}},
			Deny:   []string{"evil.example.com"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// Regular subdomain: allowed.
	req := Request{
		Category: "network",
		Action:   "connect to api.example.com:443",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.example.com", Port: 443}},
		},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve api.example.com")
	}

	// evil.example.com is explicitly denied.
	reqDeny := Request{
		Category: "network",
		Action:   "connect to evil.example.com:443",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "evil.example.com", Port: 443}},
		},
	}
	approvedDeny, _ := mgr.Check(reqDeny)
	if approvedDeny {
		t.Error("should deny evil.example.com (explicit deny takes precedence)")
	}
}

func TestManager_Check_NetworkDenyWildcard(t *testing.T) {
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "*", Port: 0}},
			Deny:   []string{"*.evil.com"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// good.com should be allowed.
	req := Request{
		Category: "network",
		Action:   "connect to good.com:443",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "good.com", Port: 443}},
		},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve good.com with wildcard baseline")
	}

	// sub.evil.com should be denied.
	reqDeny := Request{
		Category: "network",
		Action:   "connect to sub.evil.com:80",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "sub.evil.com", Port: 80}},
		},
	}
	approvedDeny, _ := mgr.Check(reqDeny)
	if approvedDeny {
		t.Error("should deny sub.evil.com (matched by deny wildcard *.evil.com)")
	}
}

func TestManager_Check_NetworkNilCapability(t *testing.T) {
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 443}},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	req := Request{
		Category:   "network",
		Action:     "connect",
		Capability: nil,
	}
	approved, _ := mgr.Check(req)
	if approved {
		t.Error("should deny when capability is nil")
	}
}

func TestManager_Check_NetworkCaseInsensitive(t *testing.T) {
	baseline := &config.Capabilities{
		Network: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "API.GitHub.COM", Port: 443}},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	req := Request{
		Category: "network",
		Action:   "connect to api.github.com:443",
		Capability: &config.NetworkCaps{
			Egress: []config.EgressRule{{Host: "api.github.com", Port: 443}},
		},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("host matching should be case-insensitive")
	}
}

// --- M3 interpreter bypass defense-in-depth tests ---

func TestBroker_Exec_InterpreterWithDashC_Blocked(t *testing.T) {
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "python3"}},
		},
	}

	in := strings.NewReader("d\n")
	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithInput(in), WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}
	_, err := broker.Exec(context.Background(), session, []string{"python3", "-c", "import os; os.system('rm -rf /')"})
	if err == nil {
		t.Fatal("expected error for interpreter with -c flag")
	}
	if !strings.Contains(err.Error(), "interpreter") {
		t.Errorf("expected 'interpreter' in error, got: %v", err)
	}
}

func TestBroker_Exec_InterpreterWithoutDashC_Allowed(t *testing.T) {
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "python3"}},
		},
	}

	out := &bytes.Buffer{}
	approver := NewTerminalApprover(WithOutput(out))
	mgr := NewManager(approver, "/dev/null", baseline)

	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)

	session := &container.Session{ContainerID: "test-id"}
	result, err := broker.Exec(context.Background(), session, []string{"python3", "script.py"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
}

// --- Unit tests for helper functions ---

func TestPathMatches(t *testing.T) {
	tests := []struct {
		name    string
		reqPath string
		pattern string
		want    bool
	}{
		{"exact match", "/home/user", "/home/user", true},
		{"glob star", "/home/user", "/home/*", true},
		{"double star child", "/workspace/file.go", "/workspace/**", true},
		{"double star nested", "/workspace/src/main.go", "/workspace/**", true},
		{"double star exact", "/workspace", "/workspace/**", true},
		{"prefix match", "/home/user/project/file", "/home/user", true},
		{"no match", "/etc/passwd", "/home/*", false},
		{"similar prefix no match", "/home_bad", "/home", false},
		{"similar doublestar no match", "/workspace2/file", "/workspace/**", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathMatches(tt.reqPath, tt.pattern)
			if got != tt.want {
				t.Errorf("pathMatches(%q, %q) = %v, want %v", tt.reqPath, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestHostMatches(t *testing.T) {
	tests := []struct {
		name    string
		host    string
		pattern string
		want    bool
	}{
		{"exact match", "api.github.com", "api.github.com", true},
		{"case insensitive", "API.GitHub.COM", "api.github.com", true},
		{"wildcard prefix", "api.github.com", "*.github.com", true},
		{"wildcard all", "anything.com", "*", true},
		{"no match", "evil.com", "api.github.com", false},
		{"bare domain vs wildcard", "github.com", "*.github.com", false},
		{"wrong suffix", "github.io", "*.github.com", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hostMatches(tt.host, tt.pattern)
			if got != tt.want {
				t.Errorf("hostMatches(%q, %q) = %v, want %v", tt.host, tt.pattern, got, tt.want)
			}
		})
	}
}

// =============================================================================
// Adversarial test suite
// =============================================================================

// mockApprover is a deterministic Approver for testing without terminal I/O.
type mockApprover struct {
	response Response
	err      error
	calls    int
}

func (m *mockApprover) Prompt(_ Request) (Response, error) {
	m.calls++
	return m.response, m.err
}

// --- extractBinary adversarial edge cases ---

func TestExtractBinary_Adversarial(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		// Path traversal
		{"deep traversal", "../../bin/sh", "sh"},
		{"triple traversal", "../../../usr/bin/python", "python"},

		// Absolute paths
		{"absolute usr bin", "/usr/bin/git", "git"},
		{"absolute bin sh", "/bin/sh", "sh"},
		{"absolute sbin", "/sbin/iptables", "iptables"},

		// Just binary name
		{"bare binary", "git", "git"},
		{"bare python", "python", "python"},

		// Relative with dot
		{"dot slash", "./script.sh", "script.sh"},
		{"dot slash nested", "./bin/tool", "tool"},

		// Unicode / homoglyph names (Cyrillic 'a' = U+0430)
		{"cyrillic homoglyph", "/usr/bin/pyth\u043en", "pyth\u043en"},

		// Null byte in path (filepath.Base handles this gracefully on most OS)
		{"null byte", "python\x00--version", "python\x00--version"},

		// Whitespace in binary name
		{"trailing space", "git ", "git "},
		{"leading space in path", " /usr/bin/git", "git"},

		// Empty path edge case (filepath.Base("") returns ".")
		{"empty string", "", "."},

		// Trailing slash
		{"trailing slash", "/usr/bin/", "bin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractBinary(tt.input)
			if got != tt.want {
				t.Errorf("extractBinary(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// --- M3 interpreter blocking: all 7 interpreters x {-c, -e} ---

func TestBroker_Exec_AllInterpreters_DashC_Blocked(t *testing.T) {
	interpreters := []string{"python", "python3", "node", "ruby", "perl", "bash", "sh"}

	for _, interp := range interpreters {
		t.Run(interp, func(t *testing.T) {
			baseline := &config.Capabilities{
				Shell: &config.ShellCaps{
					Commands: []config.ShellCommand{{Binary: interp}},
				},
			}
			mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
			mock := &mockRuntime{}
			broker := NewBroker(mock, mgr)
			session := &container.Session{ContainerID: "test-id"}

			_, err := broker.Exec(context.Background(), session, []string{interp, "-c", "malicious code"})
			if err == nil {
				t.Fatalf("%s -c should be blocked", interp)
			}
			if !strings.Contains(err.Error(), "interpreter") {
				t.Errorf("expected 'interpreter' in error, got: %v", err)
			}
			if !strings.Contains(err.Error(), "-c") {
				t.Errorf("expected '-c' in error, got: %v", err)
			}
			if len(mock.execCalls) != 0 {
				t.Errorf("runtime should not be called for blocked interpreter")
			}
		})
	}
}

func TestBroker_Exec_AllInterpreters_DashE_Blocked(t *testing.T) {
	interpreters := []string{"python", "python3", "node", "ruby", "perl", "bash", "sh"}

	for _, interp := range interpreters {
		t.Run(interp, func(t *testing.T) {
			baseline := &config.Capabilities{
				Shell: &config.ShellCaps{
					Commands: []config.ShellCommand{{Binary: interp}},
				},
			}
			mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
			mock := &mockRuntime{}
			broker := NewBroker(mock, mgr)
			session := &container.Session{ContainerID: "test-id"}

			_, err := broker.Exec(context.Background(), session, []string{interp, "-e", "malicious code"})
			if err == nil {
				t.Fatalf("%s -e should be blocked", interp)
			}
			if !strings.Contains(err.Error(), "interpreter") {
				t.Errorf("expected 'interpreter' in error, got: %v", err)
			}
			if len(mock.execCalls) != 0 {
				t.Errorf("runtime should not be called for blocked interpreter")
			}
		})
	}
}

func TestBroker_Exec_InterpreterWithoutCodeFlag_Allowed(t *testing.T) {
	// Interpreters invoked without -c or -e (e.g., running a script file)
	// should be allowed through if the binary is in the allowlist.
	interpreters := []string{"python", "python3", "node", "ruby", "perl", "bash", "sh"}

	for _, interp := range interpreters {
		t.Run(interp, func(t *testing.T) {
			baseline := &config.Capabilities{
				Shell: &config.ShellCaps{
					Commands: []config.ShellCommand{{Binary: interp}},
				},
			}
			mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
			mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
			broker := NewBroker(mock, mgr)
			session := &container.Session{ContainerID: "test-id"}

			_, err := broker.Exec(context.Background(), session, []string{interp, "script.py"})
			if err != nil {
				t.Fatalf("unexpected error for %s without code flag: %v", interp, err)
			}
			if len(mock.execCalls) != 1 {
				t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
			}
		})
	}
}

func TestBroker_Exec_InterpreterDashC_ThirdArg_Allowed(t *testing.T) {
	// M3 check only looks at cmd[1]. If -c appears as cmd[2] or later,
	// it should NOT be blocked by the interpreter defense.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "python"}},
		},
	}
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	// -c is at position [2], not [1] -- should be allowed.
	_, err := broker.Exec(context.Background(), session, []string{"python", "script.py", "-c", "config_file"})
	if err != nil {
		t.Fatalf("unexpected error: -c at position [2] should not trigger M3 block: %v", err)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_InterpreterMixedCase_PassesThrough(t *testing.T) {
	// The interpreter map is case-sensitive. "Python", "PYTHON", etc. are NOT
	// in knownInterpreters and should pass through to the manager.
	cases := []string{"Python", "PYTHON", "Node", "BASH", "SH", "Perl", "Ruby"}

	for _, interp := range cases {
		t.Run(interp, func(t *testing.T) {
			baseline := &config.Capabilities{
				Shell: &config.ShellCaps{
					Commands: []config.ShellCommand{{Binary: interp}},
				},
			}
			mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
			mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
			broker := NewBroker(mock, mgr)
			session := &container.Session{ContainerID: "test-id"}

			// Mixed-case interpreter with -c: not in knownInterpreters map,
			// so M3 check does not fire. It proceeds to the manager.
			_, err := broker.Exec(context.Background(), session, []string{interp, "-c", "code"})
			if err != nil {
				t.Fatalf("mixed-case %q should not be blocked by M3: %v", interp, err)
			}
			if len(mock.execCalls) != 1 {
				t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
			}
		})
	}
}

func TestBroker_Exec_VersionedInterpreter_PassesThrough(t *testing.T) {
	// "python3.11", "node18" etc. are not in knownInterpreters and should
	// not be blocked by M3.
	versioned := []string{"python3.11", "python3.12", "node18", "node20", "ruby3.2", "perl5.38"}

	for _, interp := range versioned {
		t.Run(interp, func(t *testing.T) {
			baseline := &config.Capabilities{
				Shell: &config.ShellCaps{
					Commands: []config.ShellCommand{{Binary: interp}},
				},
			}
			mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
			mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
			broker := NewBroker(mock, mgr)
			session := &container.Session{ContainerID: "test-id"}

			_, err := broker.Exec(context.Background(), session, []string{interp, "-c", "code"})
			if err != nil {
				t.Fatalf("versioned %q should not be blocked by M3: %v", interp, err)
			}
			if len(mock.execCalls) != 1 {
				t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
			}
		})
	}
}

func TestBroker_Exec_InterpreterWithPath_DashC_Blocked(t *testing.T) {
	// /usr/bin/python with -c: extractBinary returns "python", which IS in
	// knownInterpreters, so it must be blocked.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "python"}},
		},
	}
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"/usr/bin/python", "-c", "import os"})
	if err == nil {
		t.Fatal("/usr/bin/python -c should be blocked (basename = python)")
	}
	if !strings.Contains(err.Error(), "interpreter") {
		t.Errorf("expected 'interpreter' in error, got: %v", err)
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime should not be called")
	}
}

func TestBroker_Exec_InterpreterEmptyArgs_Allowed(t *testing.T) {
	// python "" -- args[1] is empty string, not "-c", so M3 check should pass.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "python"}},
		},
	}
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"python", ""})
	if err != nil {
		t.Fatalf("python with empty arg should not be blocked: %v", err)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_InterpreterSingleArg_Allowed(t *testing.T) {
	// Single-element command ["python"] has no args, so M3 check should pass
	// (len(cmd) > 1 is false).
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "python"}},
		},
	}
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"python"})
	if err != nil {
		t.Fatalf("bare 'python' without args should not be blocked: %v", err)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

// --- Exec flow with mock approver ---

func TestBroker_Exec_ManagerCheckError_Propagated(t *testing.T) {
	sentinel := errors.New("approver broke")
	mgr := NewManager(&mockApprover{err: sentinel}, "/dev/null", nil)
	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"git", "status"})
	if err == nil {
		t.Fatal("expected error when manager.Check returns error")
	}
	if !strings.Contains(err.Error(), "approver broke") {
		t.Errorf("expected sentinel error in chain, got: %v", err)
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime should not be called when manager errors")
	}
}

func TestBroker_Exec_ManagerDenies_ReturnsError(t *testing.T) {
	mgr := NewManager(&mockApprover{response: Deny}, "/dev/null", nil)
	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"curl", "http://evil.com"})
	if err == nil {
		t.Fatal("expected error when manager denies")
	}
	if !strings.Contains(err.Error(), "denied by capability policy") {
		t.Errorf("expected denial error, got: %v", err)
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime should not be called after denial")
	}
}

func TestBroker_Exec_ManagerApproves_DelegatesToRuntime(t *testing.T) {
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", nil)
	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 42, Stdout: []byte("hello")}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	result, err := broker.Exec(context.Background(), session, []string{"custom-tool", "--flag"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.ExitCode != 42 {
		t.Errorf("exit code = %d, want 42", result.ExitCode)
	}
	if string(result.Stdout) != "hello" {
		t.Errorf("stdout = %q, want %q", result.Stdout, "hello")
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_NilCmd_ReturnsError(t *testing.T) {
	mock := &mockRuntime{}
	broker := NewBroker(mock, nil)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, nil)
	if err == nil {
		t.Fatal("expected error for nil command")
	}
	if !strings.Contains(err.Error(), "empty command rejected") {
		t.Errorf("expected 'empty command rejected', got: %v", err)
	}
}

// --- Shell metacharacter injection ---
// These commands should pass through to the broker/manager without special
// handling. The broker does basename extraction and approval; it is the
// runtime's responsibility to handle metacharacters safely.

func TestBroker_Exec_ShellMetacharacters_PassThrough(t *testing.T) {
	tests := []struct {
		name string
		cmd  []string
	}{
		{"semicolon", []string{"git", "log", "; rm -rf /"}},
		{"pipe", []string{"git", "log", "| cat /etc/passwd"}},
		{"and chain", []string{"git", "log", "&& curl evil.com"}},
		{"or chain", []string{"git", "log", "|| curl evil.com"}},
		{"backtick", []string{"git", "log", "`curl evil.com`"}},
		{"dollar paren", []string{"git", "log", "$(curl evil.com)"}},
		{"redirect out", []string{"git", "log", "> /etc/passwd"}},
		{"redirect in", []string{"git", "log", "< /etc/shadow"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseline := &config.Capabilities{
				Shell: &config.ShellCaps{
					Commands: []config.ShellCommand{{Binary: "git"}},
				},
			}
			mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
			mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
			broker := NewBroker(mock, mgr)
			session := &container.Session{ContainerID: "test-id"}

			// The broker should NOT parse or reject shell metacharacters.
			// It passes the command slice through to the runtime as-is.
			result, err := broker.Exec(context.Background(), session, tt.cmd)
			if err != nil {
				t.Fatalf("broker should pass metacharacters through, got error: %v", err)
			}
			if result.ExitCode != 0 {
				t.Errorf("exit code = %d, want 0", result.ExitCode)
			}
			if len(mock.execCalls) != 1 {
				t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
			}
			// Verify the full command was passed to runtime unmodified.
			for i, arg := range tt.cmd {
				if mock.execCalls[0][i] != arg {
					t.Errorf("arg[%d] = %q, want %q", i, mock.execCalls[0][i], arg)
				}
			}
		})
	}
}

// --- Escalation policy tests ---

func TestBroker_Exec_EscalationDeny_BlocksEverything(t *testing.T) {
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", nil, WithEscalation("deny"))
	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"ls"})
	if err == nil {
		t.Fatal("expected error with escalation=deny")
	}
	if !strings.Contains(err.Error(), "denied by capability policy") {
		t.Errorf("expected denial error, got: %v", err)
	}
}

func TestBroker_Exec_EscalationDeny_AllowsBaseline(t *testing.T) {
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "cat"}},
		},
	}
	mgr := NewManager(&mockApprover{response: Deny}, "/dev/null", baseline, WithEscalation("deny"))
	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0, Stdout: []byte("ok\n")}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	result, err := broker.Exec(context.Background(), session, []string{"cat", "/workspace/file"})
	if err != nil {
		t.Fatalf("baseline command should be allowed with escalation=deny: %v", err)
	}
	if result.ExitCode != 0 {
		t.Errorf("exit code = %d, want 0", result.ExitCode)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

func TestBroker_Exec_EscalationAllow_BypassesApproval(t *testing.T) {
	mgr := NewManager(&mockApprover{response: Deny}, "/dev/null", nil, WithEscalation("allow"))
	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"rm", "-rf", "/"})
	if err != nil {
		t.Fatalf("escalation=allow should bypass approval: %v", err)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

// --- Path traversal with interpreter blocking ---

func TestBroker_Exec_PathTraversal_Interpreter_Blocked(t *testing.T) {
	// ../../bin/python with -c: extractBinary returns "python" which is a
	// known interpreter. Must be blocked by M3 defense.
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "python"}},
		},
	}
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"../../bin/python", "-c", "import os"})
	if err == nil {
		t.Fatal("../../bin/python -c should be blocked (basename = python)")
	}
	if !strings.Contains(err.Error(), "interpreter") {
		t.Errorf("expected 'interpreter' in error, got: %v", err)
	}
}

// --- Unicode homoglyph interpreter bypass attempt ---

func TestBroker_Exec_HomoglyphInterpreter_NotBlocked(t *testing.T) {
	// Using Cyrillic 'o' (U+043E) instead of Latin 'o' in "node" produces
	// "n\u043ede" which is NOT in knownInterpreters. This is a known
	// limitation documented as M3 -- BPF process enforcer handles inodes.
	homoglyphNode := "n\u043ede" // Cyrillic 'o'
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: homoglyphNode}},
		},
	}
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
	mock := &mockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	// Should NOT be blocked by M3 (not in the map), but passes through
	// to manager approval.
	_, err := broker.Exec(context.Background(), session, []string{homoglyphNode, "-c", "code"})
	if err != nil {
		t.Fatalf("homoglyph %q should not trigger M3 block: %v", homoglyphNode, err)
	}
	if len(mock.execCalls) != 1 {
		t.Errorf("expected 1 exec call, got %d", len(mock.execCalls))
	}
}

// --- M3 interpreter block fires BEFORE manager check ---

func TestBroker_Exec_InterpreterBlock_BeforeManagerCheck(t *testing.T) {
	// Even with escalation=allow, interpreter -c should be blocked because
	// the M3 check runs before the manager is consulted.
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", nil, WithEscalation("allow"))
	mock := &mockRuntime{}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	_, err := broker.Exec(context.Background(), session, []string{"bash", "-c", "curl evil.com"})
	if err == nil {
		t.Fatal("M3 interpreter block should fire even with escalation=allow")
	}
	if !strings.Contains(err.Error(), "interpreter") {
		t.Errorf("expected 'interpreter' in error, got: %v", err)
	}
	if len(mock.execCalls) != 0 {
		t.Error("runtime should never be called for blocked interpreter")
	}
}

// --- Concurrent exec safety ---

// syncMockRuntime is a thread-safe version of mockRuntime for concurrency tests.
type syncMockRuntime struct {
	mu         sync.Mutex
	execResult *container.ExecResult
	callCount  int
}

func (m *syncMockRuntime) Start(_ context.Context, _ *config.AgentContainer, _ container.StartOptions) (*container.Session, error) {
	return &container.Session{ContainerID: "mock-id"}, nil
}
func (m *syncMockRuntime) Stop(_ context.Context, _ *container.Session) error { return nil }
func (m *syncMockRuntime) Exec(_ context.Context, _ *container.Session, _ []string) (*container.ExecResult, error) {
	m.mu.Lock()
	m.callCount++
	m.mu.Unlock()
	return m.execResult, nil
}
func (m *syncMockRuntime) Logs(_ context.Context, _ *container.Session) (io.ReadCloser, error) {
	return io.NopCloser(&bytes.Buffer{}), nil
}
func (m *syncMockRuntime) List(_ context.Context, _ bool) ([]*container.Session, error) {
	return nil, nil
}

func TestBroker_Exec_Concurrent(t *testing.T) {
	baseline := &config.Capabilities{
		Shell: &config.ShellCaps{
			Commands: []config.ShellCommand{{Binary: "git"}},
		},
	}
	mgr := NewManager(&mockApprover{response: AllowOnce}, "/dev/null", baseline)
	mock := &syncMockRuntime{execResult: &container.ExecResult{ExitCode: 0}}
	broker := NewBroker(mock, mgr)
	session := &container.Session{ContainerID: "test-id"}

	errc := make(chan error, 20)
	for i := 0; i < 20; i++ {
		go func() {
			_, err := broker.Exec(context.Background(), session, []string{"git", "status"})
			errc <- err
		}()
	}

	for i := 0; i < 20; i++ {
		if err := <-errc; err != nil {
			t.Errorf("concurrent exec %d failed: %v", i, err)
		}
	}

	mock.mu.Lock()
	count := mock.callCount
	mock.mu.Unlock()
	if count != 20 {
		t.Errorf("expected 20 exec calls, got %d", count)
	}
}

// =============================================================================
// Filesystem path matching: adversarial & edge-case tests
// =============================================================================

func TestPathMatches_Adversarial(t *testing.T) {
	tests := []struct {
		name    string
		reqPath string
		pattern string
		want    bool
	}{
		// Path traversal attacks
		{"traversal escapes workspace", "/workspace/../etc/passwd", "/workspace/**", false},
		{"deep traversal", "/workspace/../../etc/shadow", "/workspace/**", false},
		{"traversal resolves inside", "/workspace/src/../src/main.go", "/workspace/**", true},
		{"bare traversal", "../../etc/passwd", "/workspace/**", false},
		{"traversal with dot prefix", "./../../etc/passwd", "/workspace/**", false},

		// Traversal against deny patterns: deny must still catch traversed paths
		{"traversal hits deny target", "/workspace/secrets/../secrets/key.pem", "/workspace/secrets/**", true},

		// Null bytes (filepath.Clean preserves them; the path should not match
		// patterns that don't contain null bytes)
		{"null byte in path", "/workspace/file\x00.go", "/workspace/**", true}, // Clean keeps it under /workspace/
		{"null byte breaks prefix", "/etc\x00/workspace/file", "/workspace/**", false},

		// Trailing slashes and dots
		{"trailing slash", "/workspace/", "/workspace/**", true},
		{"trailing dot", "/workspace/.", "/workspace/**", true},
		{"double trailing slash", "/workspace//file.go", "/workspace/**", true},

		// Empty and root paths
		{"empty request path", "", "/workspace/**", false},
		{"root path", "/", "/workspace/**", false},

		// Pattern edge cases
		{"empty pattern", "/workspace/file.go", "", false},
		{"root pattern", "/workspace/file.go", "/", false},
		{"dot pattern", "/workspace/file.go", ".", false},

		// Prefix confusion (similar names)
		{"workspace-evil prefix", "/workspace-evil/steal.sh", "/workspace/**", false},
		{"workspaces prefix", "/workspaces/file", "/workspace/**", false},

		// Case sensitivity (filesystem paths are case-sensitive on Linux)
		{"case mismatch", "/Workspace/file.go", "/workspace/**", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathMatches(tt.reqPath, tt.pattern)
			if got != tt.want {
				t.Errorf("pathMatches(%q, %q) = %v, want %v", tt.reqPath, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestFilesystemPathApproved_DenyPrecedence(t *testing.T) {
	// Deny patterns must ALWAYS take precedence over allow patterns,
	// even when the allow pattern is more specific.
	tests := []struct {
		name     string
		allow    []string
		deny     []string
		reqPath  string
		approved bool
	}{
		{
			name:     "deny blocks allowed path",
			allow:    []string{"/workspace/**"},
			deny:     []string{"/workspace/.env"},
			reqPath:  "/workspace/.env",
			approved: false,
		},
		{
			name:     "deny glob blocks subtree",
			allow:    []string{"/workspace/**"},
			deny:     []string{"/workspace/secrets/**"},
			reqPath:  "/workspace/secrets/api-key.txt",
			approved: false,
		},
		{
			name:     "deny blocks exact despite broader allow",
			allow:    []string{"/"},
			deny:     []string{"/etc/shadow"},
			reqPath:  "/etc/shadow",
			approved: false,
		},
		{
			name:     "non-denied path still allowed",
			allow:    []string{"/workspace/**"},
			deny:     []string{"/workspace/.env"},
			reqPath:  "/workspace/main.go",
			approved: true,
		},
		{
			name:     "deny with traversal normalized",
			allow:    []string{"/workspace/**"},
			deny:     []string{"/workspace/secrets/**"},
			reqPath:  "/workspace/./secrets/key.pem",
			approved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			baseline := &config.Capabilities{
				Filesystem: &config.FilesystemCaps{
					Read: tt.allow,
					Deny: tt.deny,
				},
			}
			mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)
			req := Request{
				Category:   "filesystem",
				Action:     "read " + tt.reqPath,
				Capability: &config.FilesystemCaps{Read: []string{tt.reqPath}},
			}
			got, _ := mgr.Check(req)
			if got != tt.approved {
				t.Errorf("path %q (allow=%v, deny=%v): approved=%v, want %v",
					tt.reqPath, tt.allow, tt.deny, got, tt.approved)
			}
		})
	}
}

func TestFilesystemPathApproved_NoPathsRequestedDenied(t *testing.T) {
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read:  []string{"/workspace/**"},
			Write: []string{"/workspace/**"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// Empty read and write slices: should return false (line 295 of manager.go).
	req := Request{
		Category:   "filesystem",
		Action:     "read nothing",
		Capability: &config.FilesystemCaps{Read: []string{}, Write: []string{}},
	}
	approved, _ := mgr.Check(req)
	if approved {
		t.Error("empty request paths must return false")
	}

	// Nil slices in capability.
	reqNil := Request{
		Category:   "filesystem",
		Action:     "read nothing",
		Capability: &config.FilesystemCaps{},
	}
	approvedNil, _ := mgr.Check(reqNil)
	if approvedNil {
		t.Error("nil request paths must return false")
	}
}

func TestPathMatches_DoubleStarGlob(t *testing.T) {
	tests := []struct {
		name    string
		reqPath string
		pattern string
		want    bool
	}{
		{"direct child", "/workspace/file.go", "/workspace/**", true},
		{"two levels deep", "/workspace/src/main.go", "/workspace/**", true},
		{"five levels deep", "/workspace/a/b/c/d/e.go", "/workspace/**", true},
		{"exact dir match", "/workspace", "/workspace/**", true},
		{"with trailing slash", "/workspace/", "/workspace/**", true},
		{"hidden file", "/workspace/.gitignore", "/workspace/**", true},
		{"outside workspace", "/home/user/file", "/workspace/**", false},
		{"similar prefix", "/workspace2/file", "/workspace/**", false},
		{"root doublestar", "/**", "/**", true},
		{"everything under root", "/any/path/at/all", "/**", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := pathMatches(tt.reqPath, tt.pattern)
			if got != tt.want {
				t.Errorf("pathMatches(%q, %q) = %v, want %v", tt.reqPath, tt.pattern, got, tt.want)
			}
		})
	}
}

func TestFilesystemPathApproved_TraversalBypassAttempt(t *testing.T) {
	// An attacker requests "/workspace/../etc/passwd". With path normalization,
	// this should resolve to "/etc/passwd" which is NOT under /workspace/**.
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read: []string{"/workspace/**"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	traversalPaths := []string{
		"/workspace/../etc/passwd",
		"/workspace/../../etc/shadow",
		"/workspace/src/../../etc/hosts",
		"/workspace/./../../root/.ssh/id_rsa",
	}

	for _, path := range traversalPaths {
		t.Run(path, func(t *testing.T) {
			req := Request{
				Category:   "filesystem",
				Action:     "read " + path,
				Capability: &config.FilesystemCaps{Read: []string{path}},
			}
			approved, _ := mgr.Check(req)
			if approved {
				t.Errorf("traversal path %q should NOT be approved under /workspace/**", path)
			}
		})
	}
}

func TestFilesystemPathApproved_WriteWithDeny(t *testing.T) {
	// Write requests must also respect deny patterns.
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Write: []string{"/workspace/**"},
			Deny:  []string{"/workspace/.git/**"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// Write to normal file: allowed.
	req := Request{
		Category:   "filesystem",
		Action:     "write /workspace/main.go",
		Capability: &config.FilesystemCaps{Write: []string{"/workspace/main.go"}},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve write to /workspace/main.go")
	}

	// Write to .git directory: denied.
	reqDeny := Request{
		Category:   "filesystem",
		Action:     "write /workspace/.git/config",
		Capability: &config.FilesystemCaps{Write: []string{"/workspace/.git/config"}},
	}
	approvedDeny, _ := mgr.Check(reqDeny)
	if approvedDeny {
		t.Error("should deny write to /workspace/.git/config (denied by /workspace/.git/**)")
	}
}

func TestFilesystemPathApproved_MixedReadWrite(t *testing.T) {
	// A request with both read and write paths: all must pass.
	baseline := &config.Capabilities{
		Filesystem: &config.FilesystemCaps{
			Read:  []string{"/workspace/**"},
			Write: []string{"/workspace/out/**"},
			Deny:  []string{"/workspace/.env"},
		},
	}

	mgr := NewManager(nonInteractiveDenyApprover(), "/dev/null", baseline)

	// Read from workspace + write to out: both allowed.
	req := Request{
		Category: "filesystem",
		Action:   "read and write",
		Capability: &config.FilesystemCaps{
			Read:  []string{"/workspace/src/main.go"},
			Write: []string{"/workspace/out/build.o"},
		},
	}
	approved, _ := mgr.Check(req)
	if !approved {
		t.Error("should approve: read from /workspace/ and write to /workspace/out/")
	}

	// Read from workspace + write to root of workspace (not under out/): denied.
	reqFail := Request{
		Category: "filesystem",
		Action:   "read and write",
		Capability: &config.FilesystemCaps{
			Read:  []string{"/workspace/src/main.go"},
			Write: []string{"/workspace/src/main.go"}, // not under /workspace/out/
		},
	}
	approvedFail, _ := mgr.Check(reqFail)
	if approvedFail {
		t.Error("should deny: write to /workspace/src/ is not under /workspace/out/")
	}

	// Read from denied path: denied even though read is allowed for workspace.
	reqDeny := Request{
		Category: "filesystem",
		Action:   "read .env",
		Capability: &config.FilesystemCaps{
			Read: []string{"/workspace/.env"},
		},
	}
	approvedDeny, _ := mgr.Check(reqDeny)
	if approvedDeny {
		t.Error("should deny: /workspace/.env is in deny list")
	}
}
