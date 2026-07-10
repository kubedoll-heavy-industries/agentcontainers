package cli

import (
	"bytes"
	"context"
	"testing"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/dojo"
)

func TestDojoCommandWiresOptions(t *testing.T) {
	origRunDojo := runDojo
	defer func() { runDojo = origRunDojo }()

	var got dojo.Options
	runDojo = func(_ context.Context, opts dojo.Options) (*dojo.Result, error) {
		got = opts
		return &dojo.Result{}, nil
	}

	cmd := newRootCmd("test", "abc", "now")
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(&out)
	cmd.SetArgs([]string{
		"dojo",
		"codex-redteam",
		"--base-dir", "/tmp/dojo-test",
		"--no-build",
		"--no-start",
		"--no-chat",
		"--model", "gpt-5.5",
		"--runtime", "docker",
		"--shell",
	})

	if err := cmd.Execute(); err != nil {
		t.Fatalf("Execute() error = %v", err)
	}
	if got.Profile != dojo.ProfileCodexRedteam {
		t.Fatalf("Profile = %q", got.Profile)
	}
	if got.BaseDir != "/tmp/dojo-test" {
		t.Fatalf("BaseDir = %q", got.BaseDir)
	}
	if got.BuildImage {
		t.Fatal("BuildImage = true, want false with --no-build")
	}
	if !got.NoStart || !got.NoChat || !got.Shell {
		t.Fatalf("NoStart/NoChat/Shell = %v/%v/%v", got.NoStart, got.NoChat, got.Shell)
	}
	if got.Model != "gpt-5.5" {
		t.Fatalf("Model = %q", got.Model)
	}
}
