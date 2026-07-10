package cli

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestLearnCmd_NoConfig(t *testing.T) {
	// Run from a temp directory with no config files.
	tmp := t.TempDir()
	origDir, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chdir(tmp); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chdir(origDir) }()

	cmd := newLearnCmd()
	cmd.SetArgs([]string{})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	// PersistentPreRunE on root sets up logger; wire it manually.
	logger, _ = newLogger(false)

	err = cmd.Execute()
	if err == nil {
		t.Error("expected error when no config exists")
	}
}

func TestLearnCmd_FromSessionNotImplemented(t *testing.T) {
	cmd := newLearnCmd()
	cmd.SetArgs([]string{"--from-session", "abc123"})
	var buf bytes.Buffer
	cmd.SetOut(&buf)
	cmd.SetErr(&buf)

	logger, _ = newLogger(false)

	err := cmd.Execute()
	if err == nil {
		t.Error("expected error for --from-session")
	}
	if err != nil && err.Error() != "learn: --from-session is not yet implemented" {
		t.Errorf("unexpected error: %v", err)
	}
}

func TestExecObservation_Record(t *testing.T) {
	obs := newExecObservation()

	// Record some exec events.
	obs.record("bash", "/usr/bin/node")
	obs.record("bash", "/usr/bin/npm")
	obs.record("bash", "/usr/bin/node") // duplicate
	obs.record("node", "/usr/bin/npx")
	obs.record("", "/usr/bin/ghost") // empty parent, ignored
	obs.record("bash", "")           // empty child, ignored

	profile := obs.buildProfile()

	if len(profile.Profiles) != 2 {
		t.Fatalf("expected 2 profile entries, got %d", len(profile.Profiles))
	}

	// Profiles should be sorted by name.
	if profile.Profiles[0].Name != "bash" {
		t.Errorf("expected first profile to be bash, got %s", profile.Profiles[0].Name)
	}
	if profile.Profiles[1].Name != "node" {
		t.Errorf("expected second profile to be node, got %s", profile.Profiles[1].Name)
	}

	// bash should have 2 children (node, npm) — sorted.
	bashChildren := profile.Profiles[0].AllowChildren
	if len(bashChildren) != 2 {
		t.Fatalf("expected 2 children for bash, got %d", len(bashChildren))
	}
	if bashChildren[0] != "/usr/bin/node" {
		t.Errorf("expected first child /usr/bin/node, got %s", bashChildren[0])
	}
	if bashChildren[1] != "/usr/bin/npm" {
		t.Errorf("expected second child /usr/bin/npm, got %s", bashChildren[1])
	}

	// node should have 1 child.
	nodeChildren := profile.Profiles[1].AllowChildren
	if len(nodeChildren) != 1 {
		t.Fatalf("expected 1 child for node, got %d", len(nodeChildren))
	}
	if nodeChildren[0] != "/usr/bin/npx" {
		t.Errorf("expected child /usr/bin/npx, got %s", nodeChildren[0])
	}
}

func TestExecObservation_EmptyProfile(t *testing.T) {
	obs := newExecObservation()
	profile := obs.buildProfile()

	if len(profile.Profiles) != 0 {
		t.Errorf("expected empty profiles, got %d", len(profile.Profiles))
	}

	// Generated timestamp should be parseable.
	if _, err := time.Parse(time.RFC3339, profile.Generated); err != nil {
		t.Errorf("generated timestamp not RFC3339: %v", err)
	}
}

func TestWriteProfile(t *testing.T) {
	tmp := t.TempDir()
	outPath := filepath.Join(tmp, "test-profile.json")

	profile := processProfile{
		Generated: "2026-04-16T00:00:00Z",
		Profiles: []profileEntry{
			{
				Name:          "bash",
				Version:       1,
				Binary:        "bash",
				AllowChildren: []string{"node", "npm"},
				Transitions:   map[string]string{},
			},
		},
	}

	if err := writeProfile(outPath, profile); err != nil {
		t.Fatal(err)
	}

	data, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatal(err)
	}

	var loaded processProfile
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("invalid JSON output: %v", err)
	}

	if loaded.Generated != "2026-04-16T00:00:00Z" {
		t.Errorf("unexpected generated: %s", loaded.Generated)
	}
	if len(loaded.Profiles) != 1 {
		t.Fatalf("expected 1 profile, got %d", len(loaded.Profiles))
	}
	if loaded.Profiles[0].Name != "bash" {
		t.Errorf("expected profile name bash, got %s", loaded.Profiles[0].Name)
	}
}

func TestLearnCmd_Flags(t *testing.T) {
	cmd := newLearnCmd()

	// Verify expected flags exist.
	flags := []string{"timeout", "output", "config", "runtime", "from-session"}
	for _, name := range flags {
		if cmd.Flags().Lookup(name) == nil {
			t.Errorf("expected flag --%s to be registered", name)
		}
	}

	// Verify short flags.
	shortFlags := map[string]string{"t": "timeout", "o": "output", "c": "config"}
	for short, long := range shortFlags {
		f := cmd.Flags().ShorthandLookup(short)
		if f == nil {
			t.Errorf("expected short flag -%s for --%s", short, long)
		} else if f.Name != long {
			t.Errorf("short flag -%s maps to %s, expected %s", short, f.Name, long)
		}
	}
}
