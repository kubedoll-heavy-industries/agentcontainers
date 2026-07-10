package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/signal"
	"sort"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
)

func newLearnCmd() *cobra.Command {
	var (
		timeout     time.Duration
		outputPath  string
		configPath  string
		runtimeFlag string
		fromSession string
	)

	cmd := &cobra.Command{
		Use:   "learn",
		Short: "Observe process execution to build a process-tree profile",
		Long: `Start a container in observation mode and record all process
executions. On exit, write a process-tree profile that can be used
as input for deny-set policy.

The container runs without deny-set enforcement so all execs are
allowed. Every ProcessExec event emitted by the enforcer is captured
and used to build (parent, child) relationships.

Use --from-session to extract a profile from an existing audit log
instead of running a new container.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if fromSession != "" {
				return runLearnFromSession(cmd, fromSession, outputPath)
			}
			return runLearn(cmd, timeout, outputPath, configPath, runtimeFlag)
		},
	}

	cmd.Flags().DurationVarP(&timeout, "timeout", "t", 0, "Duration to run before stopping (default: until Ctrl+C)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "process-profile.json", "Output file path for the generated profile")
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json")
	cmd.Flags().StringVar(&runtimeFlag, "runtime", "docker", "Container runtime backend (auto|docker|compose|sandbox)")
	cmd.Flags().StringVar(&fromSession, "from-session", "", "Read audit log from a previous session instead of running a container")

	return cmd
}

// processProfile represents the output JSON for a learned process-tree profile.
type processProfile struct {
	Generated string         `json:"generated"`
	Profiles  []profileEntry `json:"profiles"`
}

// profileEntry represents a single binary and its observed child processes.
type profileEntry struct {
	Name          string            `json:"name"`
	Version       int               `json:"version"`
	Binary        string            `json:"binary"`
	AllowChildren []string          `json:"allowChildren"`
	Transitions   map[string]string `json:"transitions"`
}

// execObservation tracks observed exec events by parent comm.
type execObservation struct {
	mu sync.Mutex

	// parentToChildren maps parent comm -> set of child binaries.
	parentToChildren map[string]map[string]bool
}

func newExecObservation() *execObservation {
	return &execObservation{
		parentToChildren: make(map[string]map[string]bool),
	}
}

func (o *execObservation) record(parentComm, childBinary string) {
	if parentComm == "" || childBinary == "" {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()

	children, ok := o.parentToChildren[parentComm]
	if !ok {
		children = make(map[string]bool)
		o.parentToChildren[parentComm] = children
	}
	children[childBinary] = true
}

func (o *execObservation) buildProfile() processProfile {
	o.mu.Lock()
	defer o.mu.Unlock()

	var entries []profileEntry
	for parent, children := range o.parentToChildren {
		var childList []string
		for c := range children {
			childList = append(childList, c)
		}
		sort.Strings(childList)
		entries = append(entries, profileEntry{
			Name:          parent,
			Version:       1,
			Binary:        parent,
			AllowChildren: childList,
			Transitions:   map[string]string{},
		})
	}
	sort.Slice(entries, func(i, j int) bool {
		return entries[i].Name < entries[j].Name
	})
	return processProfile{
		Generated: time.Now().UTC().Format(time.RFC3339),
		Profiles:  entries,
	}
}

func writeProfile(path string, profile processProfile) error {
	data, err := json.MarshalIndent(profile, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling profile: %w", err)
	}
	if err := os.WriteFile(path, append(data, '\n'), 0o644); err != nil {
		return fmt.Errorf("writing profile to %s: %w", path, err)
	}
	return nil
}

func runLearn(cmd *cobra.Command, timeout time.Duration, outputPath, configPath, runtimeFlag string) error {
	// 1. Load and validate configuration.
	cfg, cfgPath, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("learn: invalid configuration: %w", err)
	}

	// 2. Resolve runtime (enforcement level is gRPC so the sidecar streams events).
	resolvedRuntime := container.RuntimeType(runtimeFlag)
	if resolvedRuntime == "auto" {
		resolvedRuntime = container.DetectRuntime(container.DefaultSandboxProber)
		logger.Info("runtime auto-detected", zap.String("runtime", string(resolvedRuntime)))
	}
	isSandbox := resolvedRuntime == container.RuntimeSandbox

	// 3. Resolve sidecar for event streaming.
	var enfAddr string
	enfLevel := enforcement.LevelNone

	if isSandbox {
		enfLevel = enforcement.LevelGRPC
		logger.Info("sandbox runtime: in-VM enforcement for learn mode")
	} else {
		_, enfAddr, err = resolveSidecar(cmd, cfg)
		if err != nil {
			return fmt.Errorf("learn: %w", err)
		}
		if enfAddr != "" {
			enfLevel = enforcement.LevelGRPC
			_ = os.Setenv("AC_ENFORCER_ADDR", enfAddr)
		}
	}

	if enfLevel != enforcement.LevelGRPC {
		return fmt.Errorf("learn: enforcer sidecar required for observation mode (no sidecar found)")
	}

	rt, err := newRuntime(runtimeFlag, logger, enfLevel)
	if err != nil {
		return fmt.Errorf("learn: %w", err)
	}

	// 4. Resolve policy (but skip deny-sets — learn mode allows all execs).
	var caps *config.Capabilities
	if cfg.Agent != nil {
		caps = cfg.Agent.Capabilities
	}
	resolvedPolicy := policy.Resolve(caps)

	workdir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("learn: determining workspace path: %w", err)
	}

	// 5. Generate session ID.
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return fmt.Errorf("learn: generating session ID: %w", err)
	}
	sessionID := hex.EncodeToString(randBytes)

	// 6. Build start options — intentionally omit DenySetRequest so all execs pass.
	sessionTimeout := 4 * time.Hour
	if timeout > 0 {
		sessionTimeout = timeout
	}
	opts := container.StartOptions{
		Detach:        false,
		Timeout:       sessionTimeout,
		WorkspacePath: workdir,
		Policy:        resolvedPolicy,
	}

	// 7. Start the container.
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	session, err := rt.Start(ctx, cfg, opts)
	if err != nil {
		return fmt.Errorf("learn: starting container: %w", err)
	}

	if isSandbox && session.EnforcerAddr != "" {
		enfAddr = session.EnforcerAddr
		_ = os.Setenv("AC_ENFORCER_ADDR", enfAddr)
	}

	// 8. Print session info.
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Learn mode started (observing process executions)\n")
	_, _ = fmt.Fprintf(out, "  Container: %s\n", shortID(session.ContainerID))
	_, _ = fmt.Fprintf(out, "  Runtime:   %s\n", session.RuntimeType)
	_, _ = fmt.Fprintf(out, "  Config:    %s\n", cfgPath)
	_, _ = fmt.Fprintf(out, "  Session:   %s\n", sessionID)
	_, _ = fmt.Fprintf(out, "  Output:    %s\n", outputPath)
	if timeout > 0 {
		_, _ = fmt.Fprintf(out, "  Timeout:   %s\n", timeout)
	} else {
		_, _ = fmt.Fprintf(out, "  Timeout:   none (Ctrl+C to stop)\n")
	}

	// 9. Stream enforcement events and collect exec observations.
	obs := newExecObservation()
	var eventCount int64
	var eventWG sync.WaitGroup

	if es, ok := rt.(container.EventStreamer); ok {
		if eventCh := es.EnforcementEvents(session.ContainerID); eventCh != nil {
			eventWG.Add(1)
			go func() {
				defer eventWG.Done()
				for {
					select {
					case <-ctx.Done():
						return
					case evt, ok := <-eventCh:
						if !ok {
							return
						}
						if evt.Type == enforcement.EventExec && evt.Exec != nil {
							obs.record(evt.Comm, evt.Exec.Binary)
							atomic.AddInt64(&eventCount, 1)
							_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "[EXEC] pid=%d parent=%s binary=%s\n",
								evt.PID, evt.Comm, evt.Exec.Binary)
						}
					}
				}
			}()
		}
	}

	// 10. Stream logs in the background.
	logsDone := make(chan error, 1)
	go func() {
		logReader, err := rt.Logs(ctx, session)
		if err != nil {
			logsDone <- err
			return
		}
		defer logReader.Close() //nolint:errcheck
		_, err = io.Copy(out, logReader)
		logsDone <- err
	}()

	// 11. Wait for signal, timeout, or log completion.
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	var timeoutCh <-chan time.Time
	if timeout > 0 {
		timeoutCh = time.After(timeout)
	}

	select {
	case sig := <-sigCh:
		_, _ = fmt.Fprintf(out, "\nReceived %s, stopping...\n", sig)
	case err := <-logsDone:
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Log streaming ended: %v\n", err)
		}
	case <-timeoutCh:
		_, _ = fmt.Fprintf(out, "\nTimeout reached, stopping...\n")
	}

	// 12. Stop the container.
	cancel()
	if stopErr := rt.Stop(context.Background(), session); stopErr != nil {
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Warning: stopping container: %v\n", stopErr)
	}
	eventWG.Wait()
	_, _ = fmt.Fprintf(out, "Container stopped\n")

	// 13. Build and write the profile.
	profile := obs.buildProfile()
	_, _ = fmt.Fprintf(out, "Observed %d exec events across %d parent processes\n", atomic.LoadInt64(&eventCount), len(profile.Profiles))

	if err := writeProfile(outputPath, profile); err != nil {
		return fmt.Errorf("learn: %w", err)
	}
	_, _ = fmt.Fprintf(out, "Profile written to %s\n", outputPath)

	return nil
}

// runLearnFromSession reads an audit log from a previous session and extracts
// exec pairs to build a process profile. This is a placeholder that currently
// returns an error since audit log parsing is not yet implemented.
func runLearnFromSession(_ *cobra.Command, sessionID, outputPath string) error {
	_ = sessionID
	_ = outputPath
	return fmt.Errorf("learn: --from-session is not yet implemented")
}
