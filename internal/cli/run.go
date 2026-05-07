package cli

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"go.uber.org/zap"

	"github.com/moby/moby/client"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/audit"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oidc"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/orgpolicy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/policy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/sidecar"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

var (
	runRuntimeFactory       = newRuntime
	runResolveSidecar       = resolveSidecar
	runExtractPolicy        = orgpolicy.ExtractPolicy
	runMergePolicy          = orgpolicy.MergePolicy
	runVerifyImageSignature = verifyImageSignature
	runNewDockerClient      = func() (client.APIClient, error) { return client.New(client.FromEnv) }
	runStopSidecar          = sidecar.StopSidecar
)

func newRunCmd() *cobra.Command {
	var (
		detach                bool
		timeout               time.Duration
		configPath            string
		runtimeFlag           string
		insecureSkipVerify    bool
		insecureSkipOrgPolicy bool
	)

	cmd := &cobra.Command{
		Use:   "run",
		Short: "Start an agent session in an isolated container",
		Long: `Build or pull the container image, apply capability policy,
and start an interactive agent session with human-in-the-loop
approval for capability escalations.

Org policy is resolved automatically from the workspace hierarchy
(.agentcontainers/policy.json) or from the lockfile's pinned digest.
It cannot be overridden at runtime.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runRun(cmd, detach, timeout, configPath, runtimeFlag, insecureSkipVerify, insecureSkipOrgPolicy)
		},
	}

	cmd.Flags().BoolVarP(&detach, "detach", "d", false, "Run container in background")
	cmd.Flags().DurationVar(&timeout, "timeout", 4*time.Hour, "Session timeout")
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json")
	cmd.Flags().StringVar(&runtimeFlag, "runtime", "docker", "Container runtime backend (auto|docker|compose|sandbox)")
	cmd.Flags().BoolVar(&insecureSkipVerify, "insecure-skip-verify", false, "Skip cosign signature verification (dev only)")
	cmd.Flags().BoolVar(&insecureSkipOrgPolicy, "insecure-skip-org-policy", false, "Skip image org-policy extraction (dev/local images only)")

	return cmd
}

// loadConfig loads the agent container configuration, either from an explicit
// path (--config) or by searching the working directory.
func loadConfig(configPath string) (*config.AgentContainer, string, error) {
	if configPath != "" {
		absPath, err := filepath.Abs(configPath)
		if err != nil {
			return nil, "", fmt.Errorf("run: resolving config path: %w", err)
		}
		cfg, err := config.ParseFile(absPath)
		if err != nil {
			return nil, "", fmt.Errorf("run: loading config %s: %w", absPath, err)
		}
		return cfg, absPath, nil
	}

	cwd, err := os.Getwd()
	if err != nil {
		return nil, "", fmt.Errorf("run: determining working directory: %w", err)
	}
	cfg, path, err := config.Load(cwd)
	if err != nil {
		return nil, "", fmt.Errorf("run: %w", err)
	}
	return cfg, path, nil
}

// policyImageRef returns the image reference to use for org policy extraction.
// When a lockfile exists next to cfgPath and contains a pinned image digest,
// the returned reference is imageTag + "@" + digest (e.g.
// "myrepo/myimage:v1@sha256:abc..."). This prevents TOCTOU attacks (F-4)
// where a mutable tag is mutated between `agentcontainer lock` and `agentcontainer run` to point at
// an image with a weaker or absent policy layer.
//
// If no lockfile exists, the lockfile has no image entry, or the lockfile
// cannot be loaded, the original imageTag is returned unchanged and a warning
// is logged. This is a graceful degradation: environments that have not yet
// run `agentcontainer lock` continue to work.
func policyImageRef(imageTag, cfgPath string) string {
	if imageTag == "" || cfgPath == "" {
		return imageTag
	}
	cfgDir := filepath.Dir(cfgPath)
	lf, err := config.LoadLockfile(cfgDir)
	if err != nil {
		// No lockfile or parse error — fall back to mutable tag and warn.
		logger.Warn("lockfile not found or unreadable; policy ref uses mutable tag (F-4 protection inactive)",
			zap.String("cfgDir", cfgDir),
			zap.Error(err))
		return imageTag
	}
	if lf.Resolved.Image == nil || lf.Resolved.Image.Digest == "" {
		logger.Warn("lockfile has no pinned image digest; policy ref uses mutable tag (F-4 protection inactive)")
		return imageTag
	}
	// Strip any existing digest from imageTag to avoid double-@ refs.
	// ParseReference handles tag@digest, but constructing a clean ref is safer.
	ref := imageTag
	if idx := strings.Index(ref, "@"); idx != -1 {
		ref = ref[:idx]
	}
	return ref + "@" + lf.Resolved.Image.Digest
}

func runRun(cmd *cobra.Command, detach bool, timeout time.Duration, configPath string, runtimeFlag string, insecureSkipVerify bool, insecureSkipOrgPolicy bool) error {
	// 0. Resolve "auto" to a concrete runtime type so all downstream checks
	// (e.g. sandbox sidecar skip) work regardless of the original flag value.
	resolvedRuntime := container.RuntimeType(runtimeFlag)
	if resolvedRuntime == "auto" {
		resolvedRuntime = container.DetectRuntime(container.DefaultSandboxProber)
		logger.Info("runtime auto-detected", zap.String("runtime", string(resolvedRuntime)))
	}
	isSandbox := resolvedRuntime == container.RuntimeSandbox

	// 1. Load and validate configuration.
	cfg, cfgPath, err := loadConfig(configPath)
	if err != nil {
		return err
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("run: invalid configuration: %w", err)
	}

	if err := verifyRunPolicyChannel(cmd.Context(), cfg, cfgPath, newOCIResolver()); err != nil {
		return err
	}

	// 1b. Extract org policy from the image manifest and validate against
	// workspace config. Policy is embedded in the image as a typed layer at
	// build time (PRD-017). If no policy layer is found, DefaultPolicy() is
	// used. This cannot be overridden at runtime.
	workdir, err := os.Getwd()
	if err != nil {
		return fmt.Errorf("run: determining workspace path: %w", err)
	}

	// Use the lockfile-pinned digest when available to prevent TOCTOU attacks
	// (F-4): a mutable tag can be mutated between `agentcontainer lock` and `agentcontainer run` to
	// point at a different image with a weaker or absent policy layer.
	// Pinning to the lockfile digest ensures the same manifest is inspected
	// regardless of tag mutation.
	policyRef := policyImageRef(cfg.Image, cfgPath)

	orgPolicy := orgpolicy.DefaultPolicy()
	if insecureSkipOrgPolicy {
		logger.Warn("skipping image org-policy extraction (--insecure-skip-org-policy)")
	} else {
		var err error
		orgPolicy, err = runExtractPolicy(cmd.Context(), policyRef)
		if err != nil {
			return fmt.Errorf("run: extracting org policy from image: %w", err)
		}
	}
	if err := runMergePolicy(orgPolicy, cfg); err != nil {
		return fmt.Errorf("run: org policy violation: %w", err)
	}

	// 1c. Verify image signature (F-1) when provenance requires it.
	// We verify against policyRef (the lockfile-pinned digest) so the
	// signature check and the policy extraction operate on the same manifest.
	if !insecureSkipVerify {
		if err := runVerifyImageSignature(cmd, cfg, policyRef); err != nil {
			return fmt.Errorf("run: image signature verification failed: %w", err)
		}
	}

	// 1d. Initialize audit logger.
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return fmt.Errorf("run: generating session ID: %w", err)
	}
	sessionID := hex.EncodeToString(randBytes)

	var auditLog *audit.Logger
	if cfg.Agent != nil {
		auditLog, err = audit.NewLogger(sessionID)
		if err != nil {
			logger.Warn("failed to create audit logger, continuing without audit", zap.Error(err))
		}
	}
	if auditLog != nil {
		defer auditLog.Close() //nolint:errcheck
		if logErr := auditLog.Log(audit.EventLifecycle, audit.Actor{Type: "system", Name: "agentcontainer"},
			audit.WithDetail("session_start"), audit.WithResource(cfgPath)); logErr != nil {
			logger.Warn("failed to write audit entry", zap.Error(logErr))
		}
	}

	// 2. Resolve sidecar — discover external or auto-start managed.
	// For Sandbox runtime, the sidecar runs inside the VM (managed by the runtime),
	// so skip host-level sidecar resolution.
	var sidecarHandle *sidecar.SidecarHandle
	var enfAddr string
	enfLevel := enforcement.LevelNone
	var enfSource string

	if isSandbox {
		// Sandbox manages its own in-VM enforcer. Set enforcement level to
		// LevelGRPC so the runtime knows to start the sidecar.
		enfLevel = enforcement.LevelGRPC
		enfSource = "in-vm"
		logger.Info("sandbox runtime: in-VM enforcement, skipping host sidecar")
	} else {
		sidecarHandle, enfAddr, err = runResolveSidecar(cmd, cfg)
		if err != nil {
			return fmt.Errorf("run: %w", err)
		}

		// Determine enforcement level from sidecar resolution.
		if sidecarHandle != nil && sidecarHandle.Addr != "" {
			enfLevel = enforcement.LevelGRPC
			if sidecarHandle.Managed {
				enfSource = "auto-started"
			} else {
				enfSource = "external"
			}
			_ = os.Setenv("AC_ENFORCER_ADDR", enfAddr)
		} else if enfAddr != "" {
			// This shouldn't normally occur (handle nil but addr set), but handle it.
			enfLevel = enforcement.LevelGRPC
			enfSource = "external"
			_ = os.Setenv("AC_ENFORCER_ADDR", enfAddr)
		}
	}
	logger.Info("enforcement level resolved", zap.String("level", enfLevel.String()), zap.String("source", enfSource))

	rt, err := runRuntimeFactory(string(resolvedRuntime), logger, enfLevel)
	if err != nil {
		return fmt.Errorf("run: %w", err)
	}

	sessionStarted := false
	defer func() {
		if sessionStarted || isSandbox || sidecarHandle == nil || !sidecarHandle.Managed {
			return
		}
		stopManagedSidecar(cmd.OutOrStdout(), sidecarHandle)
	}()

	// 2b. Resolve secrets if configured.
	var secretsMgr *secrets.Manager
	var secretsCleanup func()
	if cfg.Agent != nil && len(cfg.Agent.Secrets) > 0 {
		secretsMgr, secretsCleanup, err = buildSecretsManager(cmd.Context(), cfg)
		if err != nil {
			return fmt.Errorf("run: secrets: %w", err)
		}
		if secretsCleanup != nil {
			defer secretsCleanup()
		}
	}

	// 3. Resolve security policy from agent capabilities.
	var caps *config.Capabilities
	if cfg.Agent != nil {
		caps = cfg.Agent.Capabilities
	}
	resolvedPolicy := resolveRuntimePolicy(cfg)

	// 3b. Apply policy config overrides.
	var policyConfig *config.PolicyConfig
	if cfg.Agent != nil {
		policyConfig = cfg.Agent.Policy
	}

	if policyConfig != nil && policyConfig.SessionTimeout != "" {
		if d, err := time.ParseDuration(policyConfig.SessionTimeout); err == nil && d > 0 {
			timeout = d
			logger.Info("session timeout overridden by policy", zap.Duration("timeout", d))
		}
	}

	// 4. Wire approval manager for interactive capability approval.
	var escalation string
	if policyConfig != nil {
		escalation = policyConfig.Escalation
	}
	approvalMgr := approval.NewManager(
		approval.NewTerminalApprover(approval.WithOutput(cmd.OutOrStdout())),
		cfgPath,
		caps,
		approval.WithEscalation(escalation),
	)

	// Persist any session approvals when the session ends.
	defer func() {
		if persistErr := approvalMgr.Persist(); persistErr != nil {
			logger.Warn("failed to persist capabilities", zap.Error(persistErr))
		}
	}()

	// 5. Wrap the runtime with the capability broker to gate Exec calls.
	brokerRT := approval.NewBroker(rt, approvalMgr)

	// 6. Build start options.
	opts := container.StartOptions{
		Detach:         detach,
		Timeout:        timeout,
		WorkspacePath:  workdir,
		Policy:         resolvedPolicy,
		PinnedImageRef: policyRef,
	}
	if secretsMgr != nil {
		// ResolvedSecrets is passed to the enforcement strategy (InjectSecrets)
		// and to Sandbox for CredentialSources/ServiceAuthConfig.
		opts.ResolvedSecrets = secretsMgr.CachedSecrets()
	}

	// 7. Start the container.
	ctx, cancel := context.WithCancel(cmd.Context())
	defer cancel()

	session, err := brokerRT.Start(ctx, cfg, opts)
	if err != nil {
		return fmt.Errorf("run: starting container: %w", err)
	}
	sessionStarted = true

	// For sandbox, read enforcer address from the session (set by the runtime).
	if isSandbox && session.EnforcerAddr != "" {
		enfAddr = session.EnforcerAddr
		_ = os.Setenv("AC_ENFORCER_ADDR", enfAddr)
		logger.Info("in-VM enforcer address", zap.String("addr", enfAddr))
	}

	// 7b. Log container started and start secret rotation.
	if auditLog != nil {
		if logErr := auditLog.Log(audit.EventLifecycle, audit.Actor{Type: "system", Name: "agentcontainer"},
			audit.WithDetail("container_started"),
			audit.WithMetadata("container_id", session.ContainerID)); logErr != nil {
			logger.Warn("failed to write audit entry", zap.Error(logErr))
		}
	}
	if secretsMgr != nil {
		if err := secretsMgr.StartRotation(ctx); err != nil {
			logger.Warn("failed to start secret rotation", zap.Error(err))
		}
	}

	// 8. Print session info.
	out := cmd.OutOrStdout()
	_, _ = fmt.Fprintf(out, "Session started\n")
	_, _ = fmt.Fprintf(out, "  Container:   %s\n", shortID(session.ContainerID))
	_, _ = fmt.Fprintf(out, "  Runtime:     %s\n", session.RuntimeType)
	if enfSource != "" {
		_, _ = fmt.Fprintf(out, "  Enforcement: %s (%s)\n", enfLevel, enfSource)
	} else {
		_, _ = fmt.Fprintf(out, "  Enforcement: %s\n", enfLevel)
	}
	if enfAddr != "" {
		_, _ = fmt.Fprintf(out, "  Enforcer:    %s\n", enfAddr)
	}
	if secretsMgr != nil {
		_, _ = fmt.Fprintf(out, "  Secrets:     %d loaded\n", len(cfg.Agent.Secrets))
	}
	_, _ = fmt.Fprintf(out, "  Config:      %s\n", cfgPath)
	_, _ = fmt.Fprintf(out, "  Timeout:     %s\n", timeout)
	_, _ = fmt.Fprintf(out, "  Session:     %s\n", sessionID)
	if auditLog != nil {
		_, _ = fmt.Fprintf(out, "  Audit log:   %s\n", auditLog.Path())
	}

	if detach {
		_, _ = fmt.Fprintf(out, "  Mode:        detached\n")
		return nil
	}

	// 9. Foreground mode: stream logs until interrupted.
	_, _ = fmt.Fprintf(out, "  Mode:        foreground (Ctrl+C to stop)\n")

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	logsDone := make(chan error, 1)
	go func() {
		logReader, err := brokerRT.Logs(ctx, session)
		if err != nil {
			logsDone <- fmt.Errorf("run: streaming logs: %w", err)
			return
		}
		defer logReader.Close() //nolint:errcheck
		_, err = io.Copy(out, logReader)
		logsDone <- err
	}()

	// Stream enforcement events (BPF block/allow) to stderr.
	if eventCh := brokerRT.EnforcementEvents(session.ContainerID); eventCh != nil {
		errOut := cmd.ErrOrStderr()
		go func() {
			for {
				select {
				case <-ctx.Done():
					return
				case evt, ok := <-eventCh:
					if !ok {
						return
					}
					printEnforcementEvent(errOut, evt)
				}
			}
		}()
	}

	// Liveness monitor: periodically probe the enforcer health endpoint.
	// If enforcement is gRPC and the enforcer becomes unreachable, cancel
	// the context to trigger container stop (fail-closed).
	enforcerDead := make(chan struct{})
	if enfLevel == enforcement.LevelGRPC && enfAddr != "" {
		go runEnforcerLiveness(ctx, cancel, enfAddr, 10*time.Second, 3, enforcerDead, enforcement.ProbeEnforcerHealth)
	}

	select {
	case sig := <-sigCh:
		_, _ = fmt.Fprintf(out, "\nReceived %s, stopping container...\n", sig)
	case err := <-logsDone:
		if err != nil {
			_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "Log streaming ended: %v\n", err)
		}
	case <-enforcerDead:
		_, _ = fmt.Fprintf(cmd.ErrOrStderr(), "\nEnforcer unreachable after 3 consecutive failures, stopping container...\n")
	}

	// 10. Cleanup: stop the container.
	if auditLog != nil {
		if logErr := auditLog.Log(audit.EventLifecycle, audit.Actor{Type: "system", Name: "agentcontainer"},
			audit.WithDetail("container_stopped"),
			audit.WithMetadata("container_id", session.ContainerID)); logErr != nil {
			logger.Warn("failed to write audit entry", zap.Error(logErr))
		}
	}

	cancel()
	if stopErr := brokerRT.Stop(context.Background(), session); stopErr != nil {
		return fmt.Errorf("run: stopping container: %w", stopErr)
	}
	_, _ = fmt.Fprintf(out, "Container stopped\n")

	// Stop managed sidecar after agent container is stopped.
	// (Sandbox runtime manages its own sidecar teardown in Stop().)
	if !isSandbox && sidecarHandle != nil && sidecarHandle.Managed {
		stopManagedSidecar(out, sidecarHandle)
	}

	return nil
}

func verifyRunPolicyChannel(ctx context.Context, cfg *config.AgentContainer, cfgPath string, fetcher policyBundleFetcher) error {
	policyRef := configuredPolicyRef(cfg)
	if policyRef == "" {
		return nil
	}
	if cfgPath == "" {
		return fmt.Errorf("run: mutable policy channel: config path is required")
	}

	lf, err := config.LoadLockfile(filepath.Dir(cfgPath))
	if err != nil {
		return fmt.Errorf("run: mutable policy channel: loading lockfile: %w", err)
	}
	if err := lf.Validate(); err != nil {
		return fmt.Errorf("run: mutable policy channel: invalid lockfile: %w", err)
	}
	if lf.Resolved.Policy == nil {
		return fmt.Errorf("run: mutable policy channel: policy %s is not pinned in lockfile", policyRef)
	}
	if coverageIssues := requirePolicyChannelLockCoverage(cfg, lf); len(coverageIssues) > 0 {
		var msgs []string
		for _, issue := range coverageIssues {
			msgs = append(msgs, issue.label+" is not pinned in lockfile")
		}
		return fmt.Errorf("run: mutable policy channel requires lockfile coverage: %s", strings.Join(msgs, "; "))
	}

	now := time.Now().UTC()
	currentPolicy, bundle, err := resolvePolicyChannel(ctx, fetcher, policyRef, now)
	if err != nil {
		return fmt.Errorf("run: mutable policy channel: fetching policy %s: %w", policyRef, err)
	}
	if err := checkPolicyReplacement(lf.Resolved.Policy, currentPolicy); err != nil {
		return fmt.Errorf("run: mutable policy channel: policy %s: %w", policyRef, err)
	}
	if _, err := verifyPolicyChannelSignature(ctx, policyRef, currentPolicy.Digest, signing.VerifyOptions{}); err != nil {
		return fmt.Errorf("run: mutable policy channel: policy %s signature verification failed: %w", policyRef, err)
	}
	if issues := evaluatePolicyChannelArtifacts(cfg, lf, bundle, now); len(issues) > 0 {
		var msgs []string
		for _, issue := range issues {
			msgs = append(msgs, fmt.Sprintf("%s: %v", issue.label, issue.err))
		}
		return fmt.Errorf("run: mutable policy channel denied artifact(s): %s", strings.Join(msgs, "; "))
	}

	return nil
}

func stopManagedSidecar(out io.Writer, handle *sidecar.SidecarHandle) {
	dockerCli, cliErr := runNewDockerClient()
	if cliErr != nil {
		logger.Warn("failed to create docker client for sidecar teardown", zap.Error(cliErr))
		return
	}
	if stopErr := runStopSidecar(context.Background(), dockerCli, handle); stopErr != nil {
		logger.Warn("failed to stop agentcontainer-enforcer sidecar", zap.Error(stopErr))
		return
	}
	_, _ = fmt.Fprintf(out, "Enforcer stopped\n")
}

func resolveRuntimePolicy(cfg *config.AgentContainer) *policy.ContainerPolicy {
	var caps *config.Capabilities
	if cfg != nil && cfg.Agent != nil {
		caps = cfg.Agent.Capabilities
	}

	resolvedPolicy := policy.Resolve(caps)
	if cfg != nil && cfg.Agent != nil {
		resolvedPolicy.SecretACLs = policy.ResolveSecrets(cfg.Agent.Secrets, cfg.Agent.Tools)
	}
	return resolvedPolicy
}

// verifyImageSignature checks the cosign signature of imageRef when the
// workspace config requires provenance signatures (F-1). The ref passed should
// be the lockfile-pinned digest ref so the same manifest used for policy
// extraction is verified.
//
// If cosign is not installed and signatures are not required, the function
// returns nil (graceful degradation). If cosign is not installed but signatures
// ARE required, the function returns an error (fail-closed).
func verifyImageSignature(cmd *cobra.Command, cfg *config.AgentContainer, imageRef string) error {
	if imageRef == "" {
		return nil
	}
	// Determine whether signature verification is required by the workspace config.
	sigRequired := false
	var provenanceCfg *config.ProvenanceConfig
	if cfg.Agent != nil {
		provenanceCfg = cfg.Agent.Provenance
	}
	if provenanceCfg != nil && provenanceCfg.Require != nil && provenanceCfg.Require.Signatures {
		sigRequired = true
	}

	if !sigRequired {
		// Signature verification not required — skip silently.
		return nil
	}

	verifier := signing.NewCosignVerifier()
	opts := signing.VerifyOptions{}
	if provenanceCfg != nil && provenanceCfg.Require != nil {
		// Key-based verification is not wired via CLI at M0, but cert-based
		// keyless fields could be set via future config fields. For now we
		// use the zero VerifyOptions (keyless, online mode) which is the safe
		// default for Sigstore.
		_ = provenanceCfg
	}

	_, err := verifier.Verify(cmd.Context(), imageRef, opts)
	if err != nil {
		// ErrVerifyNotConfigured means cosign is not on PATH.
		// Since sigRequired is true at this point, we must fail closed.
		if errors.Is(err, signing.ErrVerifyNotConfigured) {
			return fmt.Errorf("cosign not found on PATH but provenance.require.signatures is true: install cosign or set --insecure-skip-verify for development")
		}
		return err
	}

	logger.Info("image signature verified", zap.String("ref", imageRef))
	return nil
}

// resolveSidecar discovers an external sidecar or auto-starts a managed one.
// Returns a SidecarHandle (possibly nil), the enforcement address to use, and any error.
func resolveSidecar(cmd *cobra.Command, cfg *config.AgentContainer) (*sidecar.SidecarHandle, string, error) {
	var enfCfg *config.EnforcerConfig
	if cfg.Agent != nil {
		enfCfg = cfg.Agent.Enforcer
	}

	// Determine config-level addr override.
	var configAddr string
	if enfCfg != nil {
		configAddr = enfCfg.Addr
	}

	// 1. Check for pre-existing sidecar.
	result := sidecar.DiscoverExternalSidecar(sidecar.DiscoverOptions{
		ConfigAddr: configAddr,
	})
	if result.Addr != "" {
		logger.Info("using pre-existing agentcontainer-enforcer",
			zap.String("addr", result.Addr),
			zap.String("source", result.Source),
		)
		return &sidecar.SidecarHandle{Addr: result.Addr, Managed: false}, result.Addr, nil
	}

	// 2. No external sidecar — auto-start if addr override not explicitly set.
	// If addr is configured but unreachable, that is an error.
	if configAddr != "" {
		return nil, "", fmt.Errorf("enforcer addr %q configured but sidecar not reachable", configAddr)
	}

	// 3. Auto-start.
	image := sidecar.DefaultEnforcerImage
	required := true // default-deny: fail-closed unless explicitly opted out
	if enfCfg != nil {
		if enfCfg.Image != "" {
			image = enfCfg.Image
		}
		if enfCfg.Required != nil {
			required = *enfCfg.Required
		}
	}

	dockerCli, err := client.New(client.FromEnv)
	if err != nil {
		if required {
			return nil, "", fmt.Errorf("enforcer: docker unavailable: %w", err)
		}
		logger.Warn("docker unavailable, enforcement disabled (required: false)", zap.Error(err))
		return nil, "", nil
	}

	_, _ = fmt.Fprintln(cmd.OutOrStdout(), "Starting agentcontainer-enforcer sidecar...")
	startOpts := sidecar.StartOptions{
		Image:    image,
		Required: required,
	}
	if runtime.GOOS == "linux" {
		socketDir, err := os.MkdirTemp("", "agentcontainer-enforcer-")
		if err != nil {
			if required {
				return nil, "", fmt.Errorf("enforcer: creating socket dir: %w", err)
			}
			logger.Warn("could not create enforcer socket directory, falling back to random TCP", zap.Error(err))
			startOpts.RandomHostPort = true
		} else {
			startOpts.SocketPath = filepath.Join(socketDir, "agentcontainer-enforcer.sock")
		}
	} else {
		startOpts.RandomHostPort = true
	}
	handle, err := sidecar.StartSidecar(cmd.Context(), dockerCli, startOpts)
	if err != nil {
		return nil, "", fmt.Errorf("enforcer: %w", err)
	}
	if handle == nil {
		// Only reachable when required: false
		logger.Warn("enforcer unavailable, enforcement disabled (required: false)")
		return nil, "", nil
	}

	return handle, handle.Addr, nil
}

// buildSecretsManager creates a secrets.Manager from the agent configuration,
// registering the appropriate providers based on SecretConfig.Provider values.
// URI schemes (e.g. op://vault/item/field) in the Provider field are detected
// and normalised to their canonical provider name before the provider switch.
// Returns the manager, a cleanup function, and any error.
func buildSecretsManager(ctx context.Context, cfg *config.AgentContainer) (*secrets.Manager, func(), error) {
	var opts []secrets.ManagerOption
	var cleanups []func()

	// Pre-process secrets to detect URI schemes in the Provider field.
	// A Provider value like "op://vault/item/field" must be resolved to its
	// canonical provider name ("1password") before the switch below, otherwise
	// the raw URI string falls through to the default branch and returns an
	// "unknown secret provider" error.
	processedSecrets := make(map[string]config.SecretConfig, len(cfg.Agent.Secrets))
	uriRefs := make(map[string]secrets.SecretRef)

	for name, sc := range cfg.Agent.Secrets {
		if ref, ok := secrets.ParseSecretURI(sc.Provider); ok {
			sc.Provider = ref.Provider
			uriRefs[name] = ref
		}
		processedSecrets[name] = sc
	}

	// Collect unique providers from the pre-processed secrets.
	providersSeen := make(map[string]bool)
	for _, sc := range processedSecrets {
		providersSeen[sc.Provider] = true
	}

	for provider := range providersSeen {
		switch provider {
		case "env":
			opts = append(opts, secrets.WithProvider(secrets.NewEnvProvider()))

		case "oidc":
			issuer, err := oidc.NewIssuer()
			if err != nil {
				return nil, nil, fmt.Errorf("creating OIDC issuer: %w", err)
			}
			if err := issuer.Start(); err != nil {
				return nil, nil, fmt.Errorf("starting OIDC issuer: %w", err)
			}
			cleanups = append(cleanups, func() {
				_ = issuer.Stop(context.Background())
			})
			opts = append(opts, secrets.WithProvider(secrets.NewOIDCProvider(issuer)))

		case "vault":
			var vaultOpts []secrets.VaultProviderOption
			if sock := os.Getenv("VAULT_AGENT_SOCKET"); sock != "" {
				vaultOpts = append(vaultOpts, secrets.WithVaultSocket(sock))
			}
			if addr := os.Getenv("VAULT_ADDR"); addr != "" {
				vaultOpts = append(vaultOpts, secrets.WithVaultAddr(addr))
			}
			if token := os.Getenv("VAULT_TOKEN"); token != "" {
				vaultOpts = append(vaultOpts, secrets.WithVaultToken(token))
			}
			opts = append(opts, secrets.WithProvider(secrets.NewVaultProvider(vaultOpts...)))

		case "infisical":
			var infisicalOpts []secrets.InfisicalProviderOption
			if sock := os.Getenv("INFISICAL_SOCKET"); sock != "" {
				infisicalOpts = append(infisicalOpts, secrets.WithInfisicalSocket(sock))
			}
			if apiURL := os.Getenv("INFISICAL_API_URL"); apiURL != "" {
				infisicalOpts = append(infisicalOpts, secrets.WithInfisicalAddr(apiURL))
			}
			clientID := os.Getenv("INFISICAL_CLIENT_ID")
			clientSecret := os.Getenv("INFISICAL_CLIENT_SECRET")
			if (clientID == "") != (clientSecret == "") {
				return nil, nil, fmt.Errorf("INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET must both be set or both be unset")
			}
			if clientID != "" {
				infisicalOpts = append(infisicalOpts, secrets.WithInfisicalAuth(clientID, clientSecret))
			}
			opts = append(opts, secrets.WithProvider(secrets.NewInfisicalProvider(infisicalOpts...)))

		case "1password":
			// Default: `op` CLI via 1Password desktop app agent socket.
			// Enterprise: set OP_CONNECT_HOST + OP_CONNECT_TOKEN for Connect Server.
			var opOpts []secrets.OnePasswordProviderOption
			if host := os.Getenv("OP_CONNECT_HOST"); host != "" {
				opOpts = append(opOpts, secrets.WithOnePasswordAddr(host))
			}
			if token := os.Getenv("OP_CONNECT_TOKEN"); token != "" {
				opOpts = append(opOpts, secrets.WithOnePasswordToken(token))
			}
			opts = append(opts, secrets.WithProvider(secrets.NewOnePasswordProvider(opOpts...)))

		default:
			return nil, nil, fmt.Errorf("unknown secret provider %q", provider)
		}
	}

	mgr := secrets.NewManager(opts...)

	// Build SecretRefs: use URI-parsed ref if available (preserving parsed
	// params), otherwise derive from the structured SecretConfig fields.
	var refs []secrets.SecretRef
	for name, sc := range processedSecrets {
		if uriRef, ok := uriRefs[name]; ok {
			uriRef.Name = name
			refs = append(refs, uriRef)
			continue
		}
		ref := secrets.SecretRef{
			Name:     name,
			Provider: sc.Provider,
			Params:   make(map[string]string),
		}
		if sc.Audience != "" {
			ref.Params["audience"] = sc.Audience
		}
		if sc.TTL != "" {
			ref.Params["ttl"] = sc.TTL
		}
		if sc.Path != "" {
			ref.Params["path"] = sc.Path
		}
		if sc.Role != "" {
			ref.Params["role"] = sc.Role
		}
		if sc.Key != "" {
			ref.Params["key"] = sc.Key
		}
		if sc.Mount != "" {
			ref.Params["mount"] = sc.Mount
		}
		refs = append(refs, ref)
	}

	if _, err := mgr.ResolveAll(ctx, refs); err != nil {
		for _, fn := range cleanups {
			fn()
		}
		return nil, nil, err
	}

	cleanup := func() {
		_ = mgr.Close()
		for _, fn := range cleanups {
			fn()
		}
	}

	return mgr, cleanup, nil
}

// printEnforcementEvent formats a BPF enforcement event for user display.
// Only block events are shown — allow events are too noisy for the terminal.
func printEnforcementEvent(w io.Writer, evt enforcement.Event) {
	if evt.Verdict != enforcement.VerdictBlock {
		return
	}

	var detail string
	switch evt.Type {
	case enforcement.EventNetConnect, enforcement.EventNetSendmsg, enforcement.EventNetBind:
		detail = "network access"
	case enforcement.EventFSOpen:
		if evt.FS != nil && evt.FS.Path != "" {
			detail = fmt.Sprintf("file access: %s", evt.FS.Path)
		} else {
			detail = "file access"
		}
	case enforcement.EventExec:
		if evt.Exec != nil && evt.Exec.Binary != "" {
			detail = fmt.Sprintf("exec: %s", evt.Exec.Binary)
		} else {
			detail = "process execution"
		}
	case enforcement.EventCred:
		detail = "credential access"
	default:
		detail = "unknown operation"
	}

	_, _ = fmt.Fprintf(w, "[BLOCKED] pid=%d comm=%s %s\n", evt.PID, evt.Comm, detail)
}

// runEnforcerLiveness polls the enforcer gRPC health endpoint every interval.
// After maxFails consecutive failures it closes dead and calls cancel so the
// caller's select loop wakes and triggers container teardown (fail-closed).
// probe is the health-check function; pass enforcement.ProbeEnforcerHealth in
// production and a stub in tests.
func runEnforcerLiveness(ctx context.Context, cancel context.CancelFunc, addr string, interval time.Duration, maxFails int, dead chan struct{}, probe func(string) bool) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	consecutiveFails := 0
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if probe(addr) {
				consecutiveFails = 0
			} else {
				consecutiveFails++
				logger.Warn("enforcer health check failed",
					zap.String("addr", addr),
					zap.Int("consecutive_fails", consecutiveFails),
				)
				if consecutiveFails >= maxFails {
					logger.Error("enforcer unreachable, stopping container",
						zap.String("addr", addr),
					)
					close(dead)
					cancel()
					return
				}
			}
		}
	}
}
