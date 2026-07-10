package cli

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/approval"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/container"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/enforcement"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oidc"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/secrets"
)

var execRuntimeFactory = newRuntime

func newExecCmd() *cobra.Command {
	var (
		runtime     string
		configPath  string
		envVars     []string
		interactive bool
	)

	cmd := &cobra.Command{
		Use:   "exec <container-id> -- <command...>",
		Short: "Execute a command inside a running agent container",
		Long: `Run a command inside the primary container identified by <container-id>.
Everything after "--" is treated as the command and its arguments.

The command is checked against the agent capability policy before execution.
Use --config to specify the agentcontainer.json; if omitted, the config is
loaded from the working directory.

Environment variables can be injected with -e KEY=VALUE. Secret URI schemes
(e.g. op://vault/item/field) are resolved on demand before execution.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			containerID := args[0]
			cmdArgs := args[1:]

			if len(cmdArgs) == 0 {
				return fmt.Errorf("exec: no command specified (usage: agentcontainer exec <container-id> -- <command> [args...])")
			}

			return runExec(cmd, containerID, cmdArgs, runtime, configPath, envVars, interactive)
		},
	}

	cmd.Flags().StringVar(&runtime, "runtime", "docker", "Container runtime backend (auto|docker|compose|sandbox)")
	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json")
	cmd.Flags().StringArrayVarP(&envVars, "env", "e", nil, "Set environment variables (KEY=VALUE or KEY=op://...)")
	cmd.Flags().BoolVarP(&interactive, "interactive", "i", false, "Attach stdin and allocate a TTY for interactive commands")

	return cmd
}

func runExec(cmd *cobra.Command, containerID string, execCmd []string, runtimeFlag string, configPath string, envVars []string, interactive bool) error {
	// BPF enforcement is already active on the container's cgroup from agentcontainer run.
	// The runtime here only needs LevelNone because we are not re-applying
	// policy — the approval broker provides the Go-side defense-in-depth.
	rt, err := execRuntimeFactory(runtimeFlag, logger, enforcement.LevelNone)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	// Load config to wire the approval broker. Config is optional for exec —
	// the container is already running with BPF enforcement from `run`. Without
	// a config, exec runs with default-deny approval (every command prompted).
	cfg, cfgPath, err := loadConfig(configPath)
	if err != nil {
		if configPath == "" && isConfigAbsent(err) {
			// No config found — run with empty capabilities (default-deny approval).
			cfg = &config.AgentContainer{}
			cfgPath = ""
		} else {
			return err
		}
	}

	var caps *config.Capabilities
	var escalation string
	if cfg.Agent != nil {
		caps = cfg.Agent.Capabilities
		if cfg.Agent.Policy != nil {
			escalation = cfg.Agent.Policy.Escalation
		}
	}

	approvalMgr := approval.NewManager(
		approval.NewTerminalApprover(approval.WithOutput(cmd.OutOrStdout())),
		cfgPath,
		caps,
		approval.WithEscalation(escalation),
	)
	defer func() {
		if persistErr := approvalMgr.Persist(); persistErr != nil {
			logger.Warn("failed to persist capabilities")
		}
	}()

	brokerRT := approval.NewBroker(rt, approvalMgr)

	// Resolve any secret URI schemes in the --env flag values before executing.
	// Values like KEY=op://vault/item/field are resolved on demand using a
	// temporary single-provider Manager that is torn down after resolution.
	resolvedEnv, err := resolveExecEnv(cmd.Context(), envVars)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}
	// The Runtime.Exec interface only accepts a command slice. When env vars
	// have been resolved, prepend them to the command via POSIX `env` so that
	// the container process sees the correct environment without requiring an
	// interface change.
	finalCmd := execCmd
	if len(resolvedEnv) > 0 {
		envArgs := append([]string{"env"}, resolvedEnv...)
		finalCmd = append(envArgs, execCmd...)
	}

	session := &container.Session{
		ContainerID: containerID,
		RuntimeType: container.RuntimeType(runtimeFlag),
	}

	if interactive {
		exitCode, err := brokerRT.ExecInteractive(cmd.Context(), session, finalCmd, container.ExecIO{
			Stdin:  cmd.InOrStdin(),
			Stdout: cmd.OutOrStdout(),
			Stderr: cmd.ErrOrStderr(),
			TTY:    true,
		})
		if err != nil {
			return fmt.Errorf("exec: %w", err)
		}
		if exitCode != 0 {
			return fmt.Errorf("exec: command exited with code %d", exitCode)
		}
		return nil
	}

	result, err := brokerRT.Exec(cmd.Context(), session, finalCmd)
	if err != nil {
		return fmt.Errorf("exec: %w", err)
	}

	if len(result.Stdout) > 0 {
		_, _ = fmt.Fprint(cmd.OutOrStdout(), string(result.Stdout))
	}
	if len(result.Stderr) > 0 {
		_, _ = fmt.Fprint(cmd.ErrOrStderr(), string(result.Stderr))
	}

	if result.ExitCode != 0 {
		return fmt.Errorf("exec: command exited with code %d", result.ExitCode)
	}

	return nil
}

func resolveExecEnv(ctx context.Context, envVars []string) ([]string, error) {
	var resolvedEnv []string
	for _, envStr := range envVars {
		parts := strings.SplitN(envStr, "=", 2)
		if len(parts) != 2 {
			value, ok := os.LookupEnv(envStr)
			if !ok {
				return nil, fmt.Errorf("environment variable %q is not set", envStr)
			}
			resolvedEnv = append(resolvedEnv, envStr+"="+value)
			continue
		}
		ref, ok := secrets.ParseSecretURI(parts[1])
		if !ok {
			// Plain value — pass through as-is.
			resolvedEnv = append(resolvedEnv, envStr)
			continue
		}
		ref.Name = parts[0]
		secret, err := resolveSecretOnDemand(ctx, ref)
		if err != nil {
			return nil, fmt.Errorf("resolving secret for env %q: %w", parts[0], err)
		}
		resolvedEnv = append(resolvedEnv, parts[0]+"="+string(secret.Value))
	}
	return resolvedEnv, nil
}

func isConfigAbsent(err error) bool {
	return errors.Is(err, os.ErrNotExist) || strings.Contains(err.Error(), "no agentcontainer.json or devcontainer.json found")
}

// resolveSecretOnDemand creates a temporary Manager, registers the single
// required provider, resolves the secret, and tears everything down.
// It is used to resolve URI-scheme secret references passed via --env.
// Provider options mirror the env-var plumbing in buildSecretsManager (run.go)
// so that VAULT_ADDR, VAULT_TOKEN, INFISICAL_*, OP_CONNECT_* etc. are honoured.
func resolveSecretOnDemand(ctx context.Context, ref secrets.SecretRef) (*secrets.Secret, error) {
	var provider secrets.Provider
	switch ref.Provider {
	case "env":
		provider = secrets.NewEnvProvider()
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
		provider = secrets.NewVaultProvider(vaultOpts...)
	case "1password":
		var opOpts []secrets.OnePasswordProviderOption
		if host := os.Getenv("OP_CONNECT_HOST"); host != "" {
			opOpts = append(opOpts, secrets.WithOnePasswordAddr(host))
		}
		if token := os.Getenv("OP_CONNECT_TOKEN"); token != "" {
			opOpts = append(opOpts, secrets.WithOnePasswordToken(token))
		}
		provider = secrets.NewOnePasswordProvider(opOpts...)
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
			return nil, fmt.Errorf("INFISICAL_CLIENT_ID and INFISICAL_CLIENT_SECRET must both be set or both be unset")
		}
		if clientID != "" {
			infisicalOpts = append(infisicalOpts, secrets.WithInfisicalAuth(clientID, clientSecret))
		}
		provider = secrets.NewInfisicalProvider(infisicalOpts...)
	case "oidc":
		issuer, err := oidc.NewIssuer()
		if err != nil {
			return nil, fmt.Errorf("creating OIDC issuer: %w", err)
		}
		if err := issuer.Start(); err != nil {
			return nil, fmt.Errorf("starting OIDC issuer: %w", err)
		}
		defer issuer.Stop(context.Background()) //nolint:errcheck
		provider = secrets.NewOIDCProvider(issuer)
	default:
		return nil, fmt.Errorf("unsupported provider %q for on-demand resolution", ref.Provider)
	}
	defer provider.Close() //nolint:errcheck

	mgr := secrets.NewManager(secrets.WithProvider(provider))
	defer mgr.Close() //nolint:errcheck

	return mgr.Resolve(ctx, ref)
}
