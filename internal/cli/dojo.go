package cli

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/dojo"
)

var runDojo = dojo.Run

func newDojoCmd() *cobra.Command {
	var (
		baseDir               string
		image                 string
		enforcerImage         string
		runtimeFlag           string
		model                 string
		buildImage            bool
		noBuild               bool
		noStart               bool
		noChat                bool
		shell                 bool
		insecureSkipOrgPolicy bool
	)

	cmd := &cobra.Command{
		Use:   "dojo [profile]",
		Short: "Start a disposable adversarial harness and drop into chat",
		Long: `Prepare a disposable adversarial harness, start it under
agentcontainers enforcement, and drop into an interactive agent chat.

Available profiles:
  codex-redteam    General bounded escape-test prompt with canaries
  procfs-runc      Procfs/sysfs/cgroup and runtime setup confusion sweep
  runtime-sockets  Runtime socket, Kubernetes token, and metadata sweep

The default profile is codex-redteam. Each profile creates host/workspace
canaries, starts a locked-down Codex container, and passes a scoped prompt to
Codex automatically.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profile := dojo.ProfileCodexRedteam
			if len(args) > 0 {
				profile = args[0]
			}
			if noBuild {
				buildImage = false
			}
			agentPath, err := os.Executable()
			if err != nil {
				return fmt.Errorf("dojo: resolving current executable: %w", err)
			}

			_, err = runDojo(cmd.Context(), dojo.Options{
				Profile:               profile,
				BaseDir:               baseDir,
				AgentcontainerPath:    agentPath,
				Image:                 image,
				EnforcerImage:         enforcerImage,
				Runtime:               runtimeFlag,
				Model:                 model,
				BuildImage:            buildImage,
				NoStart:               noStart,
				NoChat:                noChat,
				Shell:                 shell,
				InsecureSkipOrgPolicy: insecureSkipOrgPolicy,
				Stdin:                 cmd.InOrStdin(),
				Stdout:                cmd.OutOrStdout(),
				Stderr:                cmd.ErrOrStderr(),
			})
			return err
		},
	}

	cmd.Flags().StringVar(&baseDir, "base-dir", "", "Directory for the disposable dojo workspace (default: mktemp)")
	cmd.Flags().StringVar(&image, "image", "agentcontainer-codex-redteam:verify", "Agent container image to run")
	cmd.Flags().StringVar(&enforcerImage, "enforcer-image", dojoEnvDefault("AC_ENFORCER_IMAGE", "agentcontainer-enforcer:verify"), "agentcontainer-enforcer image")
	cmd.Flags().StringVar(&runtimeFlag, "runtime", "docker", "Container runtime backend (auto|docker|compose|sandbox)")
	cmd.Flags().StringVar(&model, "model", "", "Codex model to request for chat")
	cmd.Flags().BoolVar(&buildImage, "build-image", true, "Build the default Codex red-team image before starting")
	cmd.Flags().BoolVar(&noBuild, "no-build", false, "Skip building the default Codex red-team image")
	cmd.Flags().BoolVar(&noStart, "no-start", false, "Prepare files and print commands without starting the container")
	cmd.Flags().BoolVar(&noChat, "no-chat", false, "Start the harness but do not enter Codex chat")
	cmd.Flags().BoolVar(&shell, "shell", false, "Drop into an interactive shell instead of Codex chat")
	cmd.Flags().BoolVar(&insecureSkipOrgPolicy, "insecure-skip-org-policy", false, "Skip image org-policy extraction for local dojo images (dev only)")

	return cmd
}

func dojoEnvDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
