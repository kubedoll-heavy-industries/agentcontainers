package cli

import (
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var (
	verbose bool
	quiet   bool
	noColor bool
	logger  *zap.Logger
)

func newRootCmd(version, commit, date string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agentcontainer",
		Short: "Immutable, reproducible, least-privilege runtime environments for AI agents",
		Long: `agentcontainer extends devcontainers with security policy,
supply chain verification, and human-in-the-loop permission approval
for AI agent runtime environments.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			var err error
			logger, err = newLogger(verbose)
			return err
		},
	}

	cmd.PersistentFlags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose output")
	cmd.PersistentFlags().BoolVar(&quiet, "quiet", false, "Suppress non-error output")
	cmd.PersistentFlags().BoolVar(&noColor, "no-color", false, "Disable colored output")

	cmd.AddCommand(
		newVersionCmd(version, commit, date),
		newInitCmd(),
		newRunCmd(),
		newStopCmd(),
		newExecCmd(),
		newLogsCmd(),
		newSaveCmd(),
		newBuildCmd(),
		newDojoCmd(),
		newPsCmd(),
		newUpdateCmd(),
		newLockCmd(),
		newVerifyCmd(),
		newSbomCmd(),
		newShimCmd(),
		newGcCmd(),
		newEnforcerCmd(),
		newAuditCmd(),
		newComponentCmd(),
		newSignCmd(),
		newDriftCmd(),
		newAttestCmd(),
		newTUFCmd(),
		newPolicyCmd(),
	)

	return cmd
}

// Execute runs the root command.
func Execute(version, commit, date string) error {
	return newRootCmd(version, commit, date).Execute()
}

func newLogger(verbose bool) (*zap.Logger, error) {
	if verbose {
		return zap.NewDevelopment()
	}
	return zap.NewProduction()
}
