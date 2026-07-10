package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/dojo"
)

func main() {
	var (
		baseDir       = flag.String("base-dir", "", "directory for the disposable red-team workspace (default: mktemp)")
		agentBin      = flag.String("agentcontainer", "tmp/agentcontainer", "path to the agentcontainer binary")
		image         = flag.String("image", "agentcontainer-codex-redteam:verify", "agent container image to run")
		enforcerImage = flag.String("enforcer-image", envDefault("AC_ENFORCER_IMAGE", "agentcontainer-enforcer:verify"), "agentcontainer-enforcer image")
		buildImage    = flag.Bool("build-image", true, "build the default Codex red-team image before starting")
		noStart       = flag.Bool("no-start", false, "prepare files and print commands without starting the container")
	)
	flag.Parse()

	if _, err := dojo.Run(context.Background(), dojo.Options{
		Profile:            dojo.ProfileCodexRedteam,
		BaseDir:            *baseDir,
		AgentcontainerPath: *agentBin,
		Image:              *image,
		EnforcerImage:      *enforcerImage,
		BuildImage:         *buildImage,
		NoStart:            *noStart,
		NoChat:             true,
		Stdin:              os.Stdin,
		Stdout:             os.Stdout,
		Stderr:             os.Stderr,
	}); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func envDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}
