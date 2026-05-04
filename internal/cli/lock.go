package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
)

func newLockCmd() *cobra.Command {
	var (
		configPath string
		outputPath string
	)

	cmd := &cobra.Command{
		Use:   "lock",
		Short: "Generate a lockfile pinning all artifacts by digest",
		Long: `Resolve all OCI references in agentcontainer.json (images, features,
MCP servers, skills) to their current digests and write an
agentcontainer-lock.json lockfile.

The lockfile should be committed to source control to ensure
reproducible, verifiable agent environments.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runLock(cmd, configPath, outputPath)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json (auto-detected if omitted)")
	cmd.Flags().StringVarP(&outputPath, "output", "o", "", "Output path for lockfile (default: agentcontainer-lock.json next to config)")

	return cmd
}

// resolverFactory allows tests to inject a mock resolver.
var resolverFactory func() *oci.Resolver

func newOCIResolver() *oci.Resolver {
	if resolverFactory != nil {
		return resolverFactory()
	}
	return oci.NewResolver()
}

func runLock(cmd *cobra.Command, configPath, outputPath string) error {
	out := cmd.OutOrStdout()
	ctx := cmd.Context()
	if ctx == nil {
		ctx = context.Background()
	}

	// 1. Resolve the config file path.
	var cfgDir string
	if configPath == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		_, resolved, err := config.Load(cwd)
		if err != nil {
			return fmt.Errorf("lock: %w", err)
		}
		configPath = resolved
		cfgDir = filepath.Dir(resolved)
	} else {
		absPath, err := filepath.Abs(configPath)
		if err != nil {
			return fmt.Errorf("lock: resolving config path: %w", err)
		}
		configPath = absPath
		cfgDir = filepath.Dir(absPath)
	}

	// 2. Parse the config.
	cfg, err := config.ParseFile(configPath)
	if err != nil {
		return fmt.Errorf("lock: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("lock: invalid config: %w", err)
	}

	// 3. Build the lockfile by resolving all references.
	resolver := newOCIResolver()
	now := time.Now().UTC()

	lf := &config.Lockfile{
		Version:     2,
		GeneratedAt: now,
		GeneratedBy: "agentcontainer",
		Resolved:    config.ResolvedArtifacts{},
	}

	// Resolve base image digest.
	if cfg.Image != "" {
		digest, err := resolver.Resolve(ctx, cfg.Image)
		if err != nil {
			return fmt.Errorf("lock: resolving image %s: %w", cfg.Image, err)
		}
		lf.Resolved.Image = &config.ResolvedImage{
			Digest:     digest,
			ResolvedAt: now,
		}
		_, _ = fmt.Fprintf(out, "  image: %s -> %s\n", cfg.Image, digest)
	}

	// Resolve feature references to digests.
	if len(cfg.Features) > 0 {
		lf.Resolved.Features = make(map[string]config.ResolvedFeature)
		for ref := range cfg.Features {
			digest, err := resolver.Resolve(ctx, ref)
			if err != nil {
				return fmt.Errorf("lock: resolving feature %s: %w", ref, err)
			}
			lf.Resolved.Features[ref] = config.ResolvedFeature{
				Digest:     digest,
				ResolvedAt: now,
			}
			_, _ = fmt.Fprintf(out, "  feature: %s -> %s\n", ref, digest)
		}
	}

	// Resolve MCP server images to digests.
	if cfg.Agent != nil && cfg.Agent.Tools != nil && len(cfg.Agent.Tools.MCP) > 0 {
		lf.Resolved.MCP = make(map[string]config.ResolvedMCP)
		for name, mcp := range cfg.Agent.Tools.MCP {
			digest, err := resolver.Resolve(ctx, mcp.Image)
			if err != nil {
				return fmt.Errorf("lock: resolving mcp %s (%s): %w", name, mcp.Image, err)
			}
			lf.Resolved.MCP[name] = config.ResolvedMCP{
				Digest:     digest,
				ResolvedAt: now,
			}
			_, _ = fmt.Fprintf(out, "  mcp: %s (%s) -> %s\n", name, mcp.Image, digest)
		}
	}

	// Resolve skill artifacts to digests.
	if cfg.Agent != nil && cfg.Agent.Tools != nil && len(cfg.Agent.Tools.Skills) > 0 {
		lf.Resolved.Skills = make(map[string]config.ResolvedSkill)
		for name, skill := range cfg.Agent.Tools.Skills {
			digest, err := resolver.Resolve(ctx, skill.Artifact)
			if err != nil {
				return fmt.Errorf("lock: resolving skill %s (%s): %w", name, skill.Artifact, err)
			}
			lf.Resolved.Skills[name] = config.ResolvedSkill{
				Digest:     digest,
				ResolvedAt: now,
			}
			_, _ = fmt.Fprintf(out, "  skill: %s (%s) -> %s\n", name, skill.Artifact, digest)
		}
	}

	if policyRef := configuredPolicyRef(cfg); policyRef != "" {
		resolvedPolicy, _, err := resolvePolicyChannel(ctx, resolver, policyRef, now)
		if err != nil {
			return fmt.Errorf("lock: resolving policy %s: %w", policyRef, err)
		}
		lf.Resolved.Policy = resolvedPolicy
		_, _ = fmt.Fprintf(out, "  policy: %s -> %s (epoch %d)\n", policyRef, resolvedPolicy.Digest, resolvedPolicy.Epoch)
	}

	// 4. Determine output path.
	if outputPath == "" {
		outputPath = filepath.Join(cfgDir, config.LockfileName)
	}

	// 5. Write the lockfile.
	if err := config.WriteLockfile(outputPath, lf); err != nil {
		return fmt.Errorf("lock: %w", err)
	}

	_, _ = fmt.Fprintf(out, "Lockfile written to %s\n", outputPath)
	return nil
}
