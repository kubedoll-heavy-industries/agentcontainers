package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/orgpolicy"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

type policyBundleFetcher interface {
	FetchPolicyBundle(ctx context.Context, policyRef string) ([]byte, string, error)
}

type policyArtifactDigest struct {
	label  string
	digest string
}

type policyEvaluationIssue struct {
	label string
	err   error
}

type policyCoverageIssue struct {
	label string
}

var policySignatureVerifierFactory = func() signing.Verifier {
	return signing.NewCosignVerifier()
}

func configuredPolicyRef(cfg *config.AgentContainer) string {
	if cfg == nil || cfg.Agent == nil || cfg.Agent.Provenance == nil || cfg.Agent.Provenance.Policy == nil {
		return ""
	}
	return strings.TrimSpace(cfg.Agent.Provenance.Policy.Ref)
}

func resolvePolicyChannel(ctx context.Context, fetcher policyBundleFetcher, policyRef string, now time.Time) (*config.ResolvedPolicy, *orgpolicy.PolicyBundle, error) {
	data, manifestDigest, err := fetcher.FetchPolicyBundle(ctx, policyRef)
	if err != nil {
		return nil, nil, err
	}

	bundle, err := orgpolicy.ParsePolicyBundle(data)
	if err != nil {
		return nil, nil, err
	}

	return &config.ResolvedPolicy{
		Ref:        policyRef,
		Digest:     manifestDigest,
		Epoch:      bundle.Epoch,
		ExpiresAt:  bundle.ExpiresAt,
		ResolvedAt: now,
	}, bundle, nil
}

func checkPolicyReplacement(locked, current *config.ResolvedPolicy) error {
	if locked == nil {
		return fmt.Errorf("missing resolved policy in lockfile")
	}
	if current == nil {
		return fmt.Errorf("missing current policy")
	}
	if current.Epoch < locked.Epoch {
		return fmt.Errorf("rollback detected: current epoch %d is lower than locked epoch %d", current.Epoch, locked.Epoch)
	}
	if current.Epoch == locked.Epoch && current.Digest != locked.Digest {
		return fmt.Errorf("same-epoch policy replacement detected: epoch %d changed digest from %s to %s", locked.Epoch, locked.Digest, current.Digest)
	}
	return nil
}

func verifyPolicyChannelSignature(ctx context.Context, policyRef, digest string, opts signing.VerifyOptions) (*config.SignatureRef, error) {
	if strings.TrimSpace(policyRef) == "" {
		return nil, fmt.Errorf("policy ref is empty")
	}
	if strings.TrimSpace(digest) == "" {
		return nil, fmt.Errorf("policy digest is empty")
	}

	digestRef := digestPinnedRef(policyRef, digest)
	result, err := policySignatureVerifierFactory().Verify(ctx, digestRef, opts)
	if err != nil {
		if errors.Is(err, signing.ErrVerifyNotConfigured) {
			return nil, fmt.Errorf("cosign not found on PATH for mutable policy channel %s: signed org policy bundles are required", policyRef)
		}
		return nil, err
	}
	if result == nil || !result.Verified {
		return nil, fmt.Errorf("policy signature not verified for %s", digestRef)
	}

	return &config.SignatureRef{
		KeylessRef: digestRef,
		Issuer:     result.IssuerURL,
		Subject:    result.SignerIdentity,
	}, nil
}

func digestPinnedRef(ref, digest string) string {
	base := strings.TrimSpace(ref)
	if before, _, ok := strings.Cut(base, "@"); ok {
		base = before
	}
	return base + "@" + digest
}

func requirePolicyChannelLockCoverage(cfg *config.AgentContainer, lf *config.Lockfile) []policyCoverageIssue {
	if lf == nil {
		return []policyCoverageIssue{{label: "lockfile"}}
	}

	var issues []policyCoverageIssue
	if cfg != nil && cfg.Image != "" && lf.Resolved.Image == nil {
		issues = append(issues, policyCoverageIssue{label: "image " + cfg.Image})
	}

	if cfg != nil {
		featureRefs := make([]string, 0, len(cfg.Features))
		for ref := range cfg.Features {
			featureRefs = append(featureRefs, ref)
		}
		sort.Strings(featureRefs)
		for _, ref := range featureRefs {
			if _, ok := lf.Resolved.Features[ref]; !ok {
				issues = append(issues, policyCoverageIssue{label: "feature " + ref})
			}
		}
	}

	if cfg == nil || cfg.Agent == nil || cfg.Agent.Tools == nil {
		return issues
	}

	mcpNames := make([]string, 0, len(cfg.Agent.Tools.MCP))
	for name := range cfg.Agent.Tools.MCP {
		mcpNames = append(mcpNames, name)
	}
	sort.Strings(mcpNames)
	for _, name := range mcpNames {
		if _, ok := lf.Resolved.MCP[name]; !ok {
			issues = append(issues, policyCoverageIssue{label: "mcp " + name})
		}
	}

	skillNames := make([]string, 0, len(cfg.Agent.Tools.Skills))
	for name := range cfg.Agent.Tools.Skills {
		skillNames = append(skillNames, name)
	}
	sort.Strings(skillNames)
	for _, name := range skillNames {
		if _, ok := lf.Resolved.Skills[name]; !ok {
			issues = append(issues, policyCoverageIssue{label: "skill " + name})
		}
	}

	return issues
}

func evaluatePolicyChannelArtifacts(cfg *config.AgentContainer, lf *config.Lockfile, bundle *orgpolicy.PolicyBundle, now time.Time) []policyEvaluationIssue {
	var issues []policyEvaluationIssue
	for _, artifact := range pinnedPolicyArtifacts(cfg, lf) {
		for _, err := range orgpolicy.EvaluatePolicyBundle(bundle, artifact.digest, now) {
			issues = append(issues, policyEvaluationIssue{
				label: artifact.label,
				err:   err,
			})
		}
	}
	return issues
}

func pinnedPolicyArtifacts(cfg *config.AgentContainer, lf *config.Lockfile) []policyArtifactDigest {
	if lf == nil {
		return nil
	}

	var artifacts []policyArtifactDigest
	if lf.Resolved.Image != nil {
		label := "image"
		if cfg != nil && cfg.Image != "" {
			label += " " + cfg.Image
		}
		artifacts = append(artifacts, policyArtifactDigest{label: label, digest: lf.Resolved.Image.Digest})
	}

	featureRefs := make([]string, 0, len(lf.Resolved.Features))
	for ref := range lf.Resolved.Features {
		featureRefs = append(featureRefs, ref)
	}
	sort.Strings(featureRefs)
	for _, ref := range featureRefs {
		artifacts = append(artifacts, policyArtifactDigest{
			label:  "feature " + ref,
			digest: lf.Resolved.Features[ref].Digest,
		})
	}

	mcpNames := make([]string, 0, len(lf.Resolved.MCP))
	for name := range lf.Resolved.MCP {
		mcpNames = append(mcpNames, name)
	}
	sort.Strings(mcpNames)
	for _, name := range mcpNames {
		label := "mcp " + name
		if cfg != nil && cfg.Agent != nil && cfg.Agent.Tools != nil {
			if mcp, ok := cfg.Agent.Tools.MCP[name]; ok && mcp.Image != "" {
				label += " (" + mcp.Image + ")"
			}
		}
		artifacts = append(artifacts, policyArtifactDigest{label: label, digest: lf.Resolved.MCP[name].Digest})
	}

	skillNames := make([]string, 0, len(lf.Resolved.Skills))
	for name := range lf.Resolved.Skills {
		skillNames = append(skillNames, name)
	}
	sort.Strings(skillNames)
	for _, name := range skillNames {
		label := "skill " + name
		if cfg != nil && cfg.Agent != nil && cfg.Agent.Tools != nil {
			if skill, ok := cfg.Agent.Tools.Skills[name]; ok && skill.Artifact != "" {
				label += " (" + skill.Artifact + ")"
			}
		}
		artifacts = append(artifacts, policyArtifactDigest{label: label, digest: lf.Resolved.Skills[name].Digest})
	}

	return artifacts
}
