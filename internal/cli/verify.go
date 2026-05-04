package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/config"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/oci"
	"github.com/Kubedoll-Heavy-Industries/agentcontainers/internal/signing"
)

func newVerifyCmd() *cobra.Command {
	var (
		configPath      string
		lockfilePath    string
		strict          bool
		registry        bool
		signatures      bool
		provenance      bool
		keyPath         string
		certIdentity    string
		certIssuer      string
		offline         bool
		trustedRootPath string
		bundlePath      string
		certChainPath   string
		saveBundleDir   string
	)

	cmd := &cobra.Command{
		Use:   "verify",
		Short: "Verify all artifacts against the lockfile",
		Long: `Check that all OCI references in agentcontainer.json match the digests
recorded in agentcontainer-lock.json. Reports any mismatches.

By default, digests are checked against the live registry to detect stale
lockfile entries (--registry, enabled by default). Use --registry=false to
skip registry checks and only verify lockfile coverage.

With --signatures, also verify Sigstore cosign signatures on all OCI artifacts.
Use --key for key-based verification, or --cert-identity and --cert-issuer for
keyless (Fulcio) verification.

With --provenance, verify SLSA provenance attestations on all OCI artifacts.
Checks the SLSA build level against the agentcontainer.json provenance.require.slsaLevel
setting and validates the builder identity against the trustedBuilders list.

Offline verification (--offline) verifies signatures without network access to
Rekor or Fulcio. Requires one of:
  --key              Verify against a local public key (fully offline)
  --bundle           Verify using a Sigstore bundle (.sigstore.json)
  --trusted-root     Verify using a local TUF trusted root
  --certificate-chain Verify certificate chain from a local PEM file

When --offline is set, --registry is automatically disabled.

In strict mode (--strict), any mismatch or stale entry causes a non-zero exit code.
Without --strict, issues are reported as warnings.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Offline mode validation.
			if offline {
				// Require at least one trust anchor for offline verification.
				if trustedRootPath == "" && bundlePath == "" && keyPath == "" {
					return fmt.Errorf("verify: --offline requires --trusted-root, --bundle, or --key")
				}
				// Warn if user explicitly enabled registry with offline.
				if cmd.Flags().Changed("registry") && registry {
					return fmt.Errorf("verify: --offline and --registry are mutually exclusive")
				}
				// Validate that path arguments don't look like flags.
				for _, p := range []string{trustedRootPath, bundlePath, certChainPath} {
					if p != "" && len(p) > 0 && p[0] == '-' {
						return fmt.Errorf("verify: path argument %q looks like a flag; use an absolute or relative path", p)
					}
				}
				registry = false
				signatures = true
			}

			// --save-bundle validation.
			if saveBundleDir != "" {
				if !signatures {
					return fmt.Errorf("verify: --save-bundle requires --signatures")
				}
				if offline {
					return fmt.Errorf("verify: --save-bundle and --offline are mutually exclusive")
				}
			}

			var sigOpts *sigVerifyOpts
			if signatures {
				sigOpts = &sigVerifyOpts{
					KeyPath:              keyPath,
					CertIdentity:         certIdentity,
					CertIssuer:           certIssuer,
					Offline:              offline,
					TrustedRootPath:      trustedRootPath,
					BundlePath:           bundlePath,
					CertificateChainPath: certChainPath,
				}
			}
			return runVerifyFull(cmd, configPath, lockfilePath, strict, registry, sigOpts, provenance, nil, nil, saveBundleDir, nil)
		},
	}

	cmd.Flags().StringVarP(&configPath, "config", "c", "", "Path to agentcontainer.json (auto-detected if omitted)")
	cmd.Flags().StringVarP(&lockfilePath, "lockfile", "l", "", "Path to agentcontainer-lock.json (auto-detected if omitted)")
	cmd.Flags().BoolVar(&strict, "strict", false, "Exit with error on any mismatch")
	cmd.Flags().BoolVar(&registry, "registry", true, "Check digests against live registries")
	cmd.Flags().BoolVar(&signatures, "signatures", false, "Verify Sigstore cosign signatures on OCI artifacts")
	cmd.Flags().BoolVar(&provenance, "provenance", false, "Verify SLSA provenance attestations on OCI artifacts")
	cmd.Flags().StringVar(&keyPath, "key", "", "Path to cosign public key for signature verification")
	cmd.Flags().StringVar(&certIdentity, "cert-identity", "", "Expected certificate identity for keyless verification")
	cmd.Flags().StringVar(&certIssuer, "cert-issuer", "", "Expected OIDC issuer for keyless verification")
	cmd.Flags().BoolVar(&offline, "offline", false, "Verify signatures without network access to Rekor/Fulcio")
	cmd.Flags().StringVar(&trustedRootPath, "trusted-root", "", "Path to Sigstore TUF trusted root JSON (offline mode)")
	cmd.Flags().StringVar(&bundlePath, "bundle", "", "Path to Sigstore bundle (.sigstore.json) for offline verification")
	cmd.Flags().StringVar(&certChainPath, "certificate-chain", "", "Path to PEM certificate chain for offline verification")
	cmd.Flags().StringVar(&saveBundleDir, "save-bundle", "", "Save Sigstore bundles to this directory during online verification")

	return cmd
}

// sigVerifyOpts holds the signature verification options when --signatures is set.
type sigVerifyOpts struct {
	KeyPath              string
	CertIdentity         string
	CertIssuer           string
	Offline              bool
	TrustedRootPath      string
	BundlePath           string
	CertificateChainPath string
}

// verifyResult categorizes issues found during verification.
type verifyResult struct {
	missing     []string // config refs not pinned in lockfile
	stale       []string // lockfile digests that differ from registry
	errors      []string // registry resolution failures
	sigValid    []string // artifacts with valid signatures
	sigInvalid  []string // artifacts with invalid/missing signatures
	provValid   []string // artifacts with valid provenance
	provInvalid []string // artifacts with invalid/missing provenance
	policyFail  []string // artifacts denied by mutable policy channel
}

func (vr *verifyResult) total() int {
	return len(vr.missing) + len(vr.stale) + len(vr.errors) + len(vr.sigInvalid) + len(vr.provInvalid) + len(vr.policyFail)
}

// bundleFetcher abstracts fetching Sigstore bundles for testability.
type bundleFetcher interface {
	FetchSigstoreBundle(ctx context.Context, imageRef string) ([]byte, string, error)
}

// runVerifyFull is the testable implementation that accepts signature and provenance verification options.
func runVerifyFull(cmd *cobra.Command, configPath, lockfilePath string, strict, registry bool, sigOpts *sigVerifyOpts, checkProvenance bool, verifier signing.Verifier, provVerifier signing.ProvenanceVerifier, saveBundleDir string, fetcher bundleFetcher) error {
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
			return fmt.Errorf("verify: %w", err)
		}
		_, resolved, err := config.Load(cwd)
		if err != nil {
			return fmt.Errorf("verify: %w", err)
		}
		configPath = resolved
		cfgDir = filepath.Dir(resolved)
	} else {
		absPath, err := filepath.Abs(configPath)
		if err != nil {
			return fmt.Errorf("verify: resolving config path: %w", err)
		}
		configPath = absPath
		cfgDir = filepath.Dir(absPath)
	}

	// 2. Parse the config.
	cfg, err := config.ParseFile(configPath)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	if err := cfg.Validate(); err != nil {
		return fmt.Errorf("verify: invalid config: %w", err)
	}

	// 3. Load the lockfile.
	if lockfilePath == "" {
		lockfilePath = filepath.Join(cfgDir, config.LockfileName)
	}

	lf, err := config.ParseLockfile(lockfilePath)
	if err != nil {
		return fmt.Errorf("verify: %w", err)
	}

	if err := lf.Validate(); err != nil {
		return fmt.Errorf("verify: invalid lockfile: %w", err)
	}

	// 4. Check coverage: every config reference should have a lockfile entry.
	var result verifyResult

	if cfg.Image != "" && lf.Resolved.Image == nil {
		result.missing = append(result.missing, "image: not pinned in lockfile")
	}

	for ref := range cfg.Features {
		if _, ok := lf.Resolved.Features[ref]; !ok {
			result.missing = append(result.missing, fmt.Sprintf("feature %s: not pinned in lockfile", ref))
		}
	}

	if cfg.Agent != nil && cfg.Agent.Tools != nil {
		for name := range cfg.Agent.Tools.MCP {
			if _, ok := lf.Resolved.MCP[name]; !ok {
				result.missing = append(result.missing, fmt.Sprintf("mcp %s: not pinned in lockfile", name))
			}
		}
		for name := range cfg.Agent.Tools.Skills {
			if _, ok := lf.Resolved.Skills[name]; !ok {
				result.missing = append(result.missing, fmt.Sprintf("skill %s: not pinned in lockfile", name))
			}
		}
	}

	policyRef := configuredPolicyRef(cfg)
	if policyRef != "" && lf.Resolved.Policy == nil {
		result.missing = append(result.missing, fmt.Sprintf("policy %s: not pinned in lockfile", policyRef))
	}

	// 5. Registry freshness check: compare lockfile digests against live registry.
	if registry {
		resolver := newOCIResolver()
		verifyRegistryDigests(ctx, cfg, lf, resolver, &result)
		verifyPolicyChannel(ctx, cfg, lf, resolver, policyRef, &result)
	}

	// 6. Signature verification (when --signatures is set).
	if sigOpts != nil {
		if verifier == nil {
			verifier = signing.NewCosignVerifier()
		}
		verifySignatures(ctx, cfg, lf, verifier, sigOpts, &result)
	}

	// 7. Provenance verification (when --provenance is set).
	if checkProvenance {
		if provVerifier == nil {
			provVerifier = signing.NewCosignProvenanceVerifier()
		}
		verifyProvenance(ctx, cfg, lf, provVerifier, &result)
	}

	// 8. Save bundles (when --save-bundle is set and signatures were verified).
	if saveBundleDir != "" && sigOpts != nil && len(result.sigValid) > 0 {
		savedCount, saveErr := saveBundles(ctx, cfg, lf, saveBundleDir, fetcher)
		if saveErr != nil {
			_, _ = fmt.Fprintf(out, "WARNING: saving bundles: %v\n", saveErr)
		} else if savedCount > 0 {
			_, _ = fmt.Fprintf(out, "Saved %d bundle(s) to %s\n", savedCount, saveBundleDir)
		}
	}

	// 9. Report results.
	if result.total() == 0 {
		msg := "Verification passed: all artifacts are pinned"
		if registry {
			msg += " and up to date"
		}
		if sigOpts != nil && len(result.sigValid) > 0 {
			msg += fmt.Sprintf(", %d signature(s) verified", len(result.sigValid))
			if sigOpts.Offline {
				msg += " (offline)"
			}
		}
		if checkProvenance && len(result.provValid) > 0 {
			msg += fmt.Sprintf(", %d provenance attestation(s) verified", len(result.provValid))
		}
		msg += "."
		_, _ = fmt.Fprintln(out, msg)
		return nil
	}

	for _, w := range result.missing {
		_, _ = fmt.Fprintf(out, "MISSING: %s\n", w)
	}
	for _, w := range result.stale {
		_, _ = fmt.Fprintf(out, "STALE: %s\n", w)
	}
	for _, w := range result.sigValid {
		_, _ = fmt.Fprintf(out, "SIG OK: %s\n", w)
	}
	for _, w := range result.sigInvalid {
		_, _ = fmt.Fprintf(out, "SIG FAIL: %s\n", w)
	}
	for _, w := range result.provValid {
		_, _ = fmt.Fprintf(out, "PROV OK: %s\n", w)
	}
	for _, w := range result.provInvalid {
		_, _ = fmt.Fprintf(out, "PROV FAIL: %s\n", w)
	}
	for _, w := range result.policyFail {
		_, _ = fmt.Fprintf(out, "POLICY FAIL: %s\n", w)
	}
	for _, w := range result.errors {
		_, _ = fmt.Fprintf(out, "ERROR: %s\n", w)
	}

	if strict {
		return fmt.Errorf("verify: %d issue(s) found (%d missing, %d stale, %d sig-fail, %d prov-fail, %d policy-fail, %d errors)",
			result.total(), len(result.missing), len(result.stale), len(result.sigInvalid), len(result.provInvalid), len(result.policyFail), len(result.errors))
	}

	_, _ = fmt.Fprintf(out, "\nVerification completed with %d issue(s).\n", result.total())
	return nil
}

func verifyPolicyChannel(ctx context.Context, cfg *config.AgentContainer, lf *config.Lockfile, fetcher policyBundleFetcher, policyRef string, result *verifyResult) {
	if policyRef == "" || lf.Resolved.Policy == nil {
		return
	}

	now := time.Now().UTC()
	currentPolicy, bundle, err := resolvePolicyChannel(ctx, fetcher, policyRef, now)
	if err != nil {
		result.errors = append(result.errors, fmt.Sprintf("policy %s: %v", policyRef, err))
		return
	}
	if currentPolicy.Digest != lf.Resolved.Policy.Digest {
		result.stale = append(result.stale,
			fmt.Sprintf("policy %s: lockfile has %s, registry has %s",
				policyRef, lf.Resolved.Policy.Digest, currentPolicy.Digest))
	}
	if err := checkPolicyRollback(lf.Resolved.Policy, bundle); err != nil {
		result.errors = append(result.errors, fmt.Sprintf("policy %s: %v", policyRef, err))
		return
	}
	for _, issue := range evaluatePolicyChannelArtifacts(cfg, lf, bundle, now) {
		result.policyFail = append(result.policyFail, fmt.Sprintf("%s: %v", issue.label, issue.err))
	}
}

// verifyProvenance checks SLSA provenance attestations for all OCI artifacts
// that have a pinned digest in the lockfile. Uses config provenance requirements
// (slsaLevel and trustedBuilders) to validate.
func verifyProvenance(ctx context.Context, cfg *config.AgentContainer, lf *config.Lockfile, verifier signing.ProvenanceVerifier, result *verifyResult) {
	// Build verification options from config.
	var minLevel signing.SLSALevel
	var trustedBuilders []string
	var certIssuer string

	if cfg.Agent != nil && cfg.Agent.Provenance != nil && cfg.Agent.Provenance.Require != nil {
		req := cfg.Agent.Provenance.Require
		minLevel = signing.SLSALevel(req.SLSALevel)
		trustedBuilders = req.TrustedBuilders
	}

	opts := signing.ProvenanceVerifyOptions{
		MinSLSALevel: minLevel,
		CertIssuer:   certIssuer,
	}

	// Verify image provenance.
	if cfg.Image != "" && lf.Resolved.Image != nil {
		ref := cfg.Image + "@" + lf.Resolved.Image.Digest
		verifySingleProvenance(ctx, verifier, "image", cfg.Image, ref, opts, trustedBuilders, result)
	}

	// Verify feature provenance.
	for ref := range cfg.Features {
		resolved, ok := lf.Resolved.Features[ref]
		if !ok {
			continue
		}
		digestRef := ref + "@" + resolved.Digest
		verifySingleProvenance(ctx, verifier, "feature", ref, digestRef, opts, trustedBuilders, result)
	}

	if cfg.Agent == nil || cfg.Agent.Tools == nil {
		return
	}

	// Verify MCP server provenance.
	for name, mcp := range cfg.Agent.Tools.MCP {
		resolved, ok := lf.Resolved.MCP[name]
		if !ok {
			continue
		}
		ref := mcp.Image + "@" + resolved.Digest
		verifySingleProvenance(ctx, verifier, "mcp "+name, mcp.Image, ref, opts, trustedBuilders, result)
	}

	// Verify skill provenance.
	for name, skill := range cfg.Agent.Tools.Skills {
		resolved, ok := lf.Resolved.Skills[name]
		if !ok {
			continue
		}
		ref := skill.Artifact + "@" + resolved.Digest
		verifySingleProvenance(ctx, verifier, "skill "+name, skill.Artifact, ref, opts, trustedBuilders, result)
	}
}

// verifySingleProvenance verifies one artifact's SLSA provenance and records the result.
func verifySingleProvenance(ctx context.Context, verifier signing.ProvenanceVerifier, label, displayRef, digestRef string, opts signing.ProvenanceVerifyOptions, trustedBuilders []string, result *verifyResult) {
	pvr, err := verifier.VerifyProvenance(ctx, digestRef, opts)
	if err != nil {
		result.provInvalid = append(result.provInvalid,
			fmt.Sprintf("%s %s: %v", label, displayRef, err))
		return
	}
	if !pvr.Verified {
		result.provInvalid = append(result.provInvalid,
			fmt.Sprintf("%s %s: provenance not verified", label, displayRef))
		return
	}

	// Check builder identity against trusted builders.
	if pvr.Provenance != nil && len(trustedBuilders) > 0 {
		if err := signing.ValidateBuilderIdentity(pvr.Provenance, trustedBuilders); err != nil {
			result.provInvalid = append(result.provInvalid,
				fmt.Sprintf("%s %s: %v", label, displayRef, err))
			return
		}
	}

	msg := fmt.Sprintf("%s %s (%s, builder: %s)",
		label, displayRef, signing.SLSALevelString(pvr.SLSALevel), pvr.BuilderID)
	result.provValid = append(result.provValid, msg)
}

// verifyRegistryDigests resolves each pinned lockfile entry against the live
// registry and reports any digest mismatches as stale.
func verifyRegistryDigests(ctx context.Context, cfg *config.AgentContainer, lf *config.Lockfile, resolver interface {
	Resolve(context.Context, string) (string, error)
}, result *verifyResult) {
	// Check image.
	if cfg.Image != "" && lf.Resolved.Image != nil {
		liveDigest, err := resolver.Resolve(ctx, cfg.Image)
		if err != nil {
			result.errors = append(result.errors, fmt.Sprintf("image %s: %v", cfg.Image, err))
		} else if liveDigest != lf.Resolved.Image.Digest {
			result.stale = append(result.stale,
				fmt.Sprintf("image %s: lockfile has %s, registry has %s",
					cfg.Image, lf.Resolved.Image.Digest, liveDigest))
		}
	}

	// Check features.
	for ref := range cfg.Features {
		resolved, ok := lf.Resolved.Features[ref]
		if !ok {
			continue // already reported as missing
		}
		liveDigest, err := resolver.Resolve(ctx, ref)
		if err != nil {
			result.errors = append(result.errors, fmt.Sprintf("feature %s: %v", ref, err))
			continue
		}
		if liveDigest != resolved.Digest {
			result.stale = append(result.stale,
				fmt.Sprintf("feature %s: lockfile has %s, registry has %s",
					ref, resolved.Digest, liveDigest))
		}
	}

	if cfg.Agent == nil || cfg.Agent.Tools == nil {
		return
	}

	// Check MCP servers.
	for name, mcp := range cfg.Agent.Tools.MCP {
		resolved, ok := lf.Resolved.MCP[name]
		if !ok {
			continue
		}
		liveDigest, err := resolver.Resolve(ctx, mcp.Image)
		if err != nil {
			result.errors = append(result.errors, fmt.Sprintf("mcp %s (%s): %v", name, mcp.Image, err))
			continue
		}
		if liveDigest != resolved.Digest {
			result.stale = append(result.stale,
				fmt.Sprintf("mcp %s: lockfile has %s, registry has %s",
					name, resolved.Digest, liveDigest))
		}
	}

	// Check skills.
	for name, skill := range cfg.Agent.Tools.Skills {
		resolved, ok := lf.Resolved.Skills[name]
		if !ok {
			continue
		}
		liveDigest, err := resolver.Resolve(ctx, skill.Artifact)
		if err != nil {
			result.errors = append(result.errors, fmt.Sprintf("skill %s (%s): %v", name, skill.Artifact, err))
			continue
		}
		if liveDigest != resolved.Digest {
			result.stale = append(result.stale,
				fmt.Sprintf("skill %s: lockfile has %s, registry has %s",
					name, resolved.Digest, liveDigest))
		}
	}
}

// verifySignatures checks Sigstore cosign signatures for all OCI artifacts
// that have a pinned digest in the lockfile.
func verifySignatures(ctx context.Context, cfg *config.AgentContainer, lf *config.Lockfile, verifier signing.Verifier, opts *sigVerifyOpts, result *verifyResult) {
	vOpts := signing.VerifyOptions{
		KeyPath:              opts.KeyPath,
		CertIdentity:         opts.CertIdentity,
		CertIssuer:           opts.CertIssuer,
		Offline:              opts.Offline,
		TrustedRootPath:      opts.TrustedRootPath,
		BundlePath:           opts.BundlePath,
		CertificateChainPath: opts.CertificateChainPath,
	}

	// Verify image signature.
	if cfg.Image != "" && lf.Resolved.Image != nil {
		ref := cfg.Image + "@" + lf.Resolved.Image.Digest
		verifySingleSignature(ctx, verifier, "image", cfg.Image, ref, vOpts, result)
	}

	// Verify feature signatures.
	for ref := range cfg.Features {
		resolved, ok := lf.Resolved.Features[ref]
		if !ok {
			continue
		}
		digestRef := ref + "@" + resolved.Digest
		verifySingleSignature(ctx, verifier, "feature", ref, digestRef, vOpts, result)
	}

	if cfg.Agent == nil || cfg.Agent.Tools == nil {
		return
	}

	// Verify MCP server signatures.
	for name, mcp := range cfg.Agent.Tools.MCP {
		resolved, ok := lf.Resolved.MCP[name]
		if !ok {
			continue
		}
		ref := mcp.Image + "@" + resolved.Digest
		verifySingleSignature(ctx, verifier, "mcp "+name, mcp.Image, ref, vOpts, result)
	}

	// Verify skill signatures.
	for name, skill := range cfg.Agent.Tools.Skills {
		resolved, ok := lf.Resolved.Skills[name]
		if !ok {
			continue
		}
		ref := skill.Artifact + "@" + resolved.Digest
		verifySingleSignature(ctx, verifier, "skill "+name, skill.Artifact, ref, vOpts, result)
	}
}

// verifySingleSignature verifies one artifact's signature and records the result.
func verifySingleSignature(ctx context.Context, verifier signing.Verifier, label, displayRef, digestRef string, opts signing.VerifyOptions, result *verifyResult) {
	vr, err := verifier.Verify(ctx, digestRef, opts)
	if err != nil {
		result.sigInvalid = append(result.sigInvalid,
			fmt.Sprintf("%s %s: %v", label, displayRef, err))
		return
	}
	if !vr.Verified {
		result.sigInvalid = append(result.sigInvalid,
			fmt.Sprintf("%s %s: signature not verified", label, displayRef))
		return
	}

	msg := fmt.Sprintf("%s %s", label, displayRef)
	if vr.SignerIdentity != "" {
		msg += fmt.Sprintf(" (signer: %s)", vr.SignerIdentity)
	}
	if vr.BundleVerified {
		msg += " [bundle]"
	}
	if vr.Offline {
		msg += " [offline]"
	}
	result.sigValid = append(result.sigValid, msg)
}

// saveBundles fetches and saves Sigstore bundles for all verified artifacts.
// Returns the count of saved bundles and any error encountered.
func saveBundles(ctx context.Context, cfg *config.AgentContainer, lf *config.Lockfile, destDir string, fetcher bundleFetcher) (int, error) {
	if fetcher == nil {
		fetcher = newOCIResolver()
	}

	if err := os.MkdirAll(destDir, 0o755); err != nil {
		return 0, fmt.Errorf("creating bundle directory: %w", err)
	}

	var saved int
	var errs []string

	// Collect all artifact references to save bundles for.
	type artifactRef struct {
		label    string
		imageRef string
		digest   string
	}

	var refs []artifactRef

	if cfg.Image != "" && lf.Resolved.Image != nil {
		refs = append(refs, artifactRef{
			label:    "image",
			imageRef: cfg.Image + "@" + lf.Resolved.Image.Digest,
			digest:   lf.Resolved.Image.Digest,
		})
	}

	for featureRef := range cfg.Features {
		resolved, ok := lf.Resolved.Features[featureRef]
		if !ok {
			continue
		}
		refs = append(refs, artifactRef{
			label:    "feature " + featureRef,
			imageRef: featureRef + "@" + resolved.Digest,
			digest:   resolved.Digest,
		})
	}

	if cfg.Agent != nil && cfg.Agent.Tools != nil {
		for name, mcp := range cfg.Agent.Tools.MCP {
			resolved, ok := lf.Resolved.MCP[name]
			if !ok {
				continue
			}
			refs = append(refs, artifactRef{
				label:    "mcp " + name,
				imageRef: mcp.Image + "@" + resolved.Digest,
				digest:   resolved.Digest,
			})
		}

		for name, skill := range cfg.Agent.Tools.Skills {
			resolved, ok := lf.Resolved.Skills[name]
			if !ok {
				continue
			}
			refs = append(refs, artifactRef{
				label:    "skill " + name,
				imageRef: skill.Artifact + "@" + resolved.Digest,
				digest:   resolved.Digest,
			})
		}
	}

	for _, ar := range refs {
		data, _, err := fetcher.FetchSigstoreBundle(ctx, ar.imageRef)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: %v", ar.label, err))
			continue
		}

		// Compute the bundle path.
		ref, err := oci.ParseReference(ar.imageRef)
		if err != nil {
			errs = append(errs, fmt.Sprintf("%s: parsing reference: %v", ar.label, err))
			continue
		}

		bundlePath := oci.BundlePath(destDir, ref.Registry, ref.Name, ar.digest)
		bundleDir := filepath.Dir(bundlePath)
		if err := os.MkdirAll(bundleDir, 0o755); err != nil {
			errs = append(errs, fmt.Sprintf("%s: creating directory: %v", ar.label, err))
			continue
		}

		if err := os.WriteFile(bundlePath, data, 0o644); err != nil {
			errs = append(errs, fmt.Sprintf("%s: writing bundle: %v", ar.label, err))
			continue
		}

		saved++
	}

	if len(errs) > 0 {
		return saved, fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	return saved, nil
}
