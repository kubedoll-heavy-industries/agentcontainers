package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// LockfileName is the conventional filename for the lockfile.
const LockfileName = "agentcontainer-lock.json"

// Lockfile represents the agentcontainer-lock.json file that pins every
// resolvable OCI reference to a specific digest. The lockfile is committed
// to source control to ensure reproducible, verifiable agent environments.
type Lockfile struct {
	Version     int               `json:"version"`
	GeneratedAt time.Time         `json:"generatedAt"`
	GeneratedBy string            `json:"generatedBy"`
	Resolved    ResolvedArtifacts `json:"resolved"`
}

// ResolvedArtifacts contains all pinned artifact references.
type ResolvedArtifacts struct {
	Image    *ResolvedImage             `json:"image,omitempty"`
	Features map[string]ResolvedFeature `json:"features,omitempty"`
	MCP      map[string]ResolvedMCP     `json:"mcp,omitempty"`
	Skills   map[string]ResolvedSkill   `json:"skills,omitempty"`
	Policy   *ResolvedPolicy            `json:"policy,omitempty"`
}

// ResolvedImage pins the base container image by digest.
type ResolvedImage struct {
	Digest     string    `json:"digest"`
	ResolvedAt time.Time `json:"resolvedAt"`
}

// ResolvedFeature pins a devcontainer feature by digest.
type ResolvedFeature struct {
	Digest     string    `json:"digest"`
	ResolvedAt time.Time `json:"resolvedAt"`
}

// ResolvedMCP pins an MCP server image by digest with optional
// signature and SBOM metadata.
type ResolvedMCP struct {
	Digest     string        `json:"digest"`
	ResolvedAt time.Time     `json:"resolvedAt"`
	Signature  *SignatureRef `json:"signature,omitempty"`
	SBOM       *SBOMRef      `json:"sbom,omitempty"`
}

// ResolvedSkill pins a skill artifact by digest with optional SkillBOM metadata.
type ResolvedSkill struct {
	Digest     string       `json:"digest"`
	ResolvedAt time.Time    `json:"resolvedAt"`
	SkillBOM   *SkillBOMRef `json:"skillbom,omitempty"`
}

// ResolvedPolicy pins the mutable org policy channel to a signed bundle digest.
type ResolvedPolicy struct {
	Ref        string        `json:"ref"`
	Digest     string        `json:"digest"`
	Epoch      int           `json:"epoch"`
	ExpiresAt  time.Time     `json:"expiresAt"`
	ResolvedAt time.Time     `json:"resolvedAt"`
	Signature  *SignatureRef `json:"signature,omitempty"`
}

// SignatureRef records Sigstore verification data for an artifact.
type SignatureRef struct {
	KeylessRef string `json:"keylessRef,omitempty"`
	KeyRef     string `json:"keyRef,omitempty"`
	Issuer     string `json:"issuer,omitempty"`
	Subject    string `json:"subject,omitempty"`
}

// SBOMRef records the SBOM artifact reference and vulnerability summary.
type SBOMRef struct {
	Digest          string       `json:"digest"`
	Format          string       `json:"format"`
	Vulnerabilities *VulnSummary `json:"vulnerabilities,omitempty"`
}

// VulnSummary is an informational snapshot of vulnerability counts at lock time.
type VulnSummary struct {
	Critical  int       `json:"critical"`
	High      int       `json:"high"`
	Medium    int       `json:"medium"`
	ScannedAt time.Time `json:"scannedAt"`
}

// SkillBOMRef records the SkillBOM digest, semantic embedding hash,
// and declared capabilities for a skill.
type SkillBOMRef struct {
	Digest        string   `json:"digest"`
	EmbeddingHash string   `json:"embeddingHash"`
	Capabilities  []string `json:"capabilities,omitempty"`
}

// Validate checks the Lockfile for structural correctness.
// It collects all validation errors and returns them joined via errors.Join.
func (l *Lockfile) Validate() error {
	var errs []error

	if l.Version != 2 {
		if l.Version == 1 {
			errs = append(errs, fmt.Errorf("lockfile is version 1; re-run `agentcontainer lock` to generate a version 2 lockfile"))
		} else {
			errs = append(errs, fmt.Errorf("version must be 2, got %d", l.Version))
		}
	}

	if l.GeneratedAt.IsZero() {
		errs = append(errs, errors.New("generatedAt must not be zero"))
	}

	if l.GeneratedBy == "" {
		errs = append(errs, errors.New("generatedBy must not be empty"))
	}

	if l.Resolved.Image != nil {
		if err := validateDigest("resolved.image.digest", l.Resolved.Image.Digest); err != nil {
			errs = append(errs, err)
		}
	}

	for ref, feat := range l.Resolved.Features {
		if err := validateDigest(fmt.Sprintf("resolved.features[%s].digest", ref), feat.Digest); err != nil {
			errs = append(errs, err)
		}
	}

	for name, mcp := range l.Resolved.MCP {
		prefix := fmt.Sprintf("resolved.mcp[%s]", name)
		if err := validateDigest(prefix+".digest", mcp.Digest); err != nil {
			errs = append(errs, err)
		}
		if mcp.SBOM != nil {
			if err := validateDigest(prefix+".sbom.digest", mcp.SBOM.Digest); err != nil {
				errs = append(errs, err)
			}
			if mcp.SBOM.Format == "" {
				errs = append(errs, fmt.Errorf("%s.sbom.format must not be empty", prefix))
			}
		}
	}

	for name, skill := range l.Resolved.Skills {
		prefix := fmt.Sprintf("resolved.skills[%s]", name)
		if err := validateDigest(prefix+".digest", skill.Digest); err != nil {
			errs = append(errs, err)
		}
		if skill.SkillBOM != nil {
			if err := validateDigest(prefix+".skillbom.digest", skill.SkillBOM.Digest); err != nil {
				errs = append(errs, err)
			}
			if skill.SkillBOM.EmbeddingHash == "" {
				errs = append(errs, fmt.Errorf("%s.skillbom.embeddingHash must not be empty", prefix))
			}
		}
	}

	if l.Resolved.Policy != nil {
		if err := validatePolicy(l.Resolved.Policy); err != nil {
			errs = append(errs, err)
		}
	}

	return errors.Join(errs...)
}

func validatePolicy(policy *ResolvedPolicy) error {
	var errs []error

	if policy.Ref == "" {
		errs = append(errs, errors.New("resolved.policy.ref must not be empty"))
	}
	if err := validateDigest("resolved.policy.digest", policy.Digest); err != nil {
		errs = append(errs, err)
	}
	if policy.Epoch <= 0 {
		errs = append(errs, fmt.Errorf("resolved.policy.epoch must be greater than 0, got %d", policy.Epoch))
	}
	if policy.ExpiresAt.IsZero() {
		errs = append(errs, errors.New("resolved.policy.expiresAt must not be zero"))
	}
	if policy.ResolvedAt.IsZero() {
		errs = append(errs, errors.New("resolved.policy.resolvedAt must not be zero"))
	}

	return errors.Join(errs...)
}

// validateDigest checks that a digest string looks like a valid content-addressable hash.
func validateDigest(field, digest string) error {
	if digest == "" {
		return fmt.Errorf("%s: must not be empty", field)
	}
	if !strings.Contains(digest, ":") {
		return fmt.Errorf("%s: must be in algorithm:hex format (e.g. sha256:abc123), got %q", field, digest)
	}
	return nil
}

// LoadLockfile reads and parses the lockfile from the given directory.
// It looks for LockfileName in the directory root.
func LoadLockfile(dir string) (*Lockfile, error) {
	path := filepath.Join(dir, LockfileName)
	return ParseLockfile(path)
}

// ParseLockfile reads and parses a lockfile at the given path.
func ParseLockfile(path string) (*Lockfile, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading lockfile: %w", err)
	}

	var lf Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("unmarshaling lockfile: %w", err)
	}

	return &lf, nil
}

// SaveLockfile writes the lockfile as formatted JSON to the given directory.
func SaveLockfile(dir string, lf *Lockfile) error {
	path := filepath.Join(dir, LockfileName)
	return WriteLockfile(path, lf)
}

// WriteLockfile writes the lockfile as formatted JSON to the given path.
func WriteLockfile(path string, lf *Lockfile) error {
	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return fmt.Errorf("marshaling lockfile: %w", err)
	}

	// Append trailing newline for POSIX compatibility.
	data = append(data, '\n')

	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing lockfile: %w", err)
	}

	return nil
}
