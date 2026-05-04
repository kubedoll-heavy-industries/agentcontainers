package orgpolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	digestpkg "github.com/opencontainers/go-digest"
)

const (
	// PolicyBundleMediaType is the OCI media type for org-controlled mutable policy bundles.
	PolicyBundleMediaType = "application/vnd.agentcontainers.policy.v1+json"
)

var (
	ErrPolicyBundleNil               = errors.New("policy bundle is nil")
	ErrPolicyBundleInvalidType       = errors.New("policy bundle media/artifact type is invalid")
	ErrPolicyBundleInvalidEpoch      = errors.New("policy bundle epoch is invalid")
	ErrPolicyBundleMissingExpiration = errors.New("policy bundle expiresAt is missing")
	ErrPolicyBundleExpired           = errors.New("policy bundle is expired")
	ErrPolicyBundleInvalidDigest     = errors.New("policy bundle digest is invalid")
	ErrDeprecationMissingDenyAfter   = errors.New("policy bundle deprecation denyAfter is missing")
	ErrDigestRevoked                 = errors.New("digest is revoked by policy bundle")
	ErrDigestDeprecated              = errors.New("digest is deprecated by policy bundle")
)

// PolicyBundle is the signed, org-controlled policy channel for mutable
// decisions about otherwise pinned OCI artifacts.
type PolicyBundle struct {
	MediaType           string                 `json:"mediaType,omitempty"`
	ArtifactType        string                 `json:"artifactType,omitempty"`
	Epoch               int                    `json:"epoch"`
	ExpiresAt           time.Time              `json:"expiresAt"`
	RevokedDigests      []string               `json:"revokedDigests,omitempty"`
	DeprecatedDigests   map[string]Deprecation `json:"deprecatedDigests,omitempty"`
	MinimumVersions     map[string]string      `json:"minimumVersions,omitempty"`
	VulnerabilityPolicy *VulnerabilityPolicy   `json:"vulnerabilityPolicy,omitempty"`
}

// Deprecation describes a digest that remains allowed until DenyAfter.
type Deprecation struct {
	Reason    string    `json:"reason,omitempty"`
	DenyAfter time.Time `json:"denyAfter"`
}

// VulnerabilityPolicy is reserved for scanner-backed decisions. Evaluation of
// vulnerability data is intentionally out of scope for this model.
type VulnerabilityPolicy struct {
	DenyCritical    bool   `json:"denyCritical,omitempty"`
	DenyHighWithFix bool   `json:"denyHighWithFix,omitempty"`
	MaxAgeSinceScan string `json:"maxAgeSinceScan,omitempty"`
}

// ParsePolicyBundle decodes and validates a signed policy bundle.
func ParsePolicyBundle(data []byte) (*PolicyBundle, error) {
	var bundle PolicyBundle
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&bundle); err != nil {
		return nil, fmt.Errorf("parsing policy bundle: %w", err)
	}
	var extra json.RawMessage
	if err := dec.Decode(&extra); err != io.EOF {
		if err != nil {
			return nil, fmt.Errorf("parsing policy bundle: %w", err)
		}
		return nil, fmt.Errorf("parsing policy bundle: multiple JSON values")
	}

	if err := bundle.Validate(time.Now()); err != nil {
		return nil, fmt.Errorf("validating policy bundle: %w", err)
	}
	return &bundle, nil
}

// Validate checks that a policy bundle is internally consistent and currently usable.
func (b *PolicyBundle) Validate(now time.Time) error {
	if b == nil {
		return ErrPolicyBundleNil
	}
	if b.MediaType != "" && b.MediaType != PolicyBundleMediaType {
		return fmt.Errorf("%w: mediaType %q, want %q", ErrPolicyBundleInvalidType, b.MediaType, PolicyBundleMediaType)
	}
	if b.ArtifactType != "" && b.ArtifactType != PolicyBundleMediaType {
		return fmt.Errorf("%w: artifactType %q, want %q", ErrPolicyBundleInvalidType, b.ArtifactType, PolicyBundleMediaType)
	}
	if b.Epoch <= 0 {
		return fmt.Errorf("%w: epoch must be > 0, got %d", ErrPolicyBundleInvalidEpoch, b.Epoch)
	}
	if b.ExpiresAt.IsZero() {
		return ErrPolicyBundleMissingExpiration
	}
	if !b.ExpiresAt.After(now) {
		return fmt.Errorf("%w: expiresAt %s is not after %s", ErrPolicyBundleExpired, b.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339))
	}

	for _, digest := range b.RevokedDigests {
		if !isPolicyBundleDigest(digest) {
			return fmt.Errorf("%w: revokedDigests contains %q", ErrPolicyBundleInvalidDigest, digest)
		}
	}
	for digest, deprecation := range b.DeprecatedDigests {
		if !isPolicyBundleDigest(digest) {
			return fmt.Errorf("%w: deprecatedDigests contains %q", ErrPolicyBundleInvalidDigest, digest)
		}
		if deprecation.DenyAfter.IsZero() {
			return fmt.Errorf("%w: %s", ErrDeprecationMissingDenyAfter, digest)
		}
	}

	return nil
}

// EvaluatePolicyBundle checks a digest against mutable policy bundle decisions.
// It returns all matching denials; an empty slice means the digest is allowed by
// this bundle.
func EvaluatePolicyBundle(bundle *PolicyBundle, digest string, now time.Time) []error {
	if bundle == nil {
		return []error{ErrPolicyBundleNil}
	}

	var errs []error
	if bundle.ExpiresAt.IsZero() {
		errs = append(errs, ErrPolicyBundleMissingExpiration)
	} else if !bundle.ExpiresAt.After(now) {
		errs = append(errs, fmt.Errorf("%w: expiresAt %s is not after %s", ErrPolicyBundleExpired, bundle.ExpiresAt.Format(time.RFC3339), now.Format(time.RFC3339)))
	}
	if !isPolicyBundleDigest(digest) {
		errs = append(errs, fmt.Errorf("%w: %q", ErrPolicyBundleInvalidDigest, digest))
		return errs
	}

	for _, revoked := range bundle.RevokedDigests {
		if revoked == digest {
			errs = append(errs, fmt.Errorf("%w: %s", ErrDigestRevoked, digest))
			break
		}
	}

	if deprecation, ok := bundle.DeprecatedDigests[digest]; ok && !deprecation.DenyAfter.IsZero() && !now.Before(deprecation.DenyAfter) {
		if deprecation.Reason == "" {
			errs = append(errs, fmt.Errorf("%w: %s denied after %s", ErrDigestDeprecated, digest, deprecation.DenyAfter.Format(time.RFC3339)))
		} else {
			errs = append(errs, fmt.Errorf("%w: %s denied after %s: %s", ErrDigestDeprecated, digest, deprecation.DenyAfter.Format(time.RFC3339), deprecation.Reason))
		}
	}

	return errs
}

func isPolicyBundleDigest(digest string) bool {
	_, err := digestpkg.Parse(digest)
	return err == nil
}
