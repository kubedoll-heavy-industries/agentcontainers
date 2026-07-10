package orgpolicy

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

const (
	testDigest      = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testOtherDigest = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func TestParsePolicyBundleValidEvaluatesAllowedDigest(t *testing.T) {
	bundle := PolicyBundle{
		MediaType:       PolicyBundleMediaType,
		Epoch:           1,
		ExpiresAt:       time.Now().Add(time.Hour),
		RevokedDigests:  []string{testOtherDigest},
		MinimumVersions: map[string]string{"agentcontainers": "1.2.3"},
		VulnerabilityPolicy: &VulnerabilityPolicy{
			DenyCritical:    true,
			DenyHighWithFix: true,
			MaxAgeSinceScan: "24h",
		},
	}
	data, err := json.Marshal(bundle)
	if err != nil {
		t.Fatal(err)
	}

	got, err := ParsePolicyBundle(data)
	if err != nil {
		t.Fatalf("ParsePolicyBundle() error = %v", err)
	}
	if got.MediaType != PolicyBundleMediaType {
		t.Errorf("MediaType = %q, want %q", got.MediaType, PolicyBundleMediaType)
	}
	if got.Epoch != 1 {
		t.Errorf("Epoch = %d, want 1", got.Epoch)
	}

	errs := EvaluatePolicyBundle(got, testDigest, time.Now())
	if len(errs) != 0 {
		t.Fatalf("EvaluatePolicyBundle() errors = %v, want none", errs)
	}
}

func TestEvaluatePolicyBundleRevokedDigestDenied(t *testing.T) {
	bundle := validPolicyBundle(time.Now())
	bundle.RevokedDigests = []string{testDigest}

	errs := EvaluatePolicyBundle(bundle, testDigest, time.Now())
	if !hasError(errs, ErrDigestRevoked) {
		t.Fatalf("EvaluatePolicyBundle() errors = %v, want ErrDigestRevoked", errs)
	}
}

func TestEvaluatePolicyBundleDeprecatedDigestDenyAfter(t *testing.T) {
	now := time.Now()
	denyAfter := now.Add(time.Hour)
	bundle := validPolicyBundle(now)
	bundle.DeprecatedDigests = map[string]Deprecation{
		testDigest: {
			Reason:    "replacement available",
			DenyAfter: denyAfter,
		},
	}

	beforeErrs := EvaluatePolicyBundle(bundle, testDigest, denyAfter.Add(-time.Second))
	if len(beforeErrs) != 0 {
		t.Fatalf("EvaluatePolicyBundle() before denyAfter errors = %v, want none", beforeErrs)
	}

	afterErrs := EvaluatePolicyBundle(bundle, testDigest, denyAfter)
	if !hasError(afterErrs, ErrDigestDeprecated) {
		t.Fatalf("EvaluatePolicyBundle() after denyAfter errors = %v, want ErrDigestDeprecated", afterErrs)
	}
}

func TestEvaluatePolicyBundleExpiredBundleDenied(t *testing.T) {
	now := time.Now()
	bundle := validPolicyBundle(now)
	bundle.ExpiresAt = now.Add(-time.Second)

	errs := EvaluatePolicyBundle(bundle, testDigest, now)
	if !hasError(errs, ErrPolicyBundleExpired) {
		t.Fatalf("EvaluatePolicyBundle() errors = %v, want ErrPolicyBundleExpired", errs)
	}
}

func TestParsePolicyBundleRejectsInvalidPolicy(t *testing.T) {
	future := time.Now().Add(time.Hour).Format(time.RFC3339)

	tests := []struct {
		name    string
		json    string
		wantErr error
	}{
		{
			name:    "invalid epoch",
			json:    `{"epoch":0,"expiresAt":"` + future + `"}`,
			wantErr: ErrPolicyBundleInvalidEpoch,
		},
		{
			name:    "invalid mediaType",
			json:    `{"mediaType":"application/vnd.example.wrong+json","epoch":1,"expiresAt":"` + future + `"}`,
			wantErr: ErrPolicyBundleInvalidType,
		},
		{
			name:    "invalid artifactType",
			json:    `{"artifactType":"application/vnd.example.wrong+json","epoch":1,"expiresAt":"` + future + `"}`,
			wantErr: ErrPolicyBundleInvalidType,
		},
		{
			name:    "missing expiresAt",
			json:    `{"epoch":1}`,
			wantErr: ErrPolicyBundleMissingExpiration,
		},
		{
			name:    "expired expiresAt",
			json:    `{"epoch":1,"expiresAt":"2000-01-01T00:00:00Z"}`,
			wantErr: ErrPolicyBundleExpired,
		},
		{
			name:    "invalid revoked digest",
			json:    `{"epoch":1,"expiresAt":"` + future + `","revokedDigests":["sha256:not-hex"]}`,
			wantErr: ErrPolicyBundleInvalidDigest,
		},
		{
			name:    "invalid deprecated digest",
			json:    `{"epoch":1,"expiresAt":"` + future + `","deprecatedDigests":{"not-a-digest":{"denyAfter":"` + future + `"}}}`,
			wantErr: ErrPolicyBundleInvalidDigest,
		},
		{
			name:    "missing deprecation denyAfter",
			json:    `{"epoch":1,"expiresAt":"` + future + `","deprecatedDigests":{"` + testDigest + `":{"reason":"old"}}}`,
			wantErr: ErrDeprecationMissingDenyAfter,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParsePolicyBundle([]byte(tt.json))
			if !errors.Is(err, tt.wantErr) {
				t.Fatalf("ParsePolicyBundle() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func validPolicyBundle(now time.Time) *PolicyBundle {
	return &PolicyBundle{
		MediaType: PolicyBundleMediaType,
		Epoch:     1,
		ExpiresAt: now.Add(time.Hour),
	}
}

func hasError(errs []error, target error) bool {
	for _, err := range errs {
		if errors.Is(err, target) {
			return true
		}
	}
	return false
}
