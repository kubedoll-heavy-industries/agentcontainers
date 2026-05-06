package oci

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// policyDigestOf returns the sha256:<hex> digest of a policy JSON string.
func policyDigestOf(s string) string {
	return digestOf([]byte(s))
}

func digestOf(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

func manifestBytes(t *testing.T, manifest ociManifest) []byte {
	t.Helper()

	data, err := json.Marshal(manifest)
	if err != nil {
		t.Fatalf("marshal manifest: %v", err)
	}
	return data
}

func TestFetchPolicy_Success(t *testing.T) {
	policyJSON := `{"requireSignatures": true, "minSLSALevel": 2}`
	policyDigest := policyDigestOf(policyJSON)

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    policyDigest,
				Size:      int64(len(policyJSON)),
			},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"):
			_, _ = w.Write([]byte(policyJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy:latest"

	data, err := resolver.FetchPolicy(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchPolicy() error = %v", err)
	}

	if string(data) != policyJSON {
		t.Errorf("FetchPolicy() = %q, want %q", string(data), policyJSON)
	}
}

func TestFetchPolicy_MultiplePolicyLayers(t *testing.T) {
	// When two policy layers are present, the FIRST one should be returned (first-wins,
	// F-3 fix). The base/org policy cannot be overridden by appending a derived layer.
	basePolicy := `{"requireSignatures": true, "minSLSALevel": 2}`
	derivedPolicy := `{"requireSignatures": false}` // attacker's permissive override attempt
	basePolicyDigest := policyDigestOf(basePolicy)
	derivedPolicyDigest := policyDigestOf(derivedPolicy)

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{MediaType: PolicyArtifactMediaType, Digest: basePolicyDigest, Size: int64(len(basePolicy))},
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("f", 64), Size: 100},
			{MediaType: PolicyArtifactMediaType, Digest: derivedPolicyDigest, Size: int64(len(derivedPolicy))},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"+basePolicyDigest):
			_, _ = w.Write([]byte(basePolicy))
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"+derivedPolicyDigest):
			_, _ = w.Write([]byte(derivedPolicy))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/agent-base:v2"

	data, err := resolver.FetchPolicy(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchPolicy() error = %v", err)
	}
	// First-wins: the BASE (org) policy should be returned, not the derived one.
	if string(data) != basePolicy {
		t.Errorf("FetchPolicy() = %q, want base policy %q (first-wins, F-3)", string(data), basePolicy)
	}
}

func TestFetchPolicy_ManifestNotFound(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy:missing"

	_, err := resolver.FetchPolicy(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicy() error = nil, want error for missing manifest")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain 'not found'", err.Error())
	}
}

func TestFetchPolicy_EmptyLayers(t *testing.T) {
	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/empty:latest"

	_, err := resolver.FetchPolicy(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicy() error = nil, want error for empty layers")
	}
	if !strings.Contains(err.Error(), "no layers") {
		t.Errorf("error = %q, want it to contain 'no layers'", err.Error())
	}
}

func TestFetchPolicy_BlobNotFound(t *testing.T) {
	policyDigest := "sha256:" + strings.Repeat("a", 64)
	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    policyDigest,
				Size:      100,
			},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy:latest"

	_, err := resolver.FetchPolicy(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicy() error = nil, want error for missing blob")
	}
	if !strings.Contains(err.Error(), "not found") {
		t.Errorf("error = %q, want it to contain 'not found'", err.Error())
	}
}

func TestFetchPolicy_EmptyReference(t *testing.T) {
	resolver := NewResolver()
	_, err := resolver.FetchPolicy(context.Background(), "")
	if err == nil {
		t.Fatal("FetchPolicy() error = nil, want error for empty reference")
	}
}

func TestFetchPolicy_NoMatchingLayer(t *testing.T) {
	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{MediaType: "application/vnd.other.type", Digest: "sha256:" + strings.Repeat("a", 64), Size: 10},
			{MediaType: "application/vnd.other.type2", Digest: "sha256:" + strings.Repeat("b", 64), Size: 20},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy:latest"

	_, err := resolver.FetchPolicy(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicy() error = nil, want error for no matching layer")
	}
	if !strings.Contains(err.Error(), "no policy layer found") {
		t.Errorf("error = %q, want it to contain 'no policy layer found'", err.Error())
	}
}

func TestFetchPolicy_WithBearerAuth(t *testing.T) {
	policyJSON := `{"requireSignatures": true}`
	policyDigest := policyDigestOf(policyJSON)
	wantToken := "policy-fetch-token"

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    policyDigest,
				Size:      int64(len(policyJSON)),
			},
		},
	}

	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(tokenResponse{Token: wantToken})
			return
		}

		auth := r.Header.Get("Authorization")
		if auth != "Bearer "+wantToken {
			w.Header().Set("Www-Authenticate",
				`Bearer realm="`+srvURL+`/token",service="test"`)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"):
			_, _ = w.Write([]byte(policyJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy:latest"

	data, err := resolver.FetchPolicy(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchPolicy() error = %v", err)
	}
	if string(data) != policyJSON {
		t.Errorf("FetchPolicy() = %q, want %q", string(data), policyJSON)
	}
}

func TestFetchPolicy_DigestMismatch(t *testing.T) {
	// The manifest claims the blob has a specific digest, but the server returns
	// different content. verifyDigest should catch this (F-2/F-11 fix).
	policyJSON := `{"requireSignatures": true}`
	realDigest := policyDigestOf(policyJSON)
	tamperedContent := `{}`

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    realDigest,
				Size:      int64(len(policyJSON)),
			},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"):
			// MITM: return tampered content instead of the real policy.
			_, _ = w.Write([]byte(tamperedContent))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy:latest"

	_, err := resolver.FetchPolicy(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicy() error = nil; want digest mismatch error (F-2/F-11)")
	}
	if !strings.Contains(err.Error(), "digest mismatch") {
		t.Errorf("error = %q, want it to contain 'digest mismatch'", err.Error())
	}
}

func TestFetchPolicyBundle_TagRefSuccess(t *testing.T) {
	bundleJSON := `{"version":1,"policies":[{"name":"default"}]}`
	bundleDigest := policyDigestOf(bundleJSON)

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyBundleArtifactMediaType,
				Digest:    bundleDigest,
				Size:      int64(len(bundleJSON)),
			},
		},
	}
	manifestJSON := manifestBytes(t, manifest)
	manifestDigest := digestOf(manifestJSON)

	var fetchedByDigest bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/latest"):
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"+manifestDigest):
			fetchedByDigest = true
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			_, _ = w.Write(manifestJSON)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"+bundleDigest):
			_, _ = w.Write([]byte(bundleJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy-bundle:latest"

	data, gotDigest, err := resolver.FetchPolicyBundle(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchPolicyBundle() error = %v", err)
	}
	if string(data) != bundleJSON {
		t.Errorf("FetchPolicyBundle() data = %q, want %q", string(data), bundleJSON)
	}
	if gotDigest != manifestDigest {
		t.Errorf("FetchPolicyBundle() digest = %q, want %q", gotDigest, manifestDigest)
	}
	if !fetchedByDigest {
		t.Error("FetchPolicyBundle() did not fetch manifest by resolved digest")
	}
}

func TestFetchPolicyBundle_DigestPinnedRefWrongManifestBodyFails(t *testing.T) {
	bundleJSON := `{"version":1,"policies":[{"name":"pinned"}]}`
	bundleDigest := policyDigestOf(bundleJSON)
	goodManifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyBundleArtifactMediaType,
				Digest:    bundleDigest,
				Size:      int64(len(bundleJSON)),
			},
		},
	}
	goodManifestJSON := manifestBytes(t, goodManifest)
	manifestDigest := digestOf(goodManifestJSON)

	wrongManifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyBundleArtifactMediaType,
				Digest:    "sha256:" + strings.Repeat("b", 64),
				Size:      int64(len(bundleJSON)),
			},
		},
	}
	wrongManifestJSON := manifestBytes(t, wrongManifest)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"+manifestDigest) {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write(wrongManifestJSON)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy-bundle@" + manifestDigest

	_, _, err := resolver.FetchPolicyBundle(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicyBundle() error = nil, want manifest digest mismatch")
	}
	if !strings.Contains(err.Error(), "manifest digest mismatch") {
		t.Errorf("error = %q, want it to contain 'manifest digest mismatch'", err.Error())
	}
}

func TestFetchPolicyBundle_TagResolvedWrongManifestBodyFails(t *testing.T) {
	bundleJSON := `{"version":1,"policies":[{"name":"resolved"}]}`
	bundleDigest := policyDigestOf(bundleJSON)
	goodManifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyBundleArtifactMediaType,
				Digest:    bundleDigest,
				Size:      int64(len(bundleJSON)),
			},
		},
	}
	goodManifestJSON := manifestBytes(t, goodManifest)
	manifestDigest := digestOf(goodManifestJSON)

	wrongManifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyBundleArtifactMediaType,
				Digest:    "sha256:" + strings.Repeat("c", 64),
				Size:      int64(len(bundleJSON)),
			},
		},
	}
	wrongManifestJSON := manifestBytes(t, wrongManifest)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead && strings.Contains(r.URL.Path, "/manifests/latest"):
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			w.WriteHeader(http.StatusOK)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"+manifestDigest):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			_, _ = w.Write(wrongManifestJSON)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy-bundle:latest"

	_, _, err := resolver.FetchPolicyBundle(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicyBundle() error = nil, want resolved manifest digest mismatch")
	}
	if !strings.Contains(err.Error(), "manifest digest mismatch") {
		t.Errorf("error = %q, want it to contain 'manifest digest mismatch'", err.Error())
	}
}

func TestFetchPolicyBundle_DigestPinnedRefSuccess(t *testing.T) {
	bundleJSON := `{"version":1,"policies":[{"name":"pinned"}]}`
	bundleDigest := policyDigestOf(bundleJSON)

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyBundleArtifactMediaType,
				Digest:    bundleDigest,
				Size:      int64(len(bundleJSON)),
			},
		},
	}
	manifestJSON := manifestBytes(t, manifest)
	manifestDigest := digestOf(manifestJSON)

	var sawHead bool
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodHead:
			sawHead = true
			w.WriteHeader(http.StatusNotFound)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"+manifestDigest):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			w.Header().Set("Docker-Content-Digest", manifestDigest)
			_, _ = w.Write(manifestJSON)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"+bundleDigest):
			_, _ = w.Write([]byte(bundleJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy-bundle@" + manifestDigest

	data, gotDigest, err := resolver.FetchPolicyBundle(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchPolicyBundle() error = %v", err)
	}
	if string(data) != bundleJSON {
		t.Errorf("FetchPolicyBundle() data = %q, want %q", string(data), bundleJSON)
	}
	if gotDigest != manifestDigest {
		t.Errorf("FetchPolicyBundle() digest = %q, want %q", gotDigest, manifestDigest)
	}
	if sawHead {
		t.Error("FetchPolicyBundle() issued HEAD for digest-pinned reference")
	}
}

func TestFetchPolicyBundle_EmbeddedOrgPolicyLayerDoesNotMatch(t *testing.T) {
	policyJSON := `{"requireSignatures":true}`
	policyDigest := policyDigestOf(policyJSON)

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    policyDigest,
				Size:      int64(len(policyJSON)),
			},
		},
	}
	manifestJSON := manifestBytes(t, manifest)
	manifestDigest := digestOf(manifestJSON)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"+manifestDigest) {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write(manifestJSON)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy-bundle@" + manifestDigest

	_, _, err := resolver.FetchPolicyBundle(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicyBundle() error = nil, want error for embedded orgpolicy-only manifest")
	}
	if !strings.Contains(err.Error(), "no policy bundle layer found") {
		t.Errorf("error = %q, want it to contain 'no policy bundle layer found'", err.Error())
	}
}

func TestFetchPolicyBundle_MissingBundleLayer(t *testing.T) {
	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("a", 64), Size: 10},
		},
	}
	manifestJSON := manifestBytes(t, manifest)
	manifestDigest := digestOf(manifestJSON)

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"+manifestDigest) {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_, _ = w.Write(manifestJSON)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	ref := srv.Listener.Addr().String() + "/myorg/policy-bundle@" + manifestDigest

	_, _, err := resolver.FetchPolicyBundle(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicyBundle() error = nil, want error for missing bundle layer")
	}
	if !strings.Contains(err.Error(), "no policy bundle layer found") {
		t.Errorf("error = %q, want it to contain 'no policy bundle layer found'", err.Error())
	}
}

func TestFindPolicyLayer(t *testing.T) {
	tests := []struct {
		name    string
		m       *ociManifest
		want    string
		wantErr bool
	}{
		{
			name: "single policy layer",
			m: &ociManifest{
				Layers: []ociDescriptor{
					{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("f", 64)},
					{MediaType: PolicyArtifactMediaType, Digest: "sha256:" + strings.Repeat("a", 64)},
				},
			},
			want: "sha256:" + strings.Repeat("a", 64),
		},
		{
			name: "multiple policy layers — first one wins (F-3 fix)",
			m: &ociManifest{
				Layers: []ociDescriptor{
					{MediaType: PolicyArtifactMediaType, Digest: "sha256:" + strings.Repeat("b", 64)},
					{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("f", 64)},
					{MediaType: PolicyArtifactMediaType, Digest: "sha256:" + strings.Repeat("c", 64)},
				},
			},
			want: "sha256:" + strings.Repeat("b", 64),
		},
		{
			name: "no layers",
			m: &ociManifest{
				Layers: []ociDescriptor{},
			},
			wantErr: true,
		},
		{
			name: "no policy layer",
			m: &ociManifest{
				Layers: []ociDescriptor{
					{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("a", 64)},
					{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("b", 64)},
				},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := findPolicyLayer(tt.m, nil, false)
			if tt.wantErr {
				if err == nil {
					t.Fatal("findPolicyLayer() error = nil, want error")
				}
				return
			}
			if err != nil {
				t.Fatalf("findPolicyLayer() error = %v", err)
			}
			if got.Digest != tt.want {
				t.Errorf("findPolicyLayer().Digest = %q, want %q", got.Digest, tt.want)
			}
		})
	}
}

// --- F-6: Separable org policy signer identity ---

// mustGenEd25519 generates a fresh Ed25519 key pair for tests.
func mustGenEd25519(t *testing.T) (ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("ed25519.GenerateKey: %v", err)
	}
	return pub, priv
}

// signDescriptorAnnotation returns the JSON-encoded OrgSignature annotation
// value for a policy layer descriptor (the new F-6 format used by SignDescriptor).
func signDescriptorAnnotation(t *testing.T, priv ed25519.PrivateKey, desc ociDescriptor) string {
	t.Helper()
	ann, err := SignDescriptor(priv, desc)
	if err != nil {
		t.Fatalf("SignDescriptor: %v", err)
	}
	return ann
}

// keyMap builds a trustedKeys map from a single public key.
func keyMap(pub ed25519.PublicKey) map[string]ed25519.PublicKey {
	return map[string]ed25519.PublicKey{OrgKeyID(pub): pub}
}

// TestFindPolicyLayer_OrgSignerSkipsUnsigned verifies that when an org signing
// key is configured, policy layers without the annotation are silently skipped
// rather than returned. An attacker who has image push access but not the
// org private key cannot inject an unsigned policy layer that is accepted.
func TestFindPolicyLayer_OrgSignerSkipsUnsigned(t *testing.T) {
	orgPub, _ := mustGenEd25519(t)

	digest := "sha256:" + strings.Repeat("a", 64)
	m := &ociManifest{
		Layers: []ociDescriptor{
			// Policy layer with correct media type but NO annotation — must be skipped.
			{MediaType: PolicyArtifactMediaType, Digest: digest},
		},
	}

	// Strict mode: reject entirely when no org-signed layer is found.
	_, err := findPolicyLayer(m, keyMap(orgPub), true)
	if err == nil {
		t.Fatal("findPolicyLayer() should reject unsigned layer in strict mode")
	}
	if !errors.Is(err, ErrNoOrgSignedPolicy) {
		t.Errorf("expected ErrNoOrgSignedPolicy in strict mode, got %v", err)
	}

	// Non-strict mode: fall back to first unsigned policy layer (no error).
	got, err := findPolicyLayer(m, keyMap(orgPub), false)
	if err != nil {
		t.Fatalf("findPolicyLayer() non-strict unexpected error: %v", err)
	}
	if got.Digest != digest {
		t.Errorf("non-strict fallback: got %q, want %q", got.Digest, digest)
	}
}

// TestFindPolicyLayer_OrgSignerRejectsBadSig verifies that a policy layer with
// an annotation signed by a DIFFERENT key (wrong signer or key mismatch) is
// rejected with a signature verification error, not silently skipped.
func TestFindPolicyLayer_OrgSignerRejectsBadSig(t *testing.T) {
	orgPub, _ := mustGenEd25519(t)
	_, attackerPriv := mustGenEd25519(t) // different key pair

	digest := "sha256:" + strings.Repeat("b", 64)
	layer := ociDescriptor{MediaType: PolicyArtifactMediaType, Digest: digest, Size: 42}
	// Attacker signs with their own key — org won't have it in the trusted set.
	badAnn := signDescriptorAnnotation(t, attackerPriv, layer)

	m := &ociManifest{
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    digest,
				Size:      42,
				Annotations: map[string]string{
					AnnotationOrgPolicySigner: badAnn,
				},
			},
		},
	}

	// Strict mode: an attacker-signed layer (key not in trustedKeys) is skipped,
	// and no org-signed layer is found, so ErrNoOrgSignedPolicy is returned.
	_, err := findPolicyLayer(m, keyMap(orgPub), true)
	if err == nil {
		t.Fatal("findPolicyLayer() should not accept layer signed by unknown key in strict mode")
	}
	if !errors.Is(err, ErrNoOrgSignedPolicy) {
		t.Errorf("expected ErrNoOrgSignedPolicy in strict mode, got %v", err)
	}
}

// TestFindPolicyLayer_OrgSignerAcceptsSigned verifies the happy path: a policy
// layer with a valid org-signer annotation is accepted and returned.
func TestFindPolicyLayer_OrgSignerAcceptsSigned(t *testing.T) {
	orgPub, orgPriv := mustGenEd25519(t)

	digest := "sha256:" + strings.Repeat("c", 64)
	policyDesc := ociDescriptor{MediaType: PolicyArtifactMediaType, Digest: digest, Size: 100}
	validAnn := signDescriptorAnnotation(t, orgPriv, policyDesc)

	m := &ociManifest{
		Layers: []ociDescriptor{
			// Non-policy layer — ignored.
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("f", 64)},
			// Valid signed policy layer.
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    digest,
				Size:      100,
				Annotations: map[string]string{
					AnnotationOrgPolicySigner: validAnn,
				},
			},
		},
	}

	got, err := findPolicyLayer(m, keyMap(orgPub), false)
	if err != nil {
		t.Fatalf("findPolicyLayer() unexpected error: %v", err)
	}
	if got.Digest != digest {
		t.Errorf("findPolicyLayer().Digest = %q, want %q", got.Digest, digest)
	}
}

// TestFindPolicyLayer_OrgSignerLastSignedWins verifies that when multiple org-signed
// policy layers exist, the LAST one wins (F-6 design: allows policy updates by
// appending a new signed layer to a derived image). Unsigned layers are skipped.
func TestFindPolicyLayer_OrgSignerLastSignedWins(t *testing.T) {
	orgPub, orgPriv := mustGenEd25519(t)

	firstDigest := "sha256:" + strings.Repeat("1", 64)
	secondDigest := "sha256:" + strings.Repeat("2", 64)
	unsignedDigest := "sha256:" + strings.Repeat("u", 64)

	firstDesc := ociDescriptor{MediaType: PolicyArtifactMediaType, Digest: firstDigest, Size: 10}
	secondDesc := ociDescriptor{MediaType: PolicyArtifactMediaType, Digest: secondDigest, Size: 20}

	m := &ociManifest{
		Layers: []ociDescriptor{
			// Unsigned policy layer — must be skipped.
			{MediaType: PolicyArtifactMediaType, Digest: unsignedDigest},
			// First signed policy layer.
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    firstDigest,
				Size:      10,
				Annotations: map[string]string{
					AnnotationOrgPolicySigner: signDescriptorAnnotation(t, orgPriv, firstDesc),
				},
			},
			// Second signed policy layer (e.g. org appended a policy update).
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    secondDigest,
				Size:      20,
				Annotations: map[string]string{
					AnnotationOrgPolicySigner: signDescriptorAnnotation(t, orgPriv, secondDesc),
				},
			},
		},
	}

	got, err := findPolicyLayer(m, keyMap(orgPub), false)
	if err != nil {
		t.Fatalf("findPolicyLayer() unexpected error: %v", err)
	}
	// Last signed layer wins — org updates policy by appending a new signed layer.
	if got.Digest != secondDigest {
		t.Errorf("findPolicyLayer().Digest = %q, want last-signed-wins %q", got.Digest, secondDigest)
	}
}

// TestFindPolicyLayer_OrgSignerMalformedAnnotation verifies that a malformed
// annotation (not valid JSON OrgSignature) causes the layer to be silently
// skipped during the signed scan, and ultimately returns ErrNoPolicyLayer
// (non-strict mode) or ErrNoOrgSignedPolicy (strict mode).
func TestFindPolicyLayer_OrgSignerMalformedAnnotation(t *testing.T) {
	orgPub, _ := mustGenEd25519(t)

	m := &ociManifest{
		Layers: []ociDescriptor{
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    "sha256:" + strings.Repeat("d", 64),
				Annotations: map[string]string{
					AnnotationOrgPolicySigner: "!!!not-valid-json-or-base64!!!",
				},
			},
		},
	}

	// Strict mode: malformed annotation is silently skipped during signed scan;
	// no signed layer found → ErrNoOrgSignedPolicy.
	_, err := findPolicyLayer(m, keyMap(orgPub), true)
	if err == nil {
		t.Fatal("findPolicyLayer() should return an error when no valid layer found in strict mode")
	}
	if !errors.Is(err, ErrNoOrgSignedPolicy) {
		t.Errorf("expected ErrNoOrgSignedPolicy in strict mode, got %v", err)
	}
}

// TestAppendPolicyLayer_Signed verifies that AppendPolicyLayer with a non-nil
// orgSignerKey writes the AnnotationOrgPolicySigner annotation to the layer
// descriptor, and that the annotation is a valid Ed25519 signature over the
// blob digest string verifiable by the corresponding public key.
func TestAppendPolicyLayer_Signed(t *testing.T) {
	orgPub, orgPriv := mustGenEd25519(t)
	policyJSON := []byte(`{"requireSignatures": true}`)
	policyDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(policyJSON))

	var capturedManifest ociManifest

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"):
			// Return a minimal existing manifest.
			existing := ociManifest{
				Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: "sha256:" + strings.Repeat("0", 64)},
				Layers: []ociDescriptor{},
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(existing)

		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blobs/uploads/"):
			w.Header().Set("Location", "/v2/myorg/app/blobs/uploads/upload-id")
			w.WriteHeader(http.StatusAccepted)

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/blobs/uploads/"):
			w.WriteHeader(http.StatusCreated)

		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/"):
			_ = json.NewDecoder(r.Body).Decode(&capturedManifest)
			w.WriteHeader(http.StatusCreated)

		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	imageRef := srv.Listener.Addr().String() + "/myorg/app:latest"

	_, err := resolver.AppendPolicyLayer(context.Background(), imageRef, policyJSON, orgPriv)
	if err != nil {
		t.Fatalf("AppendPolicyLayer() error = %v", err)
	}

	// The pushed manifest must have exactly one policy layer.
	if len(capturedManifest.Layers) != 1 {
		t.Fatalf("expected 1 layer in pushed manifest, got %d", len(capturedManifest.Layers))
	}
	layer := capturedManifest.Layers[0]
	if layer.MediaType != PolicyArtifactMediaType {
		t.Errorf("layer.MediaType = %q, want %q", layer.MediaType, PolicyArtifactMediaType)
	}
	if layer.Digest != policyDigest {
		t.Errorf("layer.Digest = %q, want %q", layer.Digest, policyDigest)
	}

	// Annotation must be present and verify against the org public key.
	_, ok := layer.Annotations[AnnotationOrgPolicySigner]
	if !ok {
		t.Fatalf("layer.Annotations missing %q", AnnotationOrgPolicySigner)
	}

	// Verify the annotation using the new F-6 multi-key VerifyDescriptor.
	if err := VerifyDescriptor(layer, keyMap(orgPub)); err != nil {
		t.Errorf("VerifyDescriptor() error = %v, want nil", err)
	}
}

// TestAppendPolicyLayer_Unsigned verifies that AppendPolicyLayer with a nil
// orgSignerKey produces a layer descriptor WITHOUT the annotation. This is the
// default (backward-compatible) path.
func TestAppendPolicyLayer_Unsigned(t *testing.T) {
	policyJSON := []byte(`{"requireSignatures": false}`)

	var capturedManifest ociManifest

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"):
			existing := ociManifest{
				Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json", Digest: "sha256:" + strings.Repeat("0", 64)},
				Layers: []ociDescriptor{},
			}
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(existing)
		case r.Method == http.MethodPost && strings.Contains(r.URL.Path, "/blobs/uploads/"):
			w.Header().Set("Location", "/v2/myorg/app/blobs/uploads/upload-id")
			w.WriteHeader(http.StatusAccepted)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/blobs/uploads/"):
			w.WriteHeader(http.StatusCreated)
		case r.Method == http.MethodPut && strings.Contains(r.URL.Path, "/manifests/"):
			_ = json.NewDecoder(r.Body).Decode(&capturedManifest)
			w.WriteHeader(http.StatusCreated)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()))
	imageRef := srv.Listener.Addr().String() + "/myorg/app:latest"

	_, err := resolver.AppendPolicyLayer(context.Background(), imageRef, policyJSON, nil)
	if err != nil {
		t.Fatalf("AppendPolicyLayer() error = %v", err)
	}

	if len(capturedManifest.Layers) != 1 {
		t.Fatalf("expected 1 layer, got %d", len(capturedManifest.Layers))
	}
	layer := capturedManifest.Layers[0]
	if _, ok := layer.Annotations[AnnotationOrgPolicySigner]; ok {
		t.Error("unsigned path must not produce AnnotationOrgPolicySigner annotation")
	}
}

// TestFetchPolicy_OrgSignerEndToEnd verifies FetchPolicy when a resolver is
// configured with WithOrgSignerPublicKey: it fetches a manifest, finds the
// signed policy layer, verifies the annotation, and returns the correct data.
func TestFetchPolicy_OrgSignerEndToEnd(t *testing.T) {
	orgPub, orgPriv := mustGenEd25519(t)
	policyJSON := `{"requireSignatures": true, "minSLSALevel": 3}`
	policyDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(policyJSON)))

	// Build the policy descriptor and sign it with the new JSON OrgSignature format.
	policyDesc := ociDescriptor{
		MediaType: PolicyArtifactMediaType,
		Digest:    policyDigest,
		Size:      int64(len(policyJSON)),
	}
	validAnn := signDescriptorAnnotation(t, orgPriv, policyDesc)

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			// A non-policy layer.
			{MediaType: "application/vnd.oci.image.layer.v1.tar+gzip", Digest: "sha256:" + strings.Repeat("f", 64)},
			// The signed policy layer.
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    policyDigest,
				Size:      int64(len(policyJSON)),
				Annotations: map[string]string{
					AnnotationOrgPolicySigner: validAnn,
				},
			},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
		case r.Method == http.MethodGet && strings.Contains(r.URL.Path, "/blobs/"):
			_, _ = w.Write([]byte(policyJSON))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()

	resolver := NewResolver(WithHTTPClient(srv.Client()), WithOrgSignerPublicKey(orgPub))
	ref := srv.Listener.Addr().String() + "/myorg/policy:latest"

	data, err := resolver.FetchPolicy(context.Background(), ref)
	if err != nil {
		t.Fatalf("FetchPolicy() error = %v", err)
	}
	if string(data) != policyJSON {
		t.Errorf("FetchPolicy() = %q, want %q", string(data), policyJSON)
	}
}

// TestFetchPolicy_OrgSignerRejectsUnsignedLayer verifies that FetchPolicy in
// strict mode fails when the manifest contains only unsigned policy layers.
// An attacker with image push access cannot escalate by pushing an unsigned
// policy layer; the resolver rejects it when strict mode is enabled.
func TestFetchPolicy_OrgSignerRejectsUnsignedLayer(t *testing.T) {
	orgPub, _ := mustGenEd25519(t)
	policyJSON := `{"requireSignatures": false}` // attacker's permissive policy
	policyDigest := fmt.Sprintf("sha256:%x", sha256.Sum256([]byte(policyJSON)))

	manifest := ociManifest{
		Config: ociDescriptor{MediaType: "application/vnd.oci.image.config.v1+json"},
		Layers: []ociDescriptor{
			// Unsigned policy layer — must be rejected in strict mode.
			{
				MediaType: PolicyArtifactMediaType,
				Digest:    policyDigest,
				Size:      int64(len(policyJSON)),
				// No AnnotationOrgPolicySigner annotation.
			},
		},
	}

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/manifests/") {
			w.Header().Set("Content-Type", "application/vnd.oci.image.manifest.v1+json")
			_ = json.NewEncoder(w).Encode(manifest)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	// Strict mode + org key: unsigned layers must be rejected.
	resolver := NewResolver(
		WithHTTPClient(srv.Client()),
		WithOrgSignerPublicKey(orgPub),
		WithOrgStrictMode(true),
	)
	ref := srv.Listener.Addr().String() + "/myorg/policy:latest"

	_, err := resolver.FetchPolicy(context.Background(), ref)
	if err == nil {
		t.Fatal("FetchPolicy() should fail in strict mode when only unsigned policy layers exist")
	}
	if !errors.Is(err, ErrNoOrgSignedPolicy) {
		t.Errorf("expected ErrNoOrgSignedPolicy in strict mode, got %v", err)
	}
}
