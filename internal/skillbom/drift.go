package skillbom

import "math"

// DriftClassification categorizes the magnitude of semantic drift.
type DriftClassification string

const (
	DriftPatch    DriftClassification = "patch"
	DriftMinor    DriftClassification = "minor"
	DriftMajor    DriftClassification = "major"
	DriftBreaking DriftClassification = "breaking"
)

// DefaultThresholds are the default semantic drift classification boundaries.
var DefaultThresholds = DriftThresholds{
	Patch:    0.05,
	Minor:    0.15,
	Major:    0.40,
	Breaking: 0.40,
}

// DriftThresholds defines configurable drift classification boundaries.
type DriftThresholds struct {
	Patch    float64 // below this: patch (auto-approve)
	Minor    float64 // below this: minor (notify)
	Major    float64 // below this: major (require approval)
	Breaking float64 // at or above this: breaking (block)
}

// DriftResult holds the result of comparing two SkillBOMs.
type DriftResult struct {
	// Distance is the computed drift distance.
	// For M1 (content-hash mode): 0.0 if hashes match, 1.0 if they differ.
	// For M2 (embedding mode): cosine distance in [0.0, 2.0].
	Distance float64

	// Classification is the drift tier (patch/minor/major/breaking).
	Classification DriftClassification

	// OldHash is the content hash from the previous SkillBOM.
	OldHash string

	// NewHash is the content hash from the new SkillBOM.
	NewHash string

	// EmbeddingUsed is true when drift was computed via cosine distance
	// on embedding vectors rather than binary content-hash comparison.
	EmbeddingUsed bool

	// CapabilityEscalation is true if the new SkillBOM declares
	// capabilities not present in the old one.
	CapabilityEscalation bool

	// NewCapabilities lists capabilities added in the new version.
	NewCapabilities []string
}

// ComputeDrift compares two SkillBOMs and returns a DriftResult.
// For M1, drift is binary: 0.0 if content hashes match, 1.0 if not.
// The interface is designed so M2 can swap in cosine distance on real
// embedding vectors without changing callers.
func ComputeDrift(old, new *SkillBOM) *DriftResult {
	return ComputeDriftWithThresholds(old, new, DefaultThresholds)
}

// ComputeDriftWithThresholds compares two SkillBOMs using custom thresholds.
// If both SkillBOMs have EmbeddingVector populated, cosine distance is used.
// Otherwise, it falls back to binary content-hash comparison.
func ComputeDriftWithThresholds(old, new *SkillBOM, thresholds DriftThresholds) *DriftResult {
	var distance float64
	var embeddingUsed bool

	if len(old.EmbeddingVector) > 0 && len(new.EmbeddingVector) > 0 {
		distance = CosineDistance(old.EmbeddingVector, new.EmbeddingVector)
		embeddingUsed = true
	} else if old.ContentHash != new.ContentHash {
		distance = 1.0
	}

	result := &DriftResult{
		Distance:       distance,
		Classification: classifyDrift(distance, thresholds),
		OldHash:        old.ContentHash,
		NewHash:        new.ContentHash,
		EmbeddingUsed:  embeddingUsed,
	}

	// Detect capability escalation.
	oldCaps := make(map[string]bool, len(old.Capabilities))
	for _, c := range old.Capabilities {
		oldCaps[c] = true
	}
	for _, c := range new.Capabilities {
		if !oldCaps[c] {
			result.CapabilityEscalation = true
			result.NewCapabilities = append(result.NewCapabilities, c)
		}
	}

	return result
}

// classifyDrift maps a distance to a DriftClassification.
func classifyDrift(distance float64, t DriftThresholds) DriftClassification {
	switch {
	case distance < t.Patch:
		return DriftPatch
	case distance < t.Minor:
		return DriftMinor
	case distance < t.Major:
		return DriftMajor
	default:
		return DriftBreaking
	}
}

// IsDriftAcceptable returns true if the drift distance is below the threshold.
func IsDriftAcceptable(distance float64, threshold float64) bool {
	return distance < threshold
}

// CosineDistance computes the cosine distance between two vectors.
// Returns a value in [0.0, 2.0] where 0 = identical, 1 = orthogonal, 2 = opposite.
// If either vector is zero (all elements are zero), returns 1.0 (maximum uncertainty).
func CosineDistance(a, b []float32) float64 {
	n := len(a)
	if n == 0 || len(b) == 0 {
		return 1.0
	}
	// Use the shorter length if mismatched.
	if len(b) < n {
		n = len(b)
	}

	var dot, normA, normB float64
	for i := 0; i < n; i++ {
		ai, bi := float64(a[i]), float64(b[i])
		dot += ai * bi
		normA += ai * ai
		normB += bi * bi
	}
	// Handle remaining elements in the longer vector.
	for i := n; i < len(a); i++ {
		ai := float64(a[i])
		normA += ai * ai
	}
	for i := n; i < len(b); i++ {
		bi := float64(b[i])
		normB += bi * bi
	}

	if normA == 0 || normB == 0 {
		return 1.0
	}

	similarity := dot / (math.Sqrt(normA) * math.Sqrt(normB))
	// Clamp to [-1, 1] to guard against floating-point drift.
	if similarity > 1.0 {
		similarity = 1.0
	}
	if similarity < -1.0 {
		similarity = -1.0
	}
	return 1.0 - similarity
}

// NormalizeEmbedding returns an L2-normalized copy of the input vector.
// If the input is a zero vector, a zero-length slice is returned.
func NormalizeEmbedding(v []float32) []float32 {
	var sumSq float64
	for _, x := range v {
		sumSq += float64(x) * float64(x)
	}
	if sumSq == 0 {
		return nil
	}
	norm := math.Sqrt(sumSq)
	out := make([]float32, len(v))
	for i, x := range v {
		out[i] = float32(float64(x) / norm)
	}
	return out
}
