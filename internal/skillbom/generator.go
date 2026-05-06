package skillbom

import (
	"context"
	"crypto/sha256"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

// Generator produces a SkillBOM for a skill directory.
type Generator interface {
	Generate(ctx context.Context, skillPath string) (*SkillBOM, error)
}

// DefaultGenerator is the standard SkillBOM generator that reads a skill
// directory, enumerates files, parses metadata, computes content hashes,
// and builds a CycloneDX 1.7 document.
type DefaultGenerator struct {
	// ACVersion is the agentcontainer binary version string included in the BOM metadata.
	ACVersion string
}

// NewGenerator returns a Generator with the given ac version.
func NewGenerator(acVersion string) *DefaultGenerator {
	return &DefaultGenerator{ACVersion: acVersion}
}

// fileEntry represents a single file in the skill directory.
type fileEntry struct {
	RelPath    string
	SHA256     string
	Executable bool
}

// Generate produces a SkillBOM for the skill at skillPath.
func (g *DefaultGenerator) Generate(ctx context.Context, skillPath string) (*SkillBOM, error) {
	// Validate skill directory.
	skillMD := filepath.Join(skillPath, "SKILL.md")
	if _, err := os.Stat(skillMD); err != nil {
		return nil, fmt.Errorf("skill directory must contain SKILL.md: %w", err)
	}

	// Parse metadata from SKILL.md frontmatter / capabilities.json.
	meta, err := ParseSkillDir(skillPath)
	if err != nil {
		return nil, fmt.Errorf("parsing skill metadata: %w", err)
	}

	// Default name from directory if not in frontmatter.
	if meta.Name == "" {
		meta.Name = filepath.Base(skillPath)
	}

	// Enumerate and hash all files.
	files, err := enumerateFiles(skillPath)
	if err != nil {
		return nil, fmt.Errorf("enumerating files: %w", err)
	}

	// Compute semantic content hash (M1: deterministic hash of metadata).
	contentHash, err := computeContentHash(meta)
	if err != nil {
		return nil, fmt.Errorf("computing content hash: %w", err)
	}

	// Build CycloneDX document.
	cdxJSON, err := buildCycloneDX(meta, files, contentHash, g.ACVersion)
	if err != nil {
		return nil, fmt.Errorf("building CycloneDX document: %w", err)
	}

	digest := fmt.Sprintf("sha256:%x", sha256.Sum256(cdxJSON))

	return &SkillBOM{
		Format:       Format,
		SkillName:    meta.Name,
		Version:      meta.Version,
		Description:  meta.Description,
		Capabilities: meta.Capabilities,
		ContentHash:  contentHash,
		Content:      cdxJSON,
		Digest:       digest,
		Components:   len(files),
		GeneratedAt:  time.Now().UTC(),
	}, nil
}

// enumerateFiles walks the skill directory and returns a sorted list of files
// with their SHA-256 hashes and executable status.
func enumerateFiles(dir string) ([]fileEntry, error) {
	var entries []fileEntry

	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip hidden directories.
			if d.Name() != "." && strings.HasPrefix(d.Name(), ".") {
				return filepath.SkipDir
			}
			return nil
		}
		// Skip hidden files.
		if strings.HasPrefix(d.Name(), ".") {
			return nil
		}

		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return fmt.Errorf("computing relative path: %w", err)
		}
		// Normalize to forward slashes for cross-platform consistency.
		rel = filepath.ToSlash(rel)

		data, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("reading %s: %w", rel, err)
		}

		hash := fmt.Sprintf("%x", sha256.Sum256(data))

		info, err := d.Info()
		if err != nil {
			return fmt.Errorf("stat %s: %w", rel, err)
		}
		executable := info.Mode()&0o111 != 0

		entries = append(entries, fileEntry{
			RelPath:    rel,
			SHA256:     hash,
			Executable: executable,
		})
		return nil
	})
	if err != nil {
		return nil, err
	}

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].RelPath < entries[j].RelPath
	})
	return entries, nil
}

// computeContentHash produces a deterministic SHA-256 hash from the skill's
// semantic content. For M1 this is based on normalized metadata fields.
// M2 will replace this with an actual embedding vector hash.
//
// The hash is computed over: normalized(name) + "\n" + normalized(description) + "\n" + sorted capabilities joined by "\n".
func computeContentHash(meta *SkillMetadata) (string, error) {
	var parts []string
	parts = append(parts, normalizeText(meta.Name))
	parts = append(parts, normalizeText(meta.Description))

	caps := make([]string, len(meta.Capabilities))
	copy(caps, meta.Capabilities)
	sort.Strings(caps)
	parts = append(parts, caps...)

	combined := strings.Join(parts, "\n")
	hash := sha256.Sum256([]byte(combined))
	return fmt.Sprintf("sha256:%x", hash), nil
}

// normalizeText applies the SkillBOM text normalization algorithm:
// - Strip leading/trailing whitespace
// - Normalize Unicode to NFC form
// - Collapse consecutive whitespace to single spaces
func normalizeText(s string) string {
	s = strings.TrimSpace(s)
	s = norm.NFC.String(s)
	// Collapse whitespace.
	var b strings.Builder
	prevSpace := false
	for _, r := range s {
		if unicode.IsSpace(r) {
			if !prevSpace {
				b.WriteRune(' ')
			}
			prevSpace = true
		} else {
			b.WriteRune(r)
			prevSpace = false
		}
	}
	return b.String()
}
