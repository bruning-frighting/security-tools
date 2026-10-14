// Package allowlist implements scoped, expiring suppression.
//
// Suppression here is never silent. A suppressed finding is still produced, still counted at
// the top of the report, and still listed in an appendix -- it is merely moved out of the
// analyst's primary working set. An allowlist that hides things invisibly is how real
// intrusions get missed.
package allowlist

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"
)

// Entry is one suppression rule. Every field except Hash/Signer is mandatory; Load rejects
// an entry that is missing scope, reason, owner or expiry.
type Entry struct {
	ID string `json:"id"`
	// ArtifactType narrows the entry to one kind of artifact. Required: an untyped
	// allowlist entry is far too broad.
	ArtifactType string `json:"artifact_type"`
	// PathGlob scopes the entry by artifact identity. Required.
	PathGlob string `json:"path_glob"`
	// Signer or Hash further narrows the scope. At least one of them is required, because
	// a path alone is trivially satisfied by an attacker who writes to that path.
	Signer string `json:"signer,omitempty"`
	Hash   string `json:"sha256,omitempty"`

	Reason string `json:"reason"`
	Owner  string `json:"owner"`
	// Expires is mandatory. A permanent allowlist entry is an unreviewed decision that
	// outlives the person who made it.
	Expires string `json:"expires"`

	expiry time.Time
}

type Set struct {
	Entries []Entry
	// Expired entries are retained so the report can state that they were ignored, rather
	// than silently treating an expired suppression as active or as absent.
	Expired []Entry
	now     func() time.Time
}

// Load parses an allowlist file and validates every entry.
//
// Validation is strict and fatal: a malformed allowlist silently suppressing the wrong
// things is worse than refusing to start.
func Load(path string, now func() time.Time) (*Set, error) {
	if now == nil {
		now = time.Now
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading allowlist %s: %w", path, err)
	}
	var file struct {
		Entries []Entry `json:"entries"`
	}
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("parsing allowlist %s: %w", path, err)
	}

	s := &Set{now: now}
	seen := map[string]bool{}
	for i, e := range file.Entries {
		where := fmt.Sprintf("%s entry %d (id=%q)", path, i, e.ID)
		if strings.TrimSpace(e.ID) == "" {
			return nil, fmt.Errorf("%s: missing id", where)
		}
		if seen[e.ID] {
			return nil, fmt.Errorf("%s: duplicate id", where)
		}
		seen[e.ID] = true
		if strings.TrimSpace(e.ArtifactType) == "" {
			return nil, fmt.Errorf("%s: missing artifact_type", where)
		}
		if strings.TrimSpace(e.PathGlob) == "" {
			return nil, fmt.Errorf("%s: missing path_glob (scope is mandatory)", where)
		}
		if strings.TrimSpace(e.Signer) == "" && strings.TrimSpace(e.Hash) == "" {
			return nil, fmt.Errorf("%s: scope needs a signer or a sha256 in addition to a "+
				"path; a path alone can be satisfied by an attacker writing to that path",
				where)
		}
		if strings.TrimSpace(e.Reason) == "" {
			return nil, fmt.Errorf("%s: missing reason", where)
		}
		if strings.TrimSpace(e.Owner) == "" {
			return nil, fmt.Errorf("%s: missing owner", where)
		}
		if strings.TrimSpace(e.Expires) == "" {
			return nil, fmt.Errorf("%s: missing expiry (permanent suppressions are not "+
				"permitted)", where)
		}
		t, err := time.Parse("2006-01-02", e.Expires)
		if err != nil {
			return nil, fmt.Errorf("%s: expires must be YYYY-MM-DD: %w", where, err)
		}
		e.expiry = t
		if t.Before(now()) {
			s.Expired = append(s.Expired, e)
			continue
		}
		s.Entries = append(s.Entries, e)
	}
	return s, nil
}

// Match implements check.Allowlister.
func (s *Set) Match(artifactType, artifactID string, attrs map[string]string) (string, string) {
	if s == nil {
		return "", ""
	}
	for _, e := range s.Entries {
		if !strings.EqualFold(e.ArtifactType, artifactType) {
			continue
		}
		if !globMatch(e.PathGlob, artifactID) {
			continue
		}
		// The path matched; now the mandatory second scope dimension must also match.
		if e.Hash != "" {
			if !strings.EqualFold(attrs["sha256"], e.Hash) {
				continue
			}
		} else if e.Signer != "" {
			if !strings.EqualFold(attrs["signer"], e.Signer) {
				continue
			}
		}
		return e.ID, fmt.Sprintf("%s (owner %s, expires %s)", e.Reason, e.Owner, e.Expires)
	}
	return "", ""
}

// globMatch is a deliberately small matcher supporting only '*' (any run of characters).
// Comparison is case-insensitive and separator-normalised so one entry works for both
// Windows and Linux artifact identities.
func globMatch(pattern, s string) bool {
	p := strings.ToLower(strings.ReplaceAll(pattern, `\`, "/"))
	v := strings.ToLower(strings.ReplaceAll(s, `\`, "/"))
	parts := strings.Split(p, "*")
	if len(parts) == 1 {
		return p == v
	}
	if !strings.HasPrefix(v, parts[0]) {
		return false
	}
	v = v[len(parts[0]):]
	for i := 1; i < len(parts)-1; i++ {
		idx := strings.Index(v, parts[i])
		if idx < 0 {
			return false
		}
		v = v[idx+len(parts[i]):]
	}
	return strings.HasSuffix(v, parts[len(parts)-1])
}

// Empty is the no-op allowlist used when the operator supplies none.
type Empty struct{}

func (Empty) Match(string, string, map[string]string) (string, string) { return "", "" }
