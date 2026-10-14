// Package registry loads the ATT&CK registry that was generated at build time and embedded
// into the binary.
//
// The scanner never downloads anything (PLAN.md section 1), so this embedded copy is the
// only ATT&CK data that exists at scan time. Its provenance -- version, source URL, SHA-256
// of the upstream STIX bundle -- travels with it and is printed in every report.
package registry

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// registry_embed.json is produced by build/build_registry.py. It is a generated file: do not
// edit it by hand, and do not let the Go side mutate it. Regenerate with
//
//	python build/build_registry.py
//
//go:embed embedded/registry_embed.json
var embedded []byte

type Source struct {
	Version     string `json:"version"`
	SHA256      string `json:"sha256"`
	URL         string `json:"url"`
	RetrievedAt string `json:"retrieved_at"`
	Attribution string `json:"attribution"`
}

type Scope struct {
	ImplementationTactics []string `json:"implementation_tactics"`
	HostPlatforms         []string `json:"host_platforms"`
	Note                  string   `json:"note"`
}

type Tactic struct {
	ID                    string `json:"id"`
	Shortname             string `json:"shortname"`
	Name                  string `json:"name"`
	InImplementationScope bool   `json:"in_implementation_scope"`
}

// Technique is the runtime view. Review-only fields (log sources, detection strategies,
// full reasons) stay in data/registry/attack_registry.json and are not embedded.
type Technique struct {
	ID        string   `json:"technique_id"`
	Name      string   `json:"name"`
	Tactics   []string `json:"tactics"`
	TacticIDs []string `json:"tactic_ids"`
	Platforms []string `json:"platforms"`
	// OSScope is the intersection with {windows, linux}.
	OSScope        []string `json:"os_scope"`
	IsSubtechnique bool     `json:"is_subtechnique"`
	ParentID       string   `json:"parent_id"`
	Active         bool     `json:"active"`
	Revoked        bool     `json:"revoked"`
	Deprecated     bool     `json:"deprecated"`
	RevokedByID    string   `json:"revoked_by_id"`
	// InRegistryScope: active and applicable to a Windows or Linux host. This is U_host.
	InRegistryScope bool `json:"in_registry_scope"`
	// InImplementationScope: U_host plus one of the four scope tactics. This is U_impl.
	InImplementationScope bool   `json:"in_implementation_scope"`
	TestabilityClass      string `json:"testability_class"`
	// BaselineStatus is the registry's claim BEFORE the check inventory is consulted. It is
	// never IMPLEMENTED or PARTIAL; only a gate-passing check can produce those.
	BaselineStatus    string `json:"baseline_implementation_status"`
	BaselineRationale string `json:"baseline_implementation_rationale"`
	URL               string `json:"url"`
}

// SupportsOS reports whether the technique applies to the named OS ("windows"/"linux").
func (t Technique) SupportsOS(os string) bool {
	for _, o := range t.OSScope {
		if o == os {
			return true
		}
	}
	return false
}

// HasTactic reports membership by tactic shortname.
func (t Technique) HasTactic(shortname string) bool {
	for _, s := range t.Tactics {
		if s == shortname {
			return true
		}
	}
	return false
}

type Counts map[string]any

type Registry struct {
	SchemaVersion string      `json:"schema_version"`
	Source        Source      `json:"source"`
	Scope         Scope       `json:"scope"`
	Tactics       []Tactic    `json:"tactics"`
	Counts        Counts      `json:"counts"`
	Techniques    []Technique `json:"techniques"`

	byID map[string]*Technique
}

var loaded *Registry

// Load parses the embedded registry. The result is cached; the registry is immutable.
func Load() (*Registry, error) {
	if loaded != nil {
		return loaded, nil
	}
	var r Registry
	if err := json.Unmarshal(embedded, &r); err != nil {
		return nil, fmt.Errorf("parsing embedded ATT&CK registry: %w", err)
	}
	if len(r.Techniques) == 0 {
		return nil, fmt.Errorf("embedded ATT&CK registry is empty; run build/build_registry.py")
	}
	if r.Source.Version == "" || r.Source.SHA256 == "" {
		return nil, fmt.Errorf("embedded registry has no source provenance; refusing to run " +
			"with untraceable ATT&CK data")
	}
	r.byID = make(map[string]*Technique, len(r.Techniques))
	for i := range r.Techniques {
		r.byID[r.Techniques[i].ID] = &r.Techniques[i]
	}
	loaded = &r
	return loaded, nil
}

// MustLoad is for callers that cannot proceed without the registry.
func MustLoad() *Registry {
	r, err := Load()
	if err != nil {
		panic(err)
	}
	return r
}

// Get returns a technique by ATT&CK ID, or nil.
func (r *Registry) Get(id string) *Technique { return r.byID[id] }

// Exists is the guard that stops a check from citing an ATT&CK ID that does not exist. The
// mapping validator uses it, which is how "do not invent ATT&CK IDs" is enforced in code
// rather than by review alone.
func (r *Registry) Exists(id string) bool { _, ok := r.byID[id]; return ok }

// HostScope returns U_host: active techniques applicable to Windows or Linux.
func (r *Registry) HostScope() []*Technique {
	return r.filter(func(t *Technique) bool { return t.InRegistryScope })
}

// ImplementationScope returns U_impl.
func (r *Registry) ImplementationScope() []*Technique {
	return r.filter(func(t *Technique) bool { return t.InImplementationScope })
}

// Inactive returns revoked and deprecated objects, reported separately and never counted in
// a live denominator.
func (r *Registry) Inactive() []*Technique {
	return r.filter(func(t *Technique) bool { return !t.Active })
}

func (r *Registry) filter(pred func(*Technique) bool) []*Technique {
	var out []*Technique
	for i := range r.Techniques {
		if pred(&r.Techniques[i]) {
			out = append(out, &r.Techniques[i])
		}
	}
	sort.Slice(out, func(i, j int) bool { return SortKey(out[i].ID) < SortKey(out[j].ID) })
	return out
}

// TacticName resolves a shortname to its display name, falling back to the shortname.
func (r *Registry) TacticName(shortname string) string {
	for _, t := range r.Tactics {
		if t.Shortname == shortname {
			return t.Name
		}
	}
	return shortname
}

// ImplementationTactics returns the four scope tactic shortnames.
func (r *Registry) ImplementationTactics() []string { return r.Scope.ImplementationTactics }

// SortKey orders T1547 before T1547.001 and T1003.002 before T1003.010.
func SortKey(id string) string {
	base, sub, found := strings.Cut(id, ".")
	b := strings.TrimPrefix(base, "T")
	for len(b) < 6 {
		b = "0" + b
	}
	if !found {
		return b + ".000"
	}
	for len(sub) < 3 {
		sub = "0" + sub
	}
	return b + "." + sub
}

// Provenance renders the one-line attribution every report carries.
func (r *Registry) Provenance() string {
	return fmt.Sprintf("MITRE ATT&CK Enterprise v%s (STIX sha256 %s, retrieved %s) -- %s",
		r.Source.Version, r.Source.SHA256, r.Source.RetrievedAt, r.Source.Attribution)
}
