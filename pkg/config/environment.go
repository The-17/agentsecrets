package config

import (
	"fmt"
	"os"
	"regexp"
	"sort"
	"strings"
)

// StandardEnvironments are the environments every project starts with, in
// display order. Any other valid environment name is a custom environment.
var StandardEnvironments = []string{"development", "staging", "production"}

// EnvironmentNamePattern is the control plane's slug rule. It must stay
// identical to the rule in the control plane's apps/secrets_app/environment.py.
const EnvironmentNamePattern = `^[a-z][a-z0-9-]{1,31}$`

// EnvironmentNameRule spells EnvironmentNamePattern out for humans. Error
// messages and help strings use it so the wording cannot drift from the rule.
const EnvironmentNameRule = "lowercase letters, numbers and hyphens, starting with a letter, 2 to 32 characters"

var environmentNameRegexp = regexp.MustCompile(EnvironmentNamePattern)

// reservedEnvironments are names the control plane refuses because its routes
// or infrastructure already claim them.
var reservedEnvironments = map[string]struct{}{
	"root":     {},
	"admin":    {},
	"api":      {},
	"internal": {},
	"default":  {},
}

// IsReservedEnvironment reports whether name is reserved by the control plane.
func IsReservedEnvironment(name string) bool {
	_, ok := reservedEnvironments[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

// ParseEnvironment normalizes and validates an environment name exactly as the
// control plane does: trim, lowercase, then apply the slug rule. Custom names
// are as valid as the standard three. The returned name is what gets stored and
// sent to the server.
func ParseEnvironment(raw string) (string, error) {
	name := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case name == "":
		return "", fmt.Errorf("environment name is required: use %s", EnvironmentNameRule)
	case IsReservedEnvironment(name):
		return "", fmt.Errorf("%q is a reserved environment name; choose another name", name)
	case !environmentNameRegexp.MatchString(name):
		return "", fmt.Errorf("invalid environment name %q: use %s", raw, EnvironmentNameRule)
	}
	return name, nil
}

// IsStandardEnvironment reports whether name is one of the three environments
// every project starts with. It expects a normalized name.
func IsStandardEnvironment(name string) bool {
	for _, standard := range StandardEnvironments {
		if name == standard {
			return true
		}
	}
	return false
}

// EnvironmentColumnLabel returns the short upper-case label used for table
// columns. The standard three keep their historical labels. A custom name maps
// to its slug in upper case with hyphens as underscores: stable, a legal
// identifier, and collision-free because a slug cannot contain an underscore.
func EnvironmentColumnLabel(name string) string {
	switch name {
	case "development":
		return "DEV"
	case "staging":
		return "STAGING"
	case "production":
		return "PROD"
	}
	return strings.ToUpper(strings.ReplaceAll(name, "-", "_"))
}

// dotenvVariants are conventional dotenv file suffixes that name a file, not an
// environment. Without this, `.env.example` would list "example" as an
// environment, and `.env.local` a "local" one nobody selected.
var dotenvVariants = map[string]struct{}{
	"example":  {},
	"local":    {},
	"sample":   {},
	"template": {},
}

// LocalEnvironments returns every environment this machine knows about: the
// standard three first, then custom names found in the project or global
// selection, a .env.<name> file in projectRoot, or a synced-secret cache.
// Names the user has never touched on this machine cannot be discovered, because
// the control plane exposes no environment list per project.
func LocalEnvironments(projectID, projectRoot string) ([]string, error) {
	custom := make(map[string]struct{})

	add := func(raw string) {
		name, err := ParseEnvironment(raw)
		if err != nil || IsStandardEnvironment(name) {
			return
		}
		custom[name] = struct{}{}
	}

	if p, err := LoadProjectConfig(); err == nil && p != nil {
		add(p.Environment)
	}
	if c, err := LoadGlobalConfig(); err == nil && c != nil {
		add(c.SelectedEnvironment)
	}

	if projectRoot != "" {
		entries, err := os.ReadDir(projectRoot)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("list environment files in %s: %w", projectRoot, err)
		}
		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}
			name, ok := strings.CutPrefix(entry.Name(), ".env.")
			if !ok {
				continue
			}
			if _, isVariant := dotenvVariants[name]; isVariant {
				continue
			}
			add(name)
		}
	}

	if projectID != "" {
		paths, err := GetPaths()
		if err != nil {
			return nil, err
		}
		entries, err := os.ReadDir(paths.GlobalDir)
		if err != nil && !os.IsNotExist(err) {
			return nil, fmt.Errorf("list cached environments in %s: %w", paths.GlobalDir, err)
		}
		prefix := "cloud_cache_" + projectID + "_"
		for _, entry := range entries {
			name, ok := strings.CutPrefix(entry.Name(), prefix)
			if !ok {
				continue
			}
			name, ok = strings.CutSuffix(name, ".json")
			if !ok {
				continue
			}
			add(name)
		}
	}

	local := make([]string, 0, len(StandardEnvironments)+len(custom))
	local = append(local, StandardEnvironments...)
	extra := make([]string, 0, len(custom))
	for name := range custom {
		extra = append(extra, name)
	}
	sort.Strings(extra)
	return append(local, extra...), nil
}
