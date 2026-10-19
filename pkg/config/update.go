package config

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// GitHubRelease represents the structure of a GitHub release from the API
type GitHubRelease struct {
	TagName string `json:"tag_name"`
}

// CheckResult represents the outcome of an update check
type CheckResult struct {
	NewVersionAvailable bool
	LatestVersion       string
	CurrentVersion      string
}

// CheckForUpdates checks GitHub for a newer version of the CLI.
// It only performs the check if more than 24 hours have passed since the last one.
// Returns a CheckResult if a newer version is found, or nil if no check was performed or no update was found.
func CheckForUpdates(currentVersion string) (*CheckResult, error) {
	if currentVersion == "dev" {
		return nil, nil // Don't check for dev builds
	}

	cfg, err := LoadGlobalConfig()
	if err != nil {
		return nil, nil // Silently fail if config can't be loaded
	}

	now := time.Now().Unix()
	const oneDay = 24 * 60 * 60
	const sixHours = 6 * 60 * 60

	// If we checked recently, check if a newer version is already cached
	if now-cfg.LastUpdateCheck < oneDay {
		if cfg.LatestVersion != "" && isNewer(cfg.LatestVersion, currentVersion) {
			// Limit update notifications to at most once every 6 hours
			if now-cfg.LastUpdateAlert >= sixHours {
				cfg.LastUpdateAlert = now
				_ = SaveGlobalConfig(cfg) // Best effort save
				return &CheckResult{
					NewVersionAvailable: true,
					LatestVersion:       cfg.LatestVersion,
					CurrentVersion:      currentVersion,
				}, nil
			}
		}
		return nil, nil
	}

	// Perform the check
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("https://api.github.com/repos/The-17/agentsecrets/releases/latest")
	if err != nil {
		return nil, fmt.Errorf("failed to check for updates: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("github api returned status: %d", resp.StatusCode)
	}

	var release GitHubRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("failed to decode github response: %w", err)
	}

	latest := strings.TrimPrefix(release.TagName, "v")

	// Update cache
	cfg.LastUpdateCheck = now
	cfg.LatestVersion = latest

	if isNewer(latest, currentVersion) {
		if now-cfg.LastUpdateAlert >= sixHours {
			cfg.LastUpdateAlert = now
			_ = SaveGlobalConfig(cfg) // Save cache and alert time
			return &CheckResult{
				NewVersionAvailable: true,
				LatestVersion:       latest,
				CurrentVersion:      currentVersion,
			}, nil
		}
	}
	_ = SaveGlobalConfig(cfg) // Just save cache
	return nil, nil
}

// isNewer is a simple semantic version comparator.
// Assumes standard semver (e.g., 1.1.2)
func isNewer(latest, current string) bool {
	if latest == current {
		return false
	}

	lParts := strings.Split(latest, ".")
	cParts := strings.Split(current, ".")

	for i := 0; i < len(lParts) && i < len(cParts); i++ {
		var l, c int
		fmt.Sscanf(lParts[i], "%d", &l)
		fmt.Sscanf(cParts[i], "%d", &c)

		if l > c {
			return true
		}
		if l < c {
			return false
		}
	}

	// If prefixes are same, the one with more parts is "newer" (e.g. 1.1.2.1 > 1.1.2)
	return len(lParts) > len(cParts)
}

// VersionStatus returns a short human-readable verdict for the running CLI
// version against the latest version from the cached update check. It performs
// no network I/O, so callers can use it on read-only paths such as `status`.
// An empty string means there is nothing worth reporting.
func VersionStatus(current, latest string) string {
	current = strings.TrimPrefix(strings.TrimSpace(current), "v")
	latest = strings.TrimPrefix(strings.TrimSpace(latest), "v")
	if current == "" {
		return ""
	}

	prerelease := strings.ContainsAny(current, "-+")

	if latest == "" {
		if prerelease {
			return "dev build"
		}
		return ""
	}

	// A prerelease is compared against the release it is based on, so
	// 4.0.0-dev is only "outdated" once 4.0.0 or newer ships.
	base := current
	if i := strings.IndexAny(base, "-+"); i >= 0 {
		base = base[:i]
	}
	if isNewer(latest, base) {
		return "outdated, " + latest + " available"
	}
	if prerelease {
		return "dev build"
	}
	return "up to date"
}
