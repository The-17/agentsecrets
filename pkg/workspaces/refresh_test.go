package workspaces

import (
	"reflect"
	"testing"

	"github.com/The-17/agentsecrets/pkg/config"
)

// A workspace the user was just invited to must land in the cache and be
// reported, because the whole point of the refresh is that an invitation no
// longer requires logging out and back in.
func TestMergeWorkspaceCacheAddsNewMembership(t *testing.T) {
	current := map[string]config.WorkspaceCacheEntry{
		"ws-personal": {Name: "Personal", Role: "owner", Type: "personal"},
	}
	listed := []Workspace{
		{ID: "ws-personal", Name: "Personal", Role: "owner", Type: "personal"},
		{ID: "ws-team", Name: "The Seventeen", Role: "member", Type: "shared"},
	}

	merged, result := mergeWorkspaceCache(current, listed, func(id string) string {
		if id == "ws-team" {
			return "team-key"
		}
		return ""
	})

	if !reflect.DeepEqual(result.Added, []string{"The Seventeen"}) {
		t.Fatalf("Added = %v, want [The Seventeen]", result.Added)
	}
	if len(result.Changed) != 0 || len(result.Removed) != 0 {
		t.Fatalf("unexpected changes: %+v", result)
	}
	if got := merged["ws-team"]; got.Name != "The Seventeen" || got.Role != "member" || got.Key != "team-key" {
		t.Fatalf("ws-team entry = %+v, want name/role/key populated", got)
	}
}

func TestMergeWorkspaceCacheIsQuietWhenNothingMoved(t *testing.T) {
	current := map[string]config.WorkspaceCacheEntry{
		"ws-team": {Name: "The Seventeen", Role: "member", Type: "shared"},
	}
	listed := []Workspace{
		{ID: "ws-team", Name: "The Seventeen", Role: "member", Type: "shared"},
	}

	_, result := mergeWorkspaceCache(current, listed, func(string) string { return "" })

	if result.HasChanges() {
		t.Fatalf("expected no changes, got %+v", result)
	}
}

func TestMergeWorkspaceCacheReportsRoleChangeAndRemoval(t *testing.T) {
	current := map[string]config.WorkspaceCacheEntry{
		"ws-team":  {Name: "The Seventeen", Role: "member", Type: "shared"},
		"ws-gone":  {Name: "Old Team", Role: "member", Type: "shared"},
		"ws-stays": {Name: "Personal", Role: "owner", Type: "personal"},
	}
	listed := []Workspace{
		{ID: "ws-team", Name: "The Seventeen", Role: "admin", Type: "shared"},
		{ID: "ws-stays", Name: "Personal", Role: "owner", Type: "personal"},
	}

	merged, result := mergeWorkspaceCache(current, listed, func(string) string { return "" })

	if !reflect.DeepEqual(result.Changed, []string{"The Seventeen"}) {
		t.Fatalf("Changed = %v, want [The Seventeen]", result.Changed)
	}
	if !reflect.DeepEqual(result.Removed, []string{"Old Team"}) {
		t.Fatalf("Removed = %v, want [Old Team]", result.Removed)
	}
	if _, stillThere := merged["ws-gone"]; stillThere {
		t.Fatal("removed workspace is still in the cache")
	}
	if merged["ws-team"].Role != "admin" {
		t.Fatalf("role = %q, want admin", merged["ws-team"].Role)
	}
}

// A workspace whose key cannot be unwrapped keeps the key we already hold
// instead of being silently dropped.
func TestMergeWorkspaceCacheKeepsExistingKeyWhenUnwrapFails(t *testing.T) {
	current := map[string]config.WorkspaceCacheEntry{
		"ws-team": {Name: "The Seventeen", Role: "member", Type: "shared"},
	}
	listed := []Workspace{
		{ID: "ws-team", Name: "The Seventeen", Role: "member", Type: "shared"},
	}

	merged, _ := mergeWorkspaceCache(current, listed, func(string) string { return "" })

	if _, ok := merged["ws-team"]; !ok {
		t.Fatal("workspace dropped from the cache when its key could not be unwrapped")
	}
}
