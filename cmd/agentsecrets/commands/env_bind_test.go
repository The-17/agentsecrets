package commands

import (
	"errors"
	"strings"
	"testing"

	"github.com/The-17/agentsecrets/pkg/projects"
)

func TestDirectoryProjectMatch(t *testing.T) {
	projs := []projects.Project{
		{ID: "1", Name: "billing-api"},
		{ID: "2", Name: "other"},
	}

	t.Run("exact case-insensitive match", func(t *testing.T) {
		got, ok := directoryProjectMatch(projs, "Billing-API")
		if !ok || got.ID != "1" {
			t.Fatalf("got %v, %v; want billing-api", got, ok)
		}
	})

	t.Run("no match", func(t *testing.T) {
		if _, ok := directoryProjectMatch(projs, "billing"); ok {
			t.Fatal("a partial name must not be bound automatically")
		}
	})

	t.Run("ambiguous match", func(t *testing.T) {
		dup := append(projs, projects.Project{ID: "3", Name: "BILLING-API"})
		if _, ok := directoryProjectMatch(dup, "billing-api"); ok {
			t.Fatal("two projects with the same name must not be bound automatically")
		}
	})
}

func TestNoProjectDetail(t *testing.T) {
	t.Run("zero projects names create", func(t *testing.T) {
		detail := noProjectDetail(nil, nil)
		if !strings.Contains(detail, "project create") {
			t.Errorf("detail should name create, got %q", detail)
		}
		if strings.Contains(detail, "project use") {
			t.Errorf("detail should not send a user with no projects to project use, got %q", detail)
		}
	})

	t.Run("existing projects name use and list candidates", func(t *testing.T) {
		projs := []projects.Project{
			{Name: "billing-api"},
			{Name: "web"},
		}
		detail := noProjectDetail(projs, nil)
		if !strings.Contains(detail, "project use") || !strings.Contains(detail, "billing-api") || !strings.Contains(detail, "web") {
			t.Errorf("detail should name use and the candidates, got %q", detail)
		}
	})

	t.Run("failed lookup names both verbs", func(t *testing.T) {
		detail := noProjectDetail(nil, errors.New("offline"))
		if !strings.Contains(detail, "project create") || !strings.Contains(detail, "project use") {
			t.Errorf("detail should offer both verbs when the list failed, got %q", detail)
		}
	})

	t.Run("suggestion list is bounded", func(t *testing.T) {
		projs := make([]projects.Project, 9)
		for i := range projs {
			projs[i].Name = "p" + string(rune('a'+i))
		}
		detail := noProjectDetail(projs, nil)
		if strings.Contains(detail, "pj") || strings.Contains(detail, "pi") {
			t.Errorf("detail should cap the candidate list, got %q", detail)
		}
	})
}
