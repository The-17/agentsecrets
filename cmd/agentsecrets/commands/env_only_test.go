package commands

import (
	"reflect"
	"sort"
	"testing"
)

func TestFilterSecrets(t *testing.T) {
	all := map[string]string{"A": "1", "B": "2", "C": "3"}

	t.Run("selects only named", func(t *testing.T) {
		got, missing := filterSecrets(all, []string{"A", " C "})
		if len(missing) != 0 {
			t.Fatalf("unexpected missing: %v", missing)
		}
		want := map[string]string{"A": "1", "C": "3"}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("got %v, want %v", got, want)
		}
	})

	t.Run("reports unknown names", func(t *testing.T) {
		got, missing := filterSecrets(all, []string{"A", "NOPE"})
		if len(got) != 1 || got["A"] != "1" {
			t.Errorf("expected only A, got %v", got)
		}
		sort.Strings(missing)
		if !reflect.DeepEqual(missing, []string{"NOPE"}) {
			t.Errorf("expected missing [NOPE], got %v", missing)
		}
	})

	t.Run("ignores empty entries", func(t *testing.T) {
		got, missing := filterSecrets(all, []string{"", " "})
		if len(got) != 0 || len(missing) != 0 {
			t.Errorf("expected empty result, got %v / %v", got, missing)
		}
	})
}
