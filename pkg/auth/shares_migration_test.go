package auth

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/vault"
)

// migrationFixture builds a v1 vault and a Service whose vault PUT is recorded.
func migrationFixture(t *testing.T) (*Service, *vaultLoginState, *int) {
	t.Helper()
	putCalls := 0
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut && r.URL.Path == "/auth/vault/" {
			putCalls++
			w.WriteHeader(http.StatusOK)
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(server.Close)

	client := api.NewClient(func() string { return "" })
	client.BaseURL = server.URL
	svc := NewService(client)

	const (
		userID   = "user-1"
		password = "correct horse battery staple"
	)
	privateKey := bytes.Repeat([]byte{0x07}, vault.KeySize)
	record, material, err := vault.Create(userID, password, privateKey)
	if err != nil {
		t.Fatalf("create v1 vault: %v", err)
	}

	state := &vaultLoginState{
		UserID:        userID,
		Password:      password,
		Record:        record,
		Version:       record.VaultVersion,
		FromVault:     true,
		VK:            material.VK,
		ExportKey:     bytes.Repeat([]byte{0x42}, vault.KeySize),
		ServerVaultV2: true,
		Result:        &LoginResult{RecoveryConfirmed: true},
	}
	return svc, state, &putCalls
}

func TestMaybeMigrateToSharesRunsWhenEveryGatePasses(t *testing.T) {
	svc, state, putCalls := migrationFixture(t)
	if err := svc.maybeMigrateToShares(state); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if !state.Record.IsSplit() {
		t.Fatal("vault was not upgraded to v2")
	}
	if *putCalls != 1 {
		t.Fatalf("expected one vault upload, got %d", *putCalls)
	}
	if state.Record.MinClientVersion != vault.MinClientVersionV2 {
		t.Fatalf("min_client_version = %q, want %q", state.Record.MinClientVersion, vault.MinClientVersionV2)
	}
	// The upgraded vault must still unlock with both shares.
	if _, err := state.Record.UnlockWithShares(state.UserID, state.Password, state.ExportKey); err != nil {
		t.Fatalf("migrated vault does not unlock: %v", err)
	}
}

func TestMaybeMigrateToSharesSkippedWithoutExportKey(t *testing.T) {
	svc, state, putCalls := migrationFixture(t)
	state.ExportKey = nil
	if err := svc.maybeMigrateToShares(state); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if state.Record.IsSplit() {
		t.Fatal("vault migrated without an export key")
	}
	if *putCalls != 0 {
		t.Fatalf("expected no upload, got %d", *putCalls)
	}
}

func TestMaybeMigrateToSharesSkippedWhenServerLacksV2(t *testing.T) {
	svc, state, putCalls := migrationFixture(t)
	state.ServerVaultV2 = false
	if err := svc.maybeMigrateToShares(state); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if state.Record.IsSplit() {
		t.Fatal("vault migrated although the server does not advertise vault_v2")
	}
	if *putCalls != 0 {
		t.Fatalf("expected no upload, got %d", *putCalls)
	}
}

func TestMaybeMigrateToSharesSkippedWhenRecoveryUnconfirmed(t *testing.T) {
	svc, state, putCalls := migrationFixture(t)
	state.Result.RecoveryConfirmed = false
	if err := svc.maybeMigrateToShares(state); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if state.Record.IsSplit() {
		t.Fatal("vault migrated before the recovery key was confirmed")
	}
	if *putCalls != 0 {
		t.Fatalf("expected no upload, got %d", *putCalls)
	}
}

func TestMaybeMigrateToSharesIsIdempotent(t *testing.T) {
	svc, state, putCalls := migrationFixture(t)
	if err := svc.maybeMigrateToShares(state); err != nil {
		t.Fatalf("first migrate: %v", err)
	}
	if err := svc.maybeMigrateToShares(state); err != nil {
		t.Fatalf("second migrate: %v", err)
	}
	if *putCalls != 1 {
		t.Fatalf("expected one upload across two calls, got %d", *putCalls)
	}
}
