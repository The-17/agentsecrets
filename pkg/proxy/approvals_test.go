package proxy

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestApprovalCannotBePreGranted is the regression test for the self-approval
// loophole: an agent must not be able to approve a capability before the
// request that needs it exists.
func TestApprovalCannotBePreGranted(t *testing.T) {
	store := NewApprovalStore()

	if store.ApproveByID("deadbeefdeadbeefdeadbeefdeadbeef") {
		t.Fatal("ApproveByID accepted an ID with no waiting request (pre-approval)")
	}
	if store.HasPending() {
		t.Fatal("store reports a pending request after a rejected pre-approval")
	}

	// A request made afterwards must still block: no grant was recorded.
	done := make(chan bool, 1)
	go func() { done <- store.WaitForApproval(ApprovalKey{SecretKey: "STRIPE_KEY", Domain: "api.stripe.com", Method: "POST"}, 100*time.Millisecond) }()
	if approved := <-done; approved {
		t.Fatal("request was approved without a human decision")
	}
}

// TestApprovalIsSingleUse proves one approval releases exactly one request.
func TestApprovalIsSingleUse(t *testing.T) {
	store := NewApprovalStore()
	key := ApprovalKey{SecretKey: "STRIPE_KEY", Domain: "api.stripe.com", Method: "POST"}

	done := make(chan bool, 1)
	go func() { done <- store.WaitForApproval(key, 2*time.Second) }()

	id := waitForID(t, store)
	if !store.ApproveByID(id) {
		t.Fatal("ApproveByID rejected a live pending request")
	}
	if approved := <-done; !approved {
		t.Fatal("live request was not released by its approval")
	}
	if store.ApproveByID(id) {
		t.Fatal("the same approval ID was accepted twice (replay)")
	}
}

// TestApprovalIDIsUnguessable checks the ID is long random hex, not a
// secret/method/domain tuple an agent could construct.
func TestApprovalIDIsUnguessable(t *testing.T) {
	store := NewApprovalStore()
	go func() { store.WaitForApproval(ApprovalKey{SecretKey: "K", Domain: "d", Method: "GET"}, 500*time.Millisecond) }()

	id := waitForID(t, store)
	if len(id) != 32 {
		t.Fatalf("approval ID length = %d, want 32 hex chars", len(id))
	}
	for _, c := range id {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("approval ID %q is not lowercase hex", id)
		}
	}
}

func waitForID(t *testing.T, store *ApprovalStore) string {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p := store.PendingApprovals(); len(p) > 0 {
			return p[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no pending approval appeared")
	return ""
}

// TestServerApproveRejectsUnknownID covers the HTTP surface: an ID that is not
// currently waiting is a conflict, never a grant.
func TestServerApproveRejectsUnknownID(t *testing.T) {
	srv := NewServer(0, &Engine{Approvals: NewApprovalStore()})
	srv.SetSessionToken("session-token")

	body, _ := json.Marshal(map[string]string{"request_id": "00000000000000000000000000000000"})
	req := httptest.NewRequest(http.MethodPost, "/approve", bytes.NewReader(body))
	req.Header.Set("X-AS-Session-Token", "session-token")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusConflict {
		t.Fatalf("status = %d, want 409 (unknown ID must not approve)", rec.Code)
	}
}

func TestServerApproveRequiresRequestID(t *testing.T) {
	srv := NewServer(0, &Engine{Approvals: NewApprovalStore()})
	srv.SetSessionToken("session-token")

	req := httptest.NewRequest(http.MethodPost, "/approve", bytes.NewReader([]byte(`{}`)))
	req.Header.Set("X-AS-Session-Token", "session-token")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want 400 (request_id is mandatory)", rec.Code)
	}
}

// TestServerApproveReleasesLiveRequest is the happy path through HTTP.
func TestServerApproveReleasesLiveRequest(t *testing.T) {
	store := NewApprovalStore()
	srv := NewServer(0, &Engine{Approvals: store})
	srv.SetSessionToken("session-token")

	done := make(chan bool, 1)
	go func() {
		done <- store.WaitForApproval(ApprovalKey{SecretKey: "K", Domain: "d", Method: "GET"}, 2*time.Second)
	}()
	id := waitForID(t, store)

	body, _ := json.Marshal(map[string]string{"request_id": id})
	req := httptest.NewRequest(http.MethodPost, "/approve", bytes.NewReader(body))
	req.Header.Set("X-AS-Session-Token", "session-token")
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body=%s)", rec.Code, rec.Body.String())
	}
	if approved := <-done; !approved {
		t.Fatal("live request was not released by the HTTP approval")
	}
}

// TestValidateSessionFailsClosedWithoutToken guards the empty-token passthrough
// that used to turn every endpoint into an open door.
func TestValidateSessionFailsClosedWithoutToken(t *testing.T) {
	srv := NewServer(0, &Engine{Approvals: NewApprovalStore()})
	// Deliberately do not set a session token.

	req := httptest.NewRequest(http.MethodPost, "/approve", bytes.NewReader([]byte(`{"request_id":"x"}`)))
	rec := httptest.NewRecorder()
	srv.mux.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503 when no session token is initialized", rec.Code)
	}
}
