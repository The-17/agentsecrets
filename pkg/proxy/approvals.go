package proxy

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

// ApprovalKey identifies the capability being requested. It is NOT a grant:
// it only groups waiters so the terminal can display one prompt per distinct
// secret+domain+method.
type ApprovalKey struct {
	AgentID   string `json:"agent_id"`
	SecretKey string `json:"secret_key"`
	Domain    string `json:"domain"`
	Method    string `json:"method"`
}

// PendingApproval is one blocked request awaiting a human decision. ID is a
// 128-bit random value shown ONLY on the proxy terminal. It is never logged,
// never returned to the requesting client, and never placed in an audit row,
// so the agent that triggered the request cannot learn it and cannot approve
// its own call.
type PendingApproval struct {
	ID  string
	Key ApprovalKey
}

// approvalWaiter holds a channel that a blocked request goroutine waits on.
type approvalWaiter struct {
	id        string
	ch        chan bool
	createdAt time.Time
}

// ApprovalStore tracks requests currently waiting for a human decision.
//
// Security invariants:
//   - A grant always corresponds to a request that is waiting RIGHT NOW.
//     There is no "pre-approve" path: an approval for a request that is not
//     pending is rejected. This is what stops an agent from writing the
//     approve command first and running the proxy afterwards.
//   - Approval is single-use. One approval releases exactly one waiting
//     request. There is no session-wide grant to replay.
//   - The approval ID is generated here, never accepted from the caller, and
//     is only surfaced to the human on the proxy terminal.
type ApprovalStore struct {
	mu      sync.RWMutex
	pending map[ApprovalKey][]*approvalWaiter
	// notify receives a key whenever a new waiter registers, so the
	// interactive approval goroutine can print a prompt.
	notify chan ApprovalKey
}

// NewApprovalStore creates a ready-to-use ApprovalStore.
func NewApprovalStore() *ApprovalStore {
	return &ApprovalStore{
		pending: make(map[ApprovalKey][]*approvalWaiter),
		notify:  make(chan ApprovalKey, 32),
	}
}

// Notifications returns the channel that receives a key each time a new
// request starts waiting.
func (s *ApprovalStore) Notifications() <-chan ApprovalKey {
	return s.notify
}

func newApprovalID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(b[:]), nil
}

// WaitForApproval blocks until the specific waiter is approved, denied, or the
// timeout elapses. Returns true only if a human explicitly approved this
// request. The caller holds its HTTP connection open while waiting.
func (s *ApprovalStore) WaitForApproval(k ApprovalKey, timeout time.Duration) bool {
	id, err := newApprovalID()
	if err != nil {
		// No entropy means no safe approval ID; fail closed rather than
		// inventing a guessable one.
		return false
	}

	w := &approvalWaiter{
		id:        id,
		ch:        make(chan bool, 1),
		createdAt: time.Now(),
	}
	s.mu.Lock()
	s.pending[k] = append(s.pending[k], w)
	s.mu.Unlock()

	// Non-blocking notify to the interactive goroutine.
	select {
	case s.notify <- k:
	default:
		// Channel full — the goroutine will discover the waiter via
		// PendingApprovals on its next iteration.
	}

	select {
	case result := <-w.ch:
		return result
	case <-time.After(timeout):
		s.removeWaiter(k, w)
		return false
	}
}

// PendingApprovals returns a snapshot of waiting requests, each with the ID the
// human must present to approve it. IDs are only ever displayed on the proxy
// terminal.
func (s *ApprovalStore) PendingApprovals() []PendingApproval {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]PendingApproval, 0, len(s.pending))
	for k, waiters := range s.pending {
		for _, w := range waiters {
			out = append(out, PendingApproval{ID: w.id, Key: k})
		}
	}
	return out
}

// ApproveByID approves exactly one waiting request. It returns false when the
// ID does not match a request that is waiting right now — which is the
// pre-approval and replay guard. One call releases one waiter.
func (s *ApprovalStore) ApproveByID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, waiters := range s.pending {
		for i, w := range waiters {
			if w.id != id {
				continue
			}
			select {
			case w.ch <- true:
			default:
			}
			s.pending[k] = append(waiters[:i], waiters[i+1:]...)
			if len(s.pending[k]) == 0 {
				delete(s.pending, k)
			}
			return true
		}
	}
	return false
}

// DenyByID rejects exactly one waiting request. It returns false when the ID
// is unknown. Denial never persists: the next request prompts again.
func (s *ApprovalStore) DenyByID(id string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for k, waiters := range s.pending {
		for i, w := range waiters {
			if w.id != id {
				continue
			}
			select {
			case w.ch <- false:
			default:
			}
			s.pending[k] = append(waiters[:i], waiters[i+1:]...)
			if len(s.pending[k]) == 0 {
				delete(s.pending, k)
			}
			return true
		}
	}
	return false
}

// HasPending reports whether any request is currently waiting for approval.
func (s *ApprovalStore) HasPending() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for _, waiters := range s.pending {
		if len(waiters) > 0 {
			return true
		}
	}
	return false
}

// removeWaiter cleans up a timed-out waiter from the pending map.
func (s *ApprovalStore) removeWaiter(k ApprovalKey, target *approvalWaiter) {
	s.mu.Lock()
	defer s.mu.Unlock()
	waiters := s.pending[k]
	for i, w := range waiters {
		if w == target {
			s.pending[k] = append(waiters[:i], waiters[i+1:]...)
			break
		}
	}
	if len(s.pending[k]) == 0 {
		delete(s.pending, k)
	}
}
