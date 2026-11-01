package auth

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
)

const opaqueTestCredID = "opaque-test@example.com"

// startSidecar builds and runs the real OPAQUE sidecar, returning its base URL.
func startSidecar(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "opaque-sidecar")
	build := exec.Command("go", "build", "-o", bin, "../../cmd/opaque-sidecar")
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Skipf("cannot build sidecar: %v", err)
	}

	keys := exec.Command(bin, "-print-keys")
	keysOut, err := keys.Output()
	if err != nil {
		t.Fatalf("print-keys: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := ln.Addr().String()
	ln.Close()

	cmd := exec.Command(bin, "--addr", addr)
	cmd.Env = append(os.Environ(),
		"OPAQUE_SIDECAR_TOKEN=e2e-token",
		"OPAQUE_SERVER_KEY_MATERIAL="+string(bytes.TrimSpace(keysOut)),
	)
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start sidecar: %v", err)
	}
	t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait() })

	url := "http://" + addr
	for i := 0; i < 150; i++ {
		resp, err := http.Get(url + "/healthz")
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return url
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("sidecar never became healthy")
	return ""
}

// setupOpaqueTest wires a Service whose API client talks to a mock control plane
// that proxies the OPAQUE blob endpoints to the real sidecar and returns key
// material on login/finish. It returns the Service.
func setupOpaqueTest(t *testing.T) *Service {
	t.Helper()
	setupAuthTest(t)
	sidecar := startSidecar(t)

	// storedRecord is owned by the control plane (server-side OPAQUE state).
	var storedRecord string
	mux := http.NewServeMux()

	// forward proxies a CLI JSON body to the sidecar, optionally injecting the
	// stored record (which the control plane owns, never the client), and wraps
	// the sidecar's answer in Django's CustomResponse.success envelope
	// ({"status":"success","data":...}) so the CLI parses it as in production.
	forward := func(w http.ResponseWriter, r *http.Request, sidecarPath string, injectRecord bool) {
		raw, _ := io.ReadAll(r.Body)
		var body map[string]any
		_ = json.Unmarshal(raw, &body)
		body["credential_id"] = opaqueTestCredID
		if injectRecord {
			body["record"] = storedRecord
		}
		buf, _ := json.Marshal(body)
		req, _ := http.NewRequest(r.Method, sidecar+sidecarPath, bytes.NewReader(buf))
		req.Header.Set("Authorization", "Bearer e2e-token")
		req.Header.Set("Content-Type", "application/json")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		out, _ := io.ReadAll(resp.Body)

		// Capture the stored record from register/finish before wrapping.
		if sidecarPath == "/v1/register/finish" {
			var parsed map[string]any
			if json.Unmarshal(out, &parsed) == nil {
				if s, ok := parsed["record"].(string); ok {
					storedRecord = s
				}
			}
		}

		// Wrap in the {"status":"success","data":<sidecar answer>} envelope.
		env, _ := json.Marshal(map[string]any{
			"status": "success",
			"data":   json.RawMessage(out),
		})
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(resp.StatusCode)
		w.Write(env)
	}

	mux.HandleFunc("/auth/opaque/register/start/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/register/response", false)
	})
	mux.HandleFunc("/auth/opaque/register/finish/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/register/finish", false)
	})
	mux.HandleFunc("/auth/opaque/login/start/", func(w http.ResponseWriter, r *http.Request) {
		forward(w, r, "/v1/login/start", true)
	})
	mux.HandleFunc("/auth/opaque/login/finish/", func(w http.ResponseWriter, r *http.Request) {
		// The real login_finish view returns the login material (tokens + key
		// material) directly; the sidecar's session_key is used server-side and is
		// not part of the CLI's response. We just answer with the key material so
		// the CLI can unlock the vault locally (mirrors the real login_finish view).
		keys, _ := crypto.SetupUser("opaque-test-password")
		loginData := map[string]any{
			"access":                "access-token",
			"refresh":               "refresh-token",
			"expires_at":            "2026-01-01T00:00:00Z",
			"encrypted_private_key": keys.EncryptedPrivateKey,
			"key_salt":              keys.Salt,
			"vault":                 nil,
			"vault_version":         0,
			"user": map[string]any{
				"id":         "user-opaque",
				"public_key": base64.StdEncoding.EncodeToString(keys.PublicKey),
			},
			"workspaces": []any{},
		}
		env, _ := json.Marshal(map[string]any{
			"status": "success",
			"data":   loginData,
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(env)
	})
	mux.HandleFunc("/auth/capabilities/", func(w http.ResponseWriter, r *http.Request) {
		env, _ := json.Marshal(map[string]any{
			"status": "success",
			"data":   map[string]any{"opaque": true},
		})
		w.Header().Set("Content-Type", "application/json")
		w.Write(env)
	})
	mux.HandleFunc("/auth/login/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusUnauthorized)
		json.NewEncoder(w).Encode(map[string]any{
			"code":    "password_login_disabled",
			"message": "Password login is disabled for this account. Use OPAQUE login.",
		})
	})
	mux.HandleFunc("/auth/vault", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})

	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	client := api.NewClient(func() string { return config.GetAccessToken() })
	client.BaseURL = server.URL
	return NewService(client)
}

func TestOpaqueEnrollAndLogin(t *testing.T) {
	svc := setupOpaqueTest(t)
	const password = "opaque-test-password"

	if err := svc.EnrollOpaque(opaqueTestCredID, password); err != nil {
		t.Fatalf("EnrollOpaque: %v", err)
	}
	if !config.GetOpaqueEnrolled() {
		t.Error("EnrollOpaque did not set the local OpaqueEnrolled flag")
	}

	// Replay enrollment: it must be idempotent on the client (no record rotation).
	if err := svc.EnrollOpaque(opaqueTestCredID, password); err != nil {
		t.Fatalf("EnrollOpaque replay: %v", err)
	}

	if _, err := svc.OpaqueLogin(opaqueTestCredID, password); err != nil {
		t.Fatalf("OpaqueLogin: %v", err)
	}
	if config.GetEmail() != opaqueTestCredID {
		t.Errorf("email not stored: got %q", config.GetEmail())
	}
	if config.GetAccessToken() != "access-token" {
		t.Errorf("access token not stored: got %q", config.GetAccessToken())
	}
}

func TestLoginFallsBackToOpaque(t *testing.T) {
	svc := setupOpaqueTest(t)
	const password = "opaque-test-password"

	// Enroll first so the server has a record (as a real enrolled account would).
	if err := svc.EnrollOpaque(opaqueTestCredID, password); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	// Simulate a fresh device: the local flag is clear, so the first attempt hits
	// password login, which the server rejects with password_login_disabled. Login
	// must transparently retry through the OPAQUE exchange.
	if err := config.SetOpaqueEnrolled(false); err != nil {
		t.Fatal(err)
	}
	if _, err := svc.Login(opaqueTestCredID, password); err != nil {
		t.Fatalf("Login: %v", err)
	}
	if !config.GetOpaqueEnrolled() {
		t.Error("Login did not record OPAQUE enrollment after fallback")
	}
}

func TestOpaqueLoginWrongPasswordFails(t *testing.T) {
	svc := setupOpaqueTest(t)
	if err := svc.EnrollOpaque(opaqueTestCredID, "opaque-test-password"); err != nil {
		t.Fatalf("enroll: %v", err)
	}
	if _, err := svc.OpaqueLogin(opaqueTestCredID, "wrong-password"); err == nil {
		t.Fatal("OpaqueLogin accepted a wrong password")
	}
	// A failed login must not flip the enrolled flag off.
	if !config.GetOpaqueEnrolled() {
		t.Error("enrolled flag lost after a failed OpaqueLogin")
	}
}
