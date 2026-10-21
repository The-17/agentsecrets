package opaque

import (
	"bytes"
	"encoding/json"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

const e2eCredID = "e2e-user@example.com"

func sidecarURL(t *testing.T) string {
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

	const addr = "127.0.0.1:8899"
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
	for i := 0; i < 50; i++ {
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

func postJSON(t *testing.T, url string, body any) map[string]string {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	req.Header.Set("Authorization", "Bearer e2e-token")
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("post %s: %v", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		var buf bytes.Buffer
		_, _ = buf.ReadFrom(resp.Body)
		t.Fatalf("post %s: status %d body %s", url, resp.StatusCode, buf.String())
	}
	var out map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatalf("decode %s: %v", url, err)
	}
	flat := make(map[string]string, len(out))
	for k, v := range out {
		if s, ok := v.(string); ok {
			flat[k] = s
		}
	}
	return flat
}

// TestClientAgainstRealSidecar drives the exported client helpers against the
// actual sidecar process. This is the test that would have caught a wire
// mismatch between the CLI and the server.
func TestClientAgainstRealSidecar(t *testing.T) {
	base := sidecarURL(t)
	const password = "real-sidecar-password"

	client, regStart, err := RegisterStart(password)
	if err != nil {
		t.Fatalf("register start: %v", err)
	}
	regOut := postJSON(t, base+"/v1/register/response", map[string]string{
		"reg_request":   EncodeB64(regStart),
		"credential_id": e2eCredID,
	})
	regResp, err := decodeB64(regOut["reg_response"])
	if err != nil {
		t.Fatalf("decode reg_response: %v", err)
	}
	record, err := RegisterFinish(client, regResp, e2eCredID)
	if err != nil {
		t.Fatalf("register finish helper: %v", err)
	}
	finishOut := postJSON(t, base+"/v1/register/finish", map[string]string{
		"reg_record":    EncodeB64(record),
		"credential_id": e2eCredID,
	})
	stored := finishOut["record"]
	if stored == "" {
		t.Fatal("sidecar returned an empty stored record")
	}

	loginClient, ke1, err := LoginStart(password)
	if err != nil {
		t.Fatalf("login start: %v", err)
	}
	startOut := postJSON(t, base+"/v1/login/start", map[string]string{
		"ke1":           EncodeB64(ke1),
		"record":        stored,
		"credential_id": e2eCredID,
	})
	ke3, sessionKey, err := LoginFinish(loginClient, startOut["ke2"], e2eCredID)
	if err != nil {
		t.Fatalf("login finish: %v", err)
	}
	doneOut := postJSON(t, base+"/v1/login/finish", map[string]string{
		"ke3":           EncodeB64(ke3),
		"server_state":  startOut["server_state"],
		"credential_id": e2eCredID,
	})
	if doneOut["session_key"] != EncodeB64(sessionKey) {
		t.Fatalf("session key mismatch: client and sidecar disagree")
	}

	// Wrong password must fail before the server is satisfied.
	badClient, badKE1, err := LoginStart("wrong-password")
	if err != nil {
		t.Fatalf("wrong login start: %v", err)
	}
	badStart := postJSON(t, base+"/v1/login/start", map[string]string{
		"ke1":           EncodeB64(badKE1),
		"record":        stored,
		"credential_id": e2eCredID,
	})
	if _, _, err := LoginFinish(badClient, badStart["ke2"], e2eCredID); err == nil {
		t.Fatal("client accepted a login with the wrong password")
	}
}
