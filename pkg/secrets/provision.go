// Package secrets provisioning primitives let a secret value be stored without
// the value ever passing through a command line or a model's context. The
// value arrives from a reader (typed at a visible prompt or piped in), is
// generated in-process, or is produced by a source command's stdout or a
// fetched URL. It is never an argv argument, so it stays out of shell history
// and process listings, and it is never a tool parameter or tool result.
package secrets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
)

// MaxProvisionInput bounds the bytes accepted from any value source.
const MaxProvisionInput = 1 << 20 // 1 MiB

// sourceCommandTimeout bounds how long a --from-command source may run.
const sourceCommandTimeout = 60 * time.Second

// httpSourceTimeout bounds how long a source=http fetch may take.
const httpSourceTimeout = 30 * time.Second

// StoredMeta describes a stored secret without revealing its value. Safe to
// print, log, or return over MCP.
type StoredMeta struct {
	Key         string `json:"key_name"`
	Environment string `json:"environment"`
	Length      int    `json:"length"`
	Fingerprint string `json:"fingerprint"`
}

// Fingerprint returns a short, non-reversible identifier for a value. For a
// high-entropy secret it reveals nothing usable; it exists so an operator can
// confirm which value is stored without reading it.
func Fingerprint(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])[:12]
}

func newMeta(key, env, value string) StoredMeta {
	return StoredMeta{
		Key:         key,
		Environment: env,
		Length:      len(value),
		Fingerprint: Fingerprint(value),
	}
}

// NormalizeValue turns raw source bytes into a storable value: it trims a
// trailing newline (so `printf` and interactive input behave alike) and rejects
// empty input. It is a pure transform so it can be tested without a store.
func NormalizeValue(raw []byte) (string, error) {
	value := strings.TrimRight(string(raw), "\r\n")
	if value == "" {
		return "", fmt.Errorf("empty value: nothing to store")
	}
	return value, nil
}

// ExtractJSONPath returns the string at path within a JSON body. Path segments
// are dot-separated object keys; a numeric segment indexes an array. Only a
// non-empty string leaf is accepted, so a stored value is never "null" or a
// rendered number.
func ExtractJSONPath(raw []byte, path string) (string, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return "", fmt.Errorf("json path: empty path")
	}

	var current interface{}
	if err := json.Unmarshal(raw, &current); err != nil {
		return "", fmt.Errorf("json path: body is not valid JSON: %w", err)
	}

	for _, seg := range strings.Split(path, ".") {
		seg = strings.TrimSpace(seg)
		switch node := current.(type) {
		case map[string]interface{}:
			v, ok := node[seg]
			if !ok {
				return "", fmt.Errorf("json path: key %q not found", seg)
			}
			current = v
		case []interface{}:
			idx, err := strconv.Atoi(seg)
			if err != nil || idx < 0 || idx >= len(node) {
				return "", fmt.Errorf("json path: invalid array index %q", seg)
			}
			current = node[idx]
		default:
			return "", fmt.Errorf("json path: cannot descend into %q", seg)
		}
	}

	switch v := current.(type) {
	case string:
		if v == "" {
			return "", fmt.Errorf("json path: %s is an empty string", path)
		}
		return v, nil
	case nil:
		return "", fmt.Errorf("json path: %s is null", path)
	default:
		return "", fmt.Errorf("json path: %s is not a string", path)
	}
}

// applyExtract resolves the value from raw body bytes: the string at extract
// when a path is given, otherwise the whole body normalized.
func applyExtract(raw []byte, extract string) (string, error) {
	if strings.TrimSpace(extract) == "" {
		return NormalizeValue(raw)
	}
	return ExtractJSONPath(raw, extract)
}

// ReadValueFromCommand runs command through the platform shell and returns its
// stdout as a value. When extract is non-empty, the value is the string at that
// dot-separated JSON path in the stdout instead of the whole stdout. Only
// stdout is captured; stderr is attached to the error for diagnosis and never
// treated as the value.
func ReadValueFromCommand(command, extract string) (string, error) {
	raw, err := runCommandRaw(command)
	if err != nil {
		return "", err
	}
	return applyExtract(raw, extract)
}

// runCommandRaw runs command through the platform shell and returns its stdout
// bytes. The command is the caller's own and runs at the caller's trust level.
func runCommandRaw(command string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), sourceCommandTimeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(ctx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(ctx, "sh", "-c", command)
	}

	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		detail := strings.TrimSpace(stderr.String())
		if detail != "" {
			return nil, fmt.Errorf("source command failed: %w: %s", err, detail)
		}
		return nil, fmt.Errorf("source command failed: %w", err)
	}

	return []byte(stdout.String()), nil
}

// resolveEnv returns the explicit environment, or the active one when empty.
func resolveEnv(environment string) string {
	if environment != "" {
		return environment
	}
	return config.ResolveEnvironment()
}

func validateProvision(key, environment string) error {
	if strings.TrimSpace(key) == "" {
		return fmt.Errorf("provision: empty key name")
	}
	if !config.IsValidEnvironment(resolveEnv(environment)) {
		return fmt.Errorf("provision: invalid environment %q", environment)
	}
	return nil
}

// DescribeValue builds the metadata for a value a caller already holds. It is
// the exported twin of the internal constructor, so callers outside this
// package cannot disagree about how metadata is computed.
func DescribeValue(key, environment, value string) StoredMeta {
	return newMeta(key, environment, value)
}

// SetProvisioned stores a value the caller already holds in process memory, and
// returns metadata only. The source-based methods below are preferred; this
// exists for capture paths (the MCP api_call capture) where the value already
// crossed no model-visible boundary.
func (s *Service) SetProvisioned(key, value, environment string) (StoredMeta, error) {
	if err := validateProvision(key, environment); err != nil {
		return StoredMeta{}, err
	}
	if value == "" {
		return StoredMeta{}, fmt.Errorf("provision: empty value for %s", key)
	}
	if len(value) > MaxProvisionInput {
		return StoredMeta{}, fmt.Errorf("provision: value exceeds %d bytes", MaxProvisionInput)
	}
	if err := s.BatchSet(map[string]string{key: value}, environment); err != nil {
		return StoredMeta{}, err
	}
	return newMeta(key, resolveEnv(environment), value), nil
}

// SetFromReader stores a secret whose value is read from r. Use it behind a
// visible prompt or a pipe. A single trailing newline is trimmed.
func (s *Service) SetFromReader(key string, r io.Reader, environment string) (StoredMeta, error) {
	if err := validateProvision(key, environment); err != nil {
		return StoredMeta{}, err
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxProvisionInput+1))
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: read value: %w", err)
	}
	if len(raw) > MaxProvisionInput {
		return StoredMeta{}, fmt.Errorf("provision: value exceeds %d bytes", MaxProvisionInput)
	}
	value, err := NormalizeValue(raw)
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: %w", err)
	}
	return s.SetProvisioned(key, value, environment)
}

// Generate mints a random value, stores it, and returns metadata only. The
// value is never returned, because nothing outside the vault needs to read it.
func (s *Service) Generate(key string, byteLength int, environment string) (StoredMeta, error) {
	if err := validateProvision(key, environment); err != nil {
		return StoredMeta{}, err
	}
	if byteLength <= 0 {
		byteLength = 32
	}
	value, err := crypto.GeneratePassword(byteLength)
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: generate: %w", err)
	}
	return s.SetProvisioned(key, value, environment)
}

// SetFromCommand stores the stdout of command as the secret value. When
// extract is non-empty, the value is the string at that dot-separated JSON path
// in the stdout instead of the whole stdout. The command is the caller's own,
// run at the caller's trust level. stdout is never logged.
func (s *Service) SetFromCommand(key, command, extract, environment string) (StoredMeta, error) {
	if err := validateProvision(key, environment); err != nil {
		return StoredMeta{}, err
	}
	if strings.TrimSpace(command) == "" {
		return StoredMeta{}, fmt.Errorf("provision: empty source command")
	}

	raw, err := runCommandRaw(command)
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: %w", err)
	}
	value, err := applyExtract(raw, extract)
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: %w", err)
	}
	return s.SetProvisioned(key, value, environment)
}

// SetFromHTTP stores the response body of a GET to rawURL as the secret value.
// When extract is non-empty, the value is the string at that dot-separated JSON
// path in the body instead of the whole body.
func (s *Service) SetFromHTTP(key, rawURL, extract, environment string, headers map[string]string) (StoredMeta, error) {
	if err := validateProvision(key, environment); err != nil {
		return StoredMeta{}, err
	}
	if strings.TrimSpace(rawURL) == "" {
		return StoredMeta{}, fmt.Errorf("provision: empty URL")
	}

	ctx, cancel := context.WithTimeout(context.Background(), httpSourceTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rawURL, nil)
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: invalid URL: %w", err)
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: fetch: %w", err)
	}
	defer resp.Body.Close()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, MaxProvisionInput+1))
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: read response: %w", err)
	}
	if len(raw) > MaxProvisionInput {
		return StoredMeta{}, fmt.Errorf("provision: response exceeds %d bytes", MaxProvisionInput)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return StoredMeta{}, fmt.Errorf("provision: HTTP %d fetching %s", resp.StatusCode, rawURL)
	}

	value, err := applyExtract(raw, extract)
	if err != nil {
		return StoredMeta{}, fmt.Errorf("provision: %w", err)
	}
	return s.SetProvisioned(key, value, environment)
}
