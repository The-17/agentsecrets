// Package secrets orchestrates encrypted secret storage, retrieval, and synchronisation with the cloud API.
package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/The-17/agentsecrets/pkg/agents"
	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/capabilities"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
	"github.com/The-17/agentsecrets/pkg/telemetry"
)

// Service coordinates all secret-related operations.
type Service struct {
	API *api.Client
	Env *EnvManager
}

// NewService creates a new secrets service.
func NewService(apiClient *api.Client) *Service {
	return &Service{
		API: apiClient,
		Env: NewEnvManager(),
	}
}

// Set adds or updates a single secret.
func (s *Service) Set(key, value string) error {
	return s.BatchSet(map[string]string{key: value}, "")
}

// BatchSet adds or updates multiple secrets in a single API call.
// If environment is empty, it uses the currently resolved environment.
func (s *Service) BatchSet(kv map[string]string, environment string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("batch set: no project configured in current directory")
	}

	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return fmt.Errorf("batch set: %w", err)
	}

	env := environment
	if env == "" {
		env = config.ResolveEnvironment()
	}

	apiSecrets := make(map[string]string, len(kv))
	for k, v := range kv {
		// 1. Encrypt for cloud
		encryptedValue, err := crypto.EncryptSecret(v, workspaceKey)
		if err != nil {
			return fmt.Errorf("batch set: encryption failed for %s: %w", k, err)
		}
		apiSecrets[k] = encryptedValue
	}

	// 2. Store in OS Keychain (for Proxy support) in a single batch IPC round-trip.
	// This is best-effort: the cloud + .env writes below are the source of truth,
	// so a keychain miss (e.g. daemon not running) must not fail the whole set — but warn.
	if _, err := keyring.SetSecretsBatch(project.ProjectID, env, kv, nil); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not store secrets in OS keychain (proxy may not resolve them until next pull): %v\n", err)
	}

	// 3. Sync to cloud (Single bulk call with dictionary)
	data := map[string]interface{}{
		"project_id":  project.ProjectID,
		"environment": env,
		"secrets":     apiSecrets,
	}

	if err := s.API.CallNoContent("secrets.create", "POST", data, nil, nil); err != nil {
		return fmt.Errorf("batch set: API call failed: %w", err)
	}

	// 4. Write to .env
	if err := s.Env.Write(kv); err != nil {
		return fmt.Errorf("batch set: failed to update .env: %w", err)
	}

	// 5. Update local cache (reuses already encrypted values, eliminating double encryption)
	s.updateCacheAfterSetWithEncrypted(project.ProjectID, env, apiSecrets)

	// 6. Update .env.example
	_ = s.UpdateEnvExampleFromLocal()

	return nil
}

// Get retrieves and decrypts a single secret.
func (s *Service) Get(key string) (string, error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return "", fmt.Errorf("get secret: no project configured in current directory")
	}

	env := config.ResolveEnvironment()

	// Try keychain first (fast paths)
	if val, err := keyring.GetSecret(project.ProjectID, env, key); err == nil {
		return val, nil
	}

	// Fallback to API
	valWrapper, err := api.CallJSON[struct {
		Value string `json:"value"`
	}](s.API, "secrets.get", "GET", nil, map[string]string{
		"project_id":  project.ProjectID,
		"environment": env,
		"key":         key,
	}, nil)
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return "", err
	}

	plaintext, err := crypto.DecryptSecret(valWrapper.Value, wsKey)
	if err != nil {
		return "", fmt.Errorf("get secret: decrypt: %w", err)
	}

	// Cache in keychain (best-effort; a failure here only means the value is
	// re-fetched next time, so surface it as a warning rather than failing).
	if err := keyring.SetSecret(project.ProjectID, env, key, plaintext); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: could not cache %s in the OS keychain: %v\n", key, err)
	}

	return plaintext, nil
}

// SecretMetadata holds the secret metadata from the API.
type SecretMetadata struct {
	Key       string                      `json:"key"`
	Value     string                      `json:"value,omitempty"` // Encrypted value
	UpdatedAt string                      `json:"updated_at"`
	Policy    *capabilities.SecretPolicy  `json:"policy,omitempty"` // Secret-level target constraints
}

// List returns all secret keys for the project in the active environment.
func (s *Service) List() ([]SecretMetadata, error) {
	return s.ListForEnv(config.ResolveEnvironment())
}

// ListForEnv returns all secret keys for the project in the specified environment.
func (s *Service) ListForEnv(env string) ([]SecretMetadata, error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return nil, fmt.Errorf("list secrets: no project configured in current directory")
	}

	list, err := api.CallJSON[struct {
		Secrets       []SecretMetadata `json:"secrets"`
		WorkspaceID   string           `json:"workspace_id"`
		WorkspaceName string           `json:"workspace_name"`
	}](s.API, "secrets.list", "GET", nil, map[string]string{
		"project_id": project.ProjectID,
	}, map[string]string{
		"environment": env,
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	// Auto-heal workspace if project was transferred
	if list.WorkspaceID != "" && list.WorkspaceID != project.WorkspaceID {
		project.WorkspaceID = list.WorkspaceID
		if list.WorkspaceName != "" {
			project.WorkspaceName = list.WorkspaceName
		}
		_ = config.SaveProjectConfig(project)
	}

	// Cache the cloud secrets
	_ = s.writeCache(project.ProjectID, env, list.Secrets)

	return list.Secrets, nil
}

// Pull downloads secrets from the cloud and updates .env + Keychain.
// If targetKeys is nil, all secrets are pulled.
// If targetKeys is non-nil (even if empty), only those specific keys are pulled.
func (s *Service) Pull(targetKeys []string) error {
	isSelective := targetKeys != nil
	if isSelective && len(targetKeys) == 0 {
		return nil
	}

	secrets, err := s.List()
	if err != nil {
		return err
	}

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return err
	}
	filter := make(map[string]bool)
	for _, k := range targetKeys {
		filter[k] = true
	}

	project, _ := config.LoadProjectConfig()
	env := config.ResolveEnvironment()
	secretsMap := make(map[string]string)
	policies := make(map[string][]byte)

	for _, s := range secrets {
		if isSelective && !filter[s.Key] {
			continue
		}
		plaintext, err := crypto.DecryptSecret(s.Value, wsKey)
		if err != nil {
			if selKey, errSel := config.GetSelectedWorkspaceKey(); errSel == nil && selKey != nil && !bytes.Equal(selKey, wsKey) {
				if p2, err2 := crypto.DecryptSecret(s.Value, selKey); err2 == nil {
					plaintext = p2
					err = nil
					wsKey = selKey
					if cfg, errCfg := config.LoadGlobalConfig(); errCfg == nil && cfg.SelectedWorkspaceID != "" {
						project.WorkspaceID = cfg.SelectedWorkspaceID
						if ws, ok := cfg.Workspaces[cfg.SelectedWorkspaceID]; ok {
							project.WorkspaceName = ws.Name
						}
						_ = config.SaveProjectConfig(project)
					}
				}
			}
		}
		if err != nil {
			continue
		}
		secretsMap[s.Key] = plaintext

		// Prepare policy for batch write
		if s.Policy != nil && (len(s.Policy.Domains) > 0 || len(s.Policy.Methods) > 0) {
			policyBytes, err := json.Marshal(s.Policy)
			if err == nil {
				policies[s.Key] = policyBytes
			}
		} else {
			policies[s.Key] = nil
		}
	}

	// Batch write secrets + policies in a single round-trip
	keychainFailures := 0
	if len(secretsMap) > 0 {
		if _, err := keyring.SetSecretsBatch(project.ProjectID, env, secretsMap, policies); err != nil {
			keychainFailures = len(secretsMap) // Conservative: assume all failed
		}
	}

	// A keychain miss during pull is why the proxy later "can't find" secrets —
	// so don't swallow it. The .env write below still succeeds, so this stays a
	// warning rather than a hard failure.
	if keychainFailures > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d secret/policy value(s) could not be written to the OS keychain; the proxy may not resolve them until keychain-auth is available.\n", keychainFailures)
	}

	telemetry.RecordSecretCount(len(secretsMap))

	if isSelective && len(secretsMap) == 0 {
		// Even if empty, we want to ensure .env footprint is laid down
	}

	if err := s.Env.Write(secretsMap); err != nil {
		return fmt.Errorf("pull: failed to update local files: %w", err)
	}

	// Update project last_pull timestamp
	project.LastPull = time.Now().Format(time.RFC3339)
	if err := config.SaveProjectConfig(project); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: pull succeeded but failed to update last_pull timestamp: %v\n", err)
	}

	// Pull agent policies/capabilities and cache them locally in keyring
	if project.WorkspaceID != "" {
		agentSvc := agents.NewService(s.API)
		agentsList, err := agentSvc.ListAll(project.WorkspaceID)
		if err == nil && len(agentsList) > 0 {
			// Fetch capabilities concurrently
			type capResult struct {
				name string
				caps []byte
			}
			ch := make(chan capResult, len(agentsList))
			for _, a := range agentsList {
				go func(agent agents.Agent) {
					caps, err := agentSvc.GetCapabilities(project.WorkspaceID, agent.ID)
					if err == nil && caps != nil {
						capsBytes, err := json.Marshal(caps)
						if err == nil {
							ch <- capResult{name: agent.Name, caps: capsBytes}
							return
						}
					}
					ch <- capResult{name: agent.Name, caps: nil}
				}(a)
			}
			// Collect results and write to keyring
			for range agentsList {
				r := <-ch
				if r.caps != nil {
					_ = keyring.SetAgentCapabilities(r.name, r.caps)
				}
			}
		}
	}

	_ = s.UpdateEnvExampleFromLocal()
	return nil
}

// Push uploads all local secrets (.env or keychain) to the cloud.
func (s *Service) Push() error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("push secrets: no project configured in current directory")
	}

	var localSecrets map[string]string
	env := config.ResolveEnvironment()

	if config.GetStorageMode() == 1 {
		localSecrets, err = keyring.GetAllProjectSecrets(project.ProjectID, env)
	} else {
		localSecrets, err = s.Env.Read()
	}

	if err != nil {
		return err
	}

	telemetry.RecordSecretCount(len(localSecrets))

	if len(localSecrets) == 0 {
		return nil
	}

	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return fmt.Errorf("push secrets: %w", err)
	}

	apiSet := make(map[string]string)
	keychainFailures := 0
	for k, v := range localSecrets {
		encrypted, err := crypto.EncryptSecret(v, workspaceKey)
		if err != nil {
			return fmt.Errorf("push secrets: encryption failed for key %s: %w", k, err)
		}
		apiSet[k] = encrypted

		// 1. Sync to keychain (best-effort; cloud + .env remain the source of truth)
		if err := keyring.SetSecret(project.ProjectID, env, k, v); err != nil {
			keychainFailures++
		}
	}
	if keychainFailures > 0 {
		fmt.Fprintf(os.Stderr, "Warning: %d secret(s) could not be written to the OS keychain.\n", keychainFailures)
	}

	// 2. Sync to cloud (Bulk dictionary format)
	data := map[string]interface{}{
		"project_id":  project.ProjectID,
		"environment": env,
		"secrets":     apiSet,
	}

	if err := s.API.CallNoContent("secrets.create", "POST", data, nil, nil); err != nil {
		return fmt.Errorf("push secrets: API call failed: %w", err)
	}

	// Update project last_push timestamp
	project.LastPush = time.Now().Format(time.RFC3339)
	if err := config.SaveProjectConfig(project); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: push succeeded but failed to update last_push timestamp: %v\n", err)
	}

	_ = s.UpdateEnvExampleFromLocal()

	// Refresh cloud secrets cache
	_, _ = s.ListForEnv(env)

	return nil
}

// Delete removes a secret from cloud, .env, and Keychain.
func (s *Service) Delete(key string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("delete secret: no project configured in current directory")
	}

	// 1. Delete from API
	env := config.ResolveEnvironment()
	if err := s.API.CallNoContent("secrets.delete", "DELETE", nil, map[string]string{
		"project_id":  project.ProjectID,
		"environment": env,
		"key":         key,
	}, nil); err != nil {
		return fmt.Errorf("delete secret: API call failed: %w", err)
	}

	// 2. Delete from .env
	if err := s.Env.Delete(key); err != nil {
		return fmt.Errorf("delete secret: failed to update .env: %w", err)
	}

	// 3. Delete from Keychain
	_ = keyring.DeleteSecret(project.ProjectID, env, key)

	// Update local cache
	s.updateCacheAfterDelete(project.ProjectID, env, key)

	_ = s.UpdateEnvExampleFromLocal()
	return nil
}

// DiffResult holds the differences between local and cloud secrets.
type DiffResult struct {
	Added     []string             // Keys only in .env
	Removed   []string             // Keys only in Cloud
	Changed   map[string][2]string // Key -> [LocalVal, CloudVal]
	Unchanged []string
}

// DiffCached returns the differences using cached cloud secrets where possible.
func (s *Service) DiffCached(fromEnv, toEnv string) (*DiffResult, error) {
	return s.diffInternal(fromEnv, toEnv, true)
}

// Diff returns the differences between a source and a target, querying the cloud.
func (s *Service) Diff(fromEnv, toEnv string) (*DiffResult, error) {
	return s.diffInternal(fromEnv, toEnv, false)
}

func (s *Service) diffInternal(fromEnv, toEnv string, useCache bool) (*DiffResult, error) {
	var source map[string]string
	var target map[string]string
	var err error

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return nil, err
	}

	// 1. Resolve Source
	if fromEnv != "" {
		// Source is Cloud(fromEnv)
		var list []SecretMetadata
		var cacheErr error
		if useCache {
			project, err := config.LoadProjectConfig()
			if err == nil && project.ProjectID != "" {
				list, cacheErr = s.readCache(project.ProjectID, fromEnv)
			}
		}
		if list == nil || cacheErr != nil {
			list, err = s.ListForEnv(fromEnv)
			if err != nil {
				return nil, err
			}
		}
		source = make(map[string]string)
		for _, m := range list {
			if p, err := crypto.DecryptSecret(m.Value, wsKey); err == nil {
				source[m.Key] = p
			}
		}
	} else {
		// Source is Local
		if config.GetStorageMode() == 1 {
			project, _ := config.LoadProjectConfig()
			env := config.ResolveEnvironment()
			source, err = keyring.GetAllProjectSecrets(project.ProjectID, env)
		} else {
			source, err = s.Env.Read()
		}
		if err != nil {
			return nil, err
		}
	}

	// 2. Resolve Target
	targetEnv := toEnv
	if targetEnv == "" {
		targetEnv = config.ResolveEnvironment()
	}

	var list []SecretMetadata
	var cacheErr error
	if useCache {
		project, err := config.LoadProjectConfig()
		if err == nil && project.ProjectID != "" {
			list, cacheErr = s.readCache(project.ProjectID, targetEnv)
		}
	}
	if list == nil || cacheErr != nil {
		list, err = s.ListForEnv(targetEnv)
		if err != nil {
			return nil, err
		}
	}

	target = make(map[string]string)
	decryptFailures := 0
	for _, m := range list {
		p, err := crypto.DecryptSecret(m.Value, wsKey)
		if err != nil {
			if selKey, errSel := config.GetSelectedWorkspaceKey(); errSel == nil && selKey != nil && !bytes.Equal(selKey, wsKey) {
				if p2, err2 := crypto.DecryptSecret(m.Value, selKey); err2 == nil {
					p = p2
					err = nil
					wsKey = selKey
					if cfg, errCfg := config.LoadGlobalConfig(); errCfg == nil && cfg.SelectedWorkspaceID != "" {
						if proj, errP := config.LoadProjectConfig(); errP == nil {
							proj.WorkspaceID = cfg.SelectedWorkspaceID
							if ws, ok := cfg.Workspaces[cfg.SelectedWorkspaceID]; ok {
								proj.WorkspaceName = ws.Name
							}
							_ = config.SaveProjectConfig(proj)
						}
					}
				}
			}
		}
		if err == nil {
			target[m.Key] = p
		} else {
			decryptFailures++
		}
	}

	if len(list) > 0 && len(target) == 0 && decryptFailures > 0 {
		return nil, fmt.Errorf("found %d secret(s) in cloud, but decryption failed. The local project workspace key does not match the cloud encryption key", len(list))
	}

	// 3. Compare Source vs Target
	res := &DiffResult{
		Changed: make(map[string][2]string),
	}

	for k, v := range source {
		if targetVal, ok := target[k]; ok {
			if v != targetVal {
				res.Changed[k] = [2]string{v, targetVal}
			} else {
				res.Unchanged = append(res.Unchanged, k)
			}
			delete(target, k)
		} else {
			res.Added = append(res.Added, k)
		}
	}

	// Remaining keys in target are removed in source (relative to target)
	for k := range target {
		res.Removed = append(res.Removed, k)
	}

	return res, nil
}

func (s *Service) getCachePath(projectID, env string) (string, error) {
	paths, err := config.GetPaths()
	if err != nil {
		return "", err
	}
	return filepath.Join(paths.GlobalDir, fmt.Sprintf("cloud_cache_%s_%s.json", projectID, env)), nil
}

func (s *Service) readCache(projectID, env string) ([]SecretMetadata, error) {
	path, err := s.getCachePath(projectID, env)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var secrets []SecretMetadata
	if err := json.Unmarshal(data, &secrets); err != nil {
		return nil, err
	}
	if secrets == nil {
		return []SecretMetadata{}, nil
	}
	return secrets, nil
}

func (s *Service) writeCache(projectID, env string, secrets []SecretMetadata) error {
	path, err := s.getCachePath(projectID, env)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	data, err := json.Marshal(secrets)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

func (s *Service) updateCacheAfterSetWithEncrypted(projectID, env string, encryptedSecrets map[string]string) {
	secrets, err := s.readCache(projectID, env)
	if err != nil {
		secrets = []SecretMetadata{}
	}

	cacheMap := make(map[string]SecretMetadata, len(secrets)+len(encryptedSecrets))
	for _, sm := range secrets {
		cacheMap[sm.Key] = sm
	}

	nowStr := time.Now().Format(time.RFC3339)
	for k, enc := range encryptedSecrets {
		cacheMap[k] = SecretMetadata{
			Key:       k,
			Value:     enc,
			UpdatedAt: nowStr,
		}
	}

	var updated []SecretMetadata
	for _, sm := range cacheMap {
		updated = append(updated, sm)
	}
	_ = s.writeCache(projectID, env, updated)
}

func (s *Service) updateCacheAfterSet(projectID, env string, kv map[string]string) {
	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return
	}

	encryptedSecrets := make(map[string]string, len(kv))
	for k, v := range kv {
		encrypted, err := crypto.EncryptSecret(v, workspaceKey)
		if err != nil {
			continue
		}
		encryptedSecrets[k] = encrypted
	}
	s.updateCacheAfterSetWithEncrypted(projectID, env, encryptedSecrets)
}

func (s *Service) updateCacheAfterDelete(projectID, env, key string) {
	secrets, err := s.readCache(projectID, env)
	if err != nil {
		return
	}

	var updated []SecretMetadata
	for _, sm := range secrets {
		if sm.Key != key {
			updated = append(updated, sm)
		}
	}
	_ = s.writeCache(projectID, env, updated)
}

// UpdateEnvExampleFromLocal generates .env.example using locally cached key names.
// It reads from the keyring index in parallel, requiring zero API calls.
func (s *Service) UpdateEnvExampleFromLocal() error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return nil
	}

	environments := config.ValidEnvironments
	allKeys := make(map[string]bool)
	keyEnvs := make(map[string][]string)

	type envResult struct {
		env  string
		keys []string
		err  error
	}

	results := make([]envResult, len(environments))
	var wg sync.WaitGroup
	for i, env := range environments {
		wg.Add(1)
		go func(idx int, e string) {
			defer wg.Done()
			keys, err := keyring.ListProjectKeyNames(project.ProjectID, e)
			results[idx] = envResult{env: e, keys: keys, err: err}
		}(i, env)
	}
	wg.Wait()

	for _, res := range results {
		if res.err != nil {
			return res.err
		}
		for _, key := range res.keys {
			allKeys[key] = true
			keyEnvs[key] = append(keyEnvs[key], res.env)
		}
	}

	var lines []string
	lines = append(lines, "# AgentSecrets — generated by agentsecrets secrets pull")
	lines = append(lines, "# Keys marked [all] exist in all three environments")
	lines = append(lines, "# Environment-specific keys show which environments they belong to\n")

	for key := range allKeys {
		envs := keyEnvs[key]

		hasDev := false
		hasStg := false
		hasPrd := false

		for _, e := range envs {
			if e == "development" {
				hasDev = true
			}
			if e == "staging" {
				hasStg = true
			}
			if e == "production" {
				hasPrd = true
			}
		}

		allThree := hasDev && hasStg && hasPrd

		var annotation string
		if allThree {
			annotation = "[all]"
		} else {
			var segments []string
			if hasDev {
				segments = append(segments, "[development]")
			}
			if hasStg {
				segments = append(segments, "[staging]")
			}
			if hasPrd {
				segments = append(segments, "[production]")
			}
			annotation = strings.Join(segments, " ")
		}

		lines = append(lines, fmt.Sprintf("%-24s # %s", key+"=", annotation))
	}

	return s.Env.WriteEnvExample(strings.Join(lines, "\n") + "\n")
}
