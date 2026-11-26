// Package secrets orchestrates encrypted secret storage, retrieval, and synchronisation with the cloud API.
package secrets

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
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

// setSecretsBatch is the keychain write seam. Tests replace it to prove a
// keychain failure aborts the set; production always uses the real client.
var setSecretsBatch = keyring.SetSecretsBatch

// storeKeychainBatch writes one batch to the OS keychain and surfaces any
// failure. Callers treat that failure as fatal so a project never ends up with
// values in the cloud that env cannot read locally.
func storeKeychainBatch(projectID, environment string, kv map[string]string) error {
	if _, err := setSecretsBatch(projectID, environment, kv, nil); err != nil {
		return fmt.Errorf("batch set: could not write to the OS keychain: %w", err)
	}
	return nil
}

// restoreKeychainBatch is the compensating transition for a failed cloud write.
// It restores values captured before the keychain batch was written.
func restoreKeychainBatch(projectID, env string, keys map[string]string, previous map[string]string) {
	restore := make(map[string]string)
	for key := range keys {
		if value, ok := previous[key]; ok {
			restore[key] = value
			continue
		}
		_ = keyring.DeleteSecret(projectID, env, key)
	}
	if len(restore) > 0 {
		_, _ = setSecretsBatch(projectID, env, restore, nil)
	}
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
		encryptedValue, err := crypto.EncryptSecret(v, workspaceKey)
		if err != nil {
			return fmt.Errorf("batch set: encryption failed for %s: %w", k, err)
		}
		apiSecrets[k] = encryptedValue
	}

	// 2. Store in OS Keychain in a single batch IPC round-trip. This is fatal on
	// purpose. `agentsecrets env` in local mode reads the keychain and nothing
	// else, so a set the user will consume through env must land there. A
	// best-effort write left the cloud correct while env injected fewer secrets
	// than the project held, with one stderr line as the only clue.
	previous, _ := keyring.GetAllProjectSecrets(project.ProjectID, env)
	if err := storeKeychainBatch(project.ProjectID, env, kv); err != nil {
		return err
	}

	data := map[string]interface{}{
		"project_id":  project.ProjectID,
		"environment": env,
		"secrets":     apiSecrets,
	}

	if err := s.API.CallNoContent("secrets.create", "POST", data, nil, nil); err != nil {
		// The keychain was written first. Put the previous local values back so
		// a failed cloud write cannot leave local env resolution ahead of the
		// server. A key that did not exist locally is removed again.
		restoreKeychainBatch(project.ProjectID, env, kv, previous)
		return fmt.Errorf("batch set: API call failed: %w", err)
	}

	if err := s.Env.Write(kv); err != nil {
		return fmt.Errorf("batch set: failed to update .env: %w", err)
	}

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

	if val, err := keyring.GetSecret(project.ProjectID, env, key); err == nil {
		return val, nil
	}

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
	ID        string                     `json:"id,omitempty"`
	Key       string                     `json:"key"`
	Value     string                     `json:"value,omitempty"` // Encrypted value
	UpdatedAt string                     `json:"updated_at"`
	Policy    *capabilities.SecretPolicy `json:"policy,omitempty"` // Secret-level target constraints
}

// List returns all secret keys for the project in the active environment.
func (s *Service) List() ([]SecretMetadata, error) {
	return s.ListForEnv(config.ResolveEnvironment())
}

// ProjectEnvironment is one entry of the control plane's environment inventory.
type ProjectEnvironment = api.ProjectEnvironment

// RemoteEnvironments asks the control plane which environments this project
// actually holds. The local list can only see names this machine has touched, so
// a custom environment created on the dashboard would be invisible in the CLI
// without this call.
func (s *Service) RemoteEnvironments(projectID string) []string {
	if s.API == nil || projectID == "" {
		return nil
	}
	inventory, err := api.FetchProjectEnvironments(s.API, projectID)
	if err != nil {
		return nil
	}
	names := make([]string, 0, len(inventory))
	for _, env := range inventory {
		name, parseErr := config.ParseEnvironment(env.Name)
		if parseErr != nil {
			continue
		}
		names = append(names, name)
	}
	return names
}

// Environments returns every environment the project holds: the control plane's
// inventory when it is reachable, otherwise the names this machine knows about.
// A failed call returns the local list, because offline work must keep working.
func (s *Service) Environments(projectID, projectRoot string) ([]string, error) {
	if remote := s.RemoteEnvironments(projectID); len(remote) > 0 {
		return remote, nil
	}
	return config.LocalEnvironments(projectRoot)
}

// ListForEnv returns all secret keys for the project in the specified environment.
func (s *Service) ListForEnv(env string) ([]SecretMetadata, error) {
	projectID, _ := config.ResolveProjectContext()
	if projectID == "" {
		return nil, fmt.Errorf("list secrets: no project configured in current directory")
	}

	list, err := api.CallJSON[struct {
		Secrets       []SecretMetadata `json:"secrets"`
		WorkspaceID   string           `json:"workspace_id"`
		WorkspaceName string           `json:"workspace_name"`
	}](s.API, "secrets.list", "GET", nil, map[string]string{
		"project_id": projectID,
	}, map[string]string{
		"environment": env,
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets: %w", err)
	}

	// Auto-heal workspace if project was transferred
	if list.WorkspaceID != "" {
		if project, err := config.LoadProjectConfig(); err == nil && project != nil && list.WorkspaceID != project.WorkspaceID {
			project.WorkspaceID = list.WorkspaceID
			if list.WorkspaceName != "" {
				project.WorkspaceName = list.WorkspaceName
			}
			if err := config.SaveProjectConfig(project); err != nil {
				return nil, fmt.Errorf("secrets list: workspace transfer detected but the local binding could not be updated: %w", err)
			}
		}
	}

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
						if err := config.SaveProjectConfig(project); err != nil {
							return fmt.Errorf("pull: workspace key fallback succeeded but the local binding could not be updated: %w", err)
						}
					}
				}
			}
		}
		if err != nil {
			continue
		}
		secretsMap[s.Key] = plaintext

		if s.Policy != nil && (len(s.Policy.Domains) > 0 || len(s.Policy.Methods) > 0) {
			policyBytes, err := json.Marshal(s.Policy)
			if err == nil {
				policies[s.Key] = policyBytes
			}
		} else {
			policies[s.Key] = nil
		}
	}

	keychainFailures := 0
	if len(secretsMap) > 0 {
		if _, err := keyring.SetSecretsBatch(project.ProjectID, env, secretsMap, policies); err != nil {
			keychainFailures = len(secretsMap) // Conservative: assume all failed
		}
	}

	if keychainFailures > 0 {
		return fmt.Errorf("pull: %d secret/policy value(s) could not be written to the OS keychain; local env would resolve fewer secrets than the project holds", keychainFailures)
	}

	telemetry.RecordSecretCount(len(secretsMap))

	if err := s.Env.Write(secretsMap); err != nil {
		return fmt.Errorf("pull: failed to update local files: %w", err)
	}

	project.LastPull = time.Now().Format(time.RFC3339)
	if err := config.SaveProjectConfig(project); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: pull succeeded but failed to update last_pull timestamp: %v\n", err)
	}

	if project.WorkspaceID != "" {
		agentSvc := agents.NewService(s.API)
		agentsList, err := agentSvc.ListAll(project.WorkspaceID)
		if err == nil && len(agentsList) > 0 {
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
		return fmt.Errorf("push secrets: %d secret(s) could not be written to the OS keychain; local resolution would be incomplete", keychainFailures)
	}

	data := map[string]interface{}{
		"project_id":  project.ProjectID,
		"environment": env,
		"secrets":     apiSet,
	}

	if err := s.API.CallNoContent("secrets.create", "POST", data, nil, nil); err != nil {
		return fmt.Errorf("push secrets: API call failed: %w", err)
	}

	project.LastPush = time.Now().Format(time.RFC3339)
	if err := config.SaveProjectConfig(project); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: push succeeded but failed to update last_push timestamp: %v\n", err)
	}

	_ = s.UpdateEnvExampleFromLocal()

	_, _ = s.ListForEnv(env)

	return nil
}

// Delete removes a secret from cloud, .env, and Keychain.
func (s *Service) Delete(key string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("delete secret: no project configured in current directory")
	}

	env := config.ResolveEnvironment()
	if err := s.API.CallNoContent("secrets.delete", "DELETE", nil, map[string]string{
		"project_id":  project.ProjectID,
		"environment": env,
		"key":         key,
	}, nil); err != nil {
		return fmt.Errorf("delete secret: API call failed: %w", err)
	}

	if err := s.Env.Delete(key); err != nil {
		return fmt.Errorf("delete secret: failed to update .env: %w", err)
	}

	// 3. Delete from Keychain. A miss here leaves a stale local value that the
	// next push or pull can resurrect, so the user must hear about it.
	if err := keyring.DeleteSecret(project.ProjectID, env, key); err != nil {
		return fmt.Errorf("delete secret: removed from cloud and .env but the keychain still holds %s: %w", key, err)
	}

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

// Diff compares the source environment against the target. A blank fromEnv
// reads the keychain (storage mode 1) or the .env file (mode 2); every other
// source and target comes from the control plane. Nothing is read from a local
// cache: keychain-auth is the only local store.
func (s *Service) Diff(fromEnv, toEnv string) (*DiffResult, error) {
	var source map[string]string
	var target map[string]string
	var err error

	wsKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return nil, err
	}

	if fromEnv != "" {
		list, err := s.ListForEnv(fromEnv)
		if err != nil {
			return nil, err
		}
		source = make(map[string]string)
		for _, m := range list {
			if p, err := crypto.DecryptSecret(m.Value, wsKey); err == nil {
				source[m.Key] = p
			}
		}
	} else {
		if config.GetStorageMode() == 1 {
			projectID, _ := config.ResolveProjectContext()
			if projectID == "" {
				return nil, fmt.Errorf("diff secrets: no project configured in current directory")
			}
			env := config.ResolveEnvironment()
			source, err = keyring.GetAllProjectSecrets(projectID, env)
		} else {
			source, err = s.Env.Read()
		}
		if err != nil {
			return nil, err
		}
	}

	targetEnv := toEnv
	if targetEnv == "" {
		targetEnv = config.ResolveEnvironment()
	}

	list, err := s.ListForEnv(targetEnv)
	if err != nil {
		return nil, err
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

// UpdateEnvExampleFromLocal generates .env.example using keychain key names.
// It reads from the keyring index in parallel, requiring zero API calls.
func (s *Service) UpdateEnvExampleFromLocal() error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return nil
	}

	root, _ := config.GetProjectRoot()
	envs, err := s.Environments(project.ProjectID, root)
	if err != nil {
		return err
	}
	allKeys := make(map[string]bool)
	keyEnvs := make(map[string][]string)

	type envResult struct {
		env  string
		keys []string
		err  error
	}

	results := make([]envResult, len(envs))
	var wg sync.WaitGroup
	for i, env := range envs {
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
	lines = append(lines, "# Keys marked [all] exist in every environment")
	lines = append(lines, "# Environment-specific keys show which environments they belong to\n")

	for key := range allKeys {
		var annotation string
		if len(keyEnvs[key]) == len(envs) {
			annotation = "[all]"
		} else {
			segments := make([]string, 0, len(keyEnvs[key]))
			for _, e := range keyEnvs[key] {
				segments = append(segments, "["+e+"]")
			}
			annotation = strings.Join(segments, " ")
		}

		lines = append(lines, fmt.Sprintf("%-24s # %s", key+"=", annotation))
	}

	return s.Env.WriteEnvExample(strings.Join(lines, "\n") + "\n")
}
