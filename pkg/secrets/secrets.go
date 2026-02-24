package secrets

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/The-17/agentsecrets/pkg/api"
	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/crypto"
	"github.com/The-17/agentsecrets/pkg/keyring"
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
	return s.BatchSet(map[string]string{key: value})
}

// BatchSet adds or updates multiple secrets in a single API call.
func (s *Service) BatchSet(kv map[string]string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("batch set: no project configured in current directory")
	}

	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return fmt.Errorf("batch set: %w", err)
	}

	var apiSecrets []map[string]string
	for k, v := range kv {
		// 1. Encrypt for cloud
		encryptedValue, err := crypto.EncryptSecret(v, workspaceKey)
		if err != nil {
			return fmt.Errorf("batch set: encryption failed for %s: %w", k, err)
		}
		apiSecrets = append(apiSecrets, map[string]string{"key": k, "value": encryptedValue})

		// 2. Store in OS Keychain (for Proxy support)
		_ = keyring.SetSecret(project.ProjectID, k, v)
	}

	// 3. Sync to cloud
	data := map[string]interface{}{
		"project_id": project.ProjectID,
		"secrets":    apiSecrets,
	}

	resp, err := s.API.Call("secrets.create", "POST", data, nil)
	if err != nil {
		return fmt.Errorf("batch set: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	// 4. Write to .env
	if err := s.Env.Write(kv); err != nil {
		return fmt.Errorf("batch set: failed to update .env: %w", err)
	}

	return nil
}

// Get retrieves and decrypts a single secret.
func (s *Service) Get(key string) (string, error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return "", fmt.Errorf("get secret: no project configured in current directory")
	}

	// Try keychain first (fast paths)
	if val, err := keyring.GetSecret(project.ProjectID, key); err == nil {
		return val, nil
	}

	// Fallback to API
	resp, err := s.API.Call("secrets.get", "GET", nil, map[string]string{
		"project_id": project.ProjectID,
		"key":        key,
	})
	if err != nil {
		return "", fmt.Errorf("get secret: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", s.API.DecodeError(resp)
	}

	var res struct {
		Data struct {
			Value string `json:"value"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return "", fmt.Errorf("get secret: failed to parse response: %w", err)
	}

	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return "", fmt.Errorf("get secret: %w", err)
	}

	plaintext, err := crypto.DecryptSecret(res.Data.Value, workspaceKey)
	if err != nil {
		return "", fmt.Errorf("get secret: decryption failed: %w", err)
	}

	// Cache in keychain
	_ = keyring.SetSecret(project.ProjectID, key, plaintext)

	return plaintext, nil
}

// ListResponse holds the secret metadata from the API.
type SecretMetadata struct {
	Key       string `json:"key"`
	Value     string `json:"value,omitempty"` // Encrypted value
	UpdatedAt string `json:"updated_at"`
}

// List returns all secret keys for the project. If showValues is true, it decrypts them.
func (s *Service) List(showValues bool) ([]SecretMetadata, error) {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return nil, fmt.Errorf("list secrets: no project configured in current directory")
	}

	resp, err := s.API.Call("secrets.list", "GET", nil, map[string]string{
		"project_id": project.ProjectID,
	})
	if err != nil {
		return nil, fmt.Errorf("list secrets: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, s.API.DecodeError(resp)
	}

	var res struct {
		Data struct {
			Secrets []SecretMetadata `json:"secrets"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&res); err != nil {
		return nil, fmt.Errorf("list secrets: failed to parse response: %w", err)
	}

	if showValues {
		workspaceKey, err := config.GetProjectWorkspaceKey()
		if err != nil {
			return nil, fmt.Errorf("list secrets: %w", err)
		}

		for i := range res.Data.Secrets {
			plaintext, err := crypto.DecryptSecret(res.Data.Secrets[i].Value, workspaceKey)
			if err == nil {
				res.Data.Secrets[i].Value = plaintext
			}
		}
	}

	return res.Data.Secrets, nil
}

// Pull downloads secrets from the cloud and updates .env + Keychain.
// If targetKeys is nil, all secrets are pulled.
// If targetKeys is non-nil (even if empty), only those specific keys are pulled.
func (s *Service) Pull(targetKeys []string) error {
	isSelective := targetKeys != nil
	if isSelective && len(targetKeys) == 0 {
		return nil
	}

	secrets, err := s.List(true)
	if err != nil {
		return err
	} 

	filter := make(map[string]bool)
	for _, k := range targetKeys {
		filter[k] = true
	}

	project, _ := config.LoadProjectConfig()
	secretsMap := make(map[string]string)
	for _, s := range secrets {
		if isSelective && !filter[s.Key] {
			continue
		}
		secretsMap[s.Key] = s.Value
		// Sync to OS keychain (Proxy support)
		_ = keyring.SetSecret(project.ProjectID, s.Key, s.Value)
	}

	if isSelective && len(secretsMap) == 0 {
		return nil
	}

	if err := s.Env.Write(secretsMap); err != nil {
		return fmt.Errorf("pull: failed to write .env: %w", err)
	}

	// Update project last_pull timestamp
	project.LastPull = time.Now().Format(time.RFC3339)
	_ = config.SaveProjectConfig(project)

	return nil
}

// Push uploads all local .env secrets to the cloud.
func (s *Service) Push() error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("push secrets: no project configured in current directory")
	}

	localSecrets, err := s.Env.Read()
	if err != nil {
		return err
	}

	if len(localSecrets) == 0 {
		return nil
	}

	workspaceKey, err := config.GetProjectWorkspaceKey()
	if err != nil {
		return fmt.Errorf("push secrets: %w", err)
	}

	var apiSecrets []map[string]string
	for k, v := range localSecrets {
		encrypted, err := crypto.EncryptSecret(v, workspaceKey)
		if err != nil {
			return fmt.Errorf("push secrets: encryption failed for key %s: %w", k, err)
		}
		apiSecrets = append(apiSecrets, map[string]string{"key": k, "value": encrypted})
		// Sync to keychain
		_ = keyring.SetSecret(project.ProjectID, k, v)
	}

	data := map[string]interface{}{
		"project_id": project.ProjectID,
		"secrets":    apiSecrets,
	}

	resp, err := s.API.Call("secrets.create", "POST", data, nil)
	if err != nil {
		return fmt.Errorf("push secrets: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	// Update project last_push timestamp
	project.LastPush = time.Now().Format(time.RFC3339)
	_ = config.SaveProjectConfig(project)

	return nil
}

// Delete removes a secret from cloud, .env, and Keychain.
func (s *Service) Delete(key string) error {
	project, err := config.LoadProjectConfig()
	if err != nil || project.ProjectID == "" {
		return fmt.Errorf("delete secret: no project configured in current directory")
	}

	// 1. Delete from API
	resp, err := s.API.Call("secrets.delete", "DELETE", nil, map[string]string{
		"project_id": project.ProjectID,
		"key":        key,
	})
	if err != nil {
		return fmt.Errorf("delete secret: API call failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return s.API.DecodeError(resp)
	}

	// 2. Delete from .env
	if err := s.Env.Delete(key); err != nil {
		return fmt.Errorf("delete secret: failed to update .env: %w", err)
	}

	// 3. Delete from Keychain
	_ = keyring.DeleteSecret(project.ProjectID, key)

	return nil
}

// DiffResult holds the differences between local and cloud secrets.
type DiffResult struct {
	Added    []string            // Keys only in .env
	Removed  []string            // Keys only in Cloud
	Changed  map[string][2]string // Key -> [LocalVal, CloudVal]
	Unchanged []string
}

// Diff compares local .env secrets with cloud secrets.
func (s *Service) Diff() (*DiffResult, error) {
	local, err := s.Env.Read()
	if err != nil {
		return nil, err
	}

	cloud, err := s.List(true)
	if err != nil {
		return nil, err
	}

	res := &DiffResult{
		Changed: make(map[string][2]string),
	}

	cloudMap := make(map[string]string)
	for _, c := range cloud {
		cloudMap[c.Key] = c.Value
	}

	// Check local vs cloud
	for k, v := range local {
		if cloudVal, ok := cloudMap[k]; ok {
			if v != cloudVal {
				res.Changed[k] = [2]string{v, cloudVal}
			} else {
				res.Unchanged = append(res.Unchanged, k)
			}
			delete(cloudMap, k)
		} else {
			res.Added = append(res.Added, k)
		}
	}

	// Remaining keys in cloudMap are removed locally
	for k := range cloudMap {
		res.Removed = append(res.Removed, k)
	}

	return res, nil
}
