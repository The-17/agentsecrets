// Package keyring handles secure storage of cryptographic keys and secrets.
//
// All operations are delegated exclusively to the keychain-auth daemon client.
// Service name: "AgentSecrets"
// Keypair naming: "{email}_private_key", "{email}_public_key"
// Secret naming: "{projectID}:{environment}:{key}"
package keyring

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/The-17/agentsecrets/pkg/keychainauth"
)

const serviceName = "AgentSecrets"

// StoreKeypair saves both private and public keys.
func StoreKeypair(email string, privateKey, publicKey []byte) error {
	privB64 := base64.StdEncoding.EncodeToString(privateKey)
	pubB64 := base64.StdEncoding.EncodeToString(publicKey)

	if err := keychainauth.Write(serviceName, email+"_private_key", privB64); err != nil {
		return fmt.Errorf("failed to store private key: %w", err)
	}
	if err := keychainauth.Write(serviceName, email+"_public_key", pubB64); err != nil {
		return fmt.Errorf("failed to store public key: %w", err)
	}
	return nil
}

// GetPrivateKey retrieves the user's private key.
func GetPrivateKey(email string) ([]byte, error) {
	encoded, err := keychainauth.Read(serviceName, email+"_private_key")
	if err != nil {
		return nil, fmt.Errorf("private key not found in keychain: %w", err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// GetPublicKey retrieves the user's public key.
func GetPublicKey(email string) ([]byte, error) {
	encoded, err := keychainauth.Read(serviceName, email+"_public_key")
	if err != nil {
		return nil, fmt.Errorf("public key not found in keychain: %w", err)
	}
	return base64.StdEncoding.DecodeString(encoded)
}

// DeleteKeypair removes both keys (used during logout).
func DeleteKeypair(email string) error {
	_ = keychainauth.Delete(serviceName, email+"_private_key")
	_ = keychainauth.Delete(serviceName, email+"_public_key")
	return nil
}

// --- Individual Secret Storage (for Proxy support) ---

// SetSecret stores a decrypted secret in the keyring via keychain-auth.
func SetSecret(projectID, environment, key, value string) error {
	return keychainauth.SetSecret(projectID, environment, key, value)
}

// SetSecretsBatch stores multiple secrets and their policies in a single
// keychain-auth round-trip. See keychainauth.SetSecretsBatch.
func SetSecretsBatch(projectID, environment string, secrets map[string]string, policies map[string][]byte) (int, error) {
	return keychainauth.SetSecretsBatch(projectID, environment, secrets, policies)
}

// GetSecret retrieves a secret value directly from the OS keychain via keychain-auth.
func GetSecret(projectID, environment, key string) (string, error) {
	return keychainauth.GetSecret(projectID, environment, key)
}

// SecretExists checks whether a secret key exists locally without reading its value.
func SecretExists(projectID, environment, key string) (bool, error) {
	_, err := GetSecret(projectID, environment, key)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// DeleteSecret removes a secret from the keyring via keychain-auth.
func DeleteSecret(projectID, environment, key string) error {
	return keychainauth.DeleteSecret(projectID, environment, key)
}

// SetWorkspaceAllowlist stores the allowlist for a workspace in the OS keychain via keychain-auth.
func SetWorkspaceAllowlist(workspaceID string, domains []string) error {
	return keychainauth.SetWorkspaceAllowlist(workspaceID, domains)
}

// GetWorkspaceAllowlist retrieves the allowlist for a workspace from the OS keychain via keychain-auth.
func GetWorkspaceAllowlist(workspaceID string) ([]string, error) {
	return keychainauth.GetWorkspaceAllowlist(workspaceID)
}

// ListProjectKeyNames returns the key names for a given project and environment via keychain-auth.
func ListProjectKeyNames(projectID, environment string) ([]string, error) {
	return keychainauth.ListProjectKeyNames(projectID, environment)
}

// GetAllProjectSecrets returns all secrets mapped for a specific project and environment from the keyring via keychain-auth.
func GetAllProjectSecrets(projectID, environment string) (map[string]string, error) {
	return keychainauth.GetAllProjectSecrets(projectID, environment)
}

// SetSecretPolicy caches a secret's policy in the local keyring via keychain-auth.
func SetSecretPolicy(projectID, environment, key string, policy []byte) error {
	return keychainauth.SetSecretPolicy(projectID, environment, key, policy)
}

// GetSecretPolicy retrieves the cached policy for a secret via keychain-auth.
func GetSecretPolicy(projectID, environment, key string) ([]byte, error) {
	return keychainauth.GetSecretPolicy(projectID, environment, key)
}

// SetUserTokens stores the serialized user tokens in the OS keychain via keychain-auth.
func SetUserTokens(tokensJSON string) error {
	return keychainauth.Write(serviceName, "user_tokens", tokensJSON)
}

// GetUserTokens retrieves the serialized user tokens from the OS keychain via keychain-auth.
func GetUserTokens() (string, error) {
	return keychainauth.Read(serviceName, "user_tokens")
}

// DeleteUserTokens removes the user tokens from the OS keychain via keychain-auth.
func DeleteUserTokens() error {
	return keychainauth.Delete(serviceName, "user_tokens")
}

// SetAgentToken stores an agent token in the OS keychain via keychain-auth.
func SetAgentToken(agentName, token string) error {
	name := "agent_token_" + agentName
	return keychainauth.Write(serviceName, name, token)
}

// GetAgentToken retrieves an agent token from the OS keychain via keychain-auth.
func GetAgentToken(agentName string) (string, error) {
	name := "agent_token_" + agentName
	return keychainauth.Read(serviceName, name)
}

// DeleteAgentToken removes an agent token from the OS keychain via keychain-auth.
func DeleteAgentToken(agentName string) error {
	name := "agent_token_" + agentName
	return keychainauth.Delete(serviceName, name)
}

// agentProofSeedKey names the proof-of-possession seed by a fingerprint of the
// workload token rather than by the token itself: the token is the only identifier
// a resolver call has in hand, and storing the raw token as a key name would leak
// it into keychain listing/logs. SHA-256 is one-way, so the name reveals nothing.
func agentProofSeedKey(token string) string {
	sum := sha256.Sum256([]byte(token))
	return "agent_pop_seed_" + hex.EncodeToString(sum[:16])
}

// SetAgentProofSeed stores the base64 seed that proves possession of a workload
// token, keyed by the token's fingerprint. The CLI calls this at mint time so a
// later resolver call can find the key from the token alone.
func SetAgentProofSeed(token string, seed []byte) error {
	if strings.TrimSpace(token) == "" {
		return fmt.Errorf("cannot store proof seed without a token")
	}
	return keychainauth.Write(serviceName, agentProofSeedKey(token), base64.StdEncoding.EncodeToString(seed))
}

// GetAgentProofSeed returns the proof seed for a workload token, if one is stored.
// It implements pop's token-to-seed resolver.
func GetAgentProofSeed(token string) ([]byte, bool) {
	if strings.TrimSpace(token) == "" {
		return nil, false
	}
	raw, err := keychainauth.Read(serviceName, agentProofSeedKey(token))
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil, false
	}
	seed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(seed) == 0 {
		return nil, false
	}
	return seed, true
}

// SetAgentProofSeedByName stores the seed under the agent name as well, so a new
// token issued for an existing agent can inherit the same key (cnf_key lives on
// the agent, so every token for it is bound to the same public key).
func SetAgentProofSeedByName(agentName string, seed []byte) error {
	if strings.TrimSpace(agentName) == "" {
		return fmt.Errorf("cannot store proof seed without an agent name")
	}
	return keychainauth.Write(serviceName, "agent_pop_seed_name_"+agentName, base64.StdEncoding.EncodeToString(seed))
}

// GetAgentProofSeedByName returns the seed stored for an agent, if any.
func GetAgentProofSeedByName(agentName string) ([]byte, bool) {
	if strings.TrimSpace(agentName) == "" {
		return nil, false
	}
	raw, err := keychainauth.Read(serviceName, "agent_pop_seed_name_"+agentName)
	if err != nil || strings.TrimSpace(raw) == "" {
		return nil, false
	}
	seed, err := base64.StdEncoding.DecodeString(raw)
	if err != nil || len(seed) == 0 {
		return nil, false
	}
	return seed, true
}

// SetWorkspaceKey stores the base64-encoded workspace key in the OS keychain via keychain-auth.
func SetWorkspaceKey(workspaceID, keyB64 string) error {
	name := "workspace_key_" + workspaceID
	return keychainauth.Write(serviceName, name, keyB64)
}

// GetWorkspaceKey retrieves the base64-encoded workspace key from the OS keychain via keychain-auth.
func GetWorkspaceKey(workspaceID string) (string, error) {
	name := "workspace_key_" + workspaceID
	return keychainauth.Read(serviceName, name)
}

// DeleteWorkspaceKey removes a workspace key from the OS keychain via keychain-auth.
func DeleteWorkspaceKey(workspaceID string) error {
	name := "workspace_key_" + workspaceID
	return keychainauth.Delete(serviceName, name)
}

// SetProxySessionToken stores the local proxy session token securely via keychain-auth.
func SetProxySessionToken(token string) error {
	return keychainauth.Write(serviceName, "proxy_session_token", token)
}

// GetProxySessionToken retrieves the local proxy session token securely via keychain-auth.
func GetProxySessionToken() (string, error) {
	return keychainauth.Read(serviceName, "proxy_session_token")
}

// DeleteProxySessionToken deletes the local proxy session token via keychain-auth.
func DeleteProxySessionToken() error {
	return keychainauth.Delete(serviceName, "proxy_session_token")
}

// SetAgentCapabilities stores an agent's capabilities in the OS keychain via keychain-auth.
func SetAgentCapabilities(agentName string, caps []byte) error {
	name := "agent_capabilities_" + agentName
	return keychainauth.Write(serviceName, name, string(caps))
}

// GetAgentCapabilities retrieves an agent's capabilities from the OS keychain via keychain-auth.
func GetAgentCapabilities(agentName string) ([]byte, error) {
	name := "agent_capabilities_" + agentName
	val, err := keychainauth.Read(serviceName, name)
	if err != nil {
		return nil, err
	}
	return []byte(val), nil
}

// DeleteAgentCapabilities removes an agent's capabilities from the OS keychain via keychain-auth.
func DeleteAgentCapabilities(agentName string) error {
	name := "agent_capabilities_" + agentName
	return keychainauth.Delete(serviceName, name)
}

// FindAgentNameByToken searches the local keyring for an agent name corresponding to the token.
func FindAgentNameByToken(token string) (string, error) {
	keys, err := keychainauth.Search(serviceName, "agent_token_")
	if err != nil {
		return "", err
	}
	for _, k := range keys {
		t, err := keychainauth.Read(serviceName, k)
		if err == nil && t == token {
			return strings.TrimPrefix(k, "agent_token_"), nil
		}
	}
	return "", fmt.Errorf("agent token not found in local keyring")
}
