package secrets

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/The-17/agentsecrets/pkg/config"
)

// EnvManager handles reading and writing .env files while preserving comments.
type EnvManager struct {
	EnvPath        string
	EnvExamplePath string
}

// NewEnvManager creates a manager for the current project using the resolved environment.
func NewEnvManager() *EnvManager {
	root, _ := config.GetProjectRoot()
	if root == "" {
		root = "."
	}

	env := config.ResolveEnvironment()
	// Map "development" to ".env" for backward compatibility if desired
	// We use .env for development as the primary default, but support others.
	filename := ".env"
	if env != "development" {
		filename = fmt.Sprintf(".env.%s", env)
	}

	return &EnvManager{
		EnvPath:        filepath.Join(root, filename),
		EnvExamplePath: filepath.Join(root, ".env.example"),
	}
}

// Regex to parse a .env line: optional whitespace, KEY, optional whitespace, =, optional whitespace, VALUE, optional inline comment
var envLineRegex = regexp.MustCompile(`^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*)$`)

// Read returns all secrets from the .env file as a map.
func (m *EnvManager) Read() (map[string]string, error) {
	file, err := os.Open(m.EnvPath)
	if err != nil {
		if os.IsNotExist(err) {
			return make(map[string]string), nil
		}
		return nil, fmt.Errorf("read .env: %w", err)
	}
	defer file.Close()

	secrets := make(map[string]string)
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		match := envLineRegex.FindStringSubmatch(line)
		if len(match) > 2 {
			key := match[1]
			value := match[2]

			// Handle inline comments and quoting
			value = m.parseValue(value)
			secrets[key] = value
		}
	}

	return secrets, scanner.Err()
}

// parseValue handles quotes and separates inline comments.
func (m *EnvManager) parseValue(val string) string {
	val = strings.TrimSpace(val)
	if val == "" {
		return ""
	}

	// If starting with a quote, find the closing quote
	if val[0] == '"' || val[0] == '\'' {
		quote := val[0]
		for i := 1; i < len(val); i++ {
			if val[i] == quote && val[i-1] != '\\' {
				return val[1:i]
			}
		}
	}

	// If not quoted, the first # starts a comment
	if idx := strings.Index(val, "#"); idx != -1 {
		return strings.TrimSpace(val[:idx])
	}

	return val
}

// EnsureEnvGitignore adds environment-specific .env files to the gitignore at
// the project root. It lives in the write path, not only in init, because a
// project can be created with `project create` while the global default is
// already mode 2. That route writes a plaintext .env with no gitignore entry.
func EnsureEnvGitignore(dir string) error {
	if dir == "" {
		dir = "."
	}
	path := filepath.Join(dir, ".gitignore")
	entries := []string{".env", ".env.development", ".env.staging", ".env.production"}

	existing := ""
	if data, err := os.ReadFile(path); err == nil {
		existing = string(data)
	}

	var toAdd []string
	for _, entry := range entries {
		found := false
		for _, line := range strings.Split(existing, "\n") {
			if strings.TrimSpace(line) == entry {
				found = true
				break
			}
		}
		if !found {
			toAdd = append(toAdd, entry)
		}
	}
	if len(toAdd) == 0 {
		return nil
	}

	content := existing
	if content != "" && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	content += "\n# AgentSecrets environment files\n" + strings.Join(toAdd, "\n") + "\n"
	return os.WriteFile(path, []byte(content), 0644)
}

// Write merges the provided secrets into the environment-specific .env file.
func (m *EnvManager) Write(newSecrets map[string]string) error {
	mode := config.GetStorageMode()
	if mode != 1 {
		root, _ := config.GetProjectRoot()
		if err := EnsureEnvGitignore(root); err != nil {
			return fmt.Errorf("failed to gitignore .env files: %w", err)
		}
		if err := m.updateFile(m.EnvPath, newSecrets, false); err != nil {
			return err
		}
	}
	return nil
}

// WriteEnvExample overwrites the .env.example file with the exact provided content.
func (m *EnvManager) WriteEnvExample(content string) error {
	return os.WriteFile(m.EnvExamplePath, []byte(content), 0644)
}

// updateFile reads the existing file, updates existing keys, and appends new ones.
func (m *EnvManager) updateFile(path string, newSecrets map[string]string, keysOnly bool) error {
	var lines []string
	existingKeys := make(map[string]bool)

	// Read existing file if it exists
	if _, err := os.Stat(path); err == nil {
		file, err := os.Open(path)
		if err != nil {
			return fmt.Errorf("update %s: %w", path, err)
		}
		defer file.Close()

		scanner := bufio.NewScanner(file)
		for scanner.Scan() {
			line := scanner.Text()

			// If it's a KEY=VALUE line, check if we need to update it
			match := envLineRegex.FindStringSubmatch(line)
			if len(match) > 2 {
				key := match[1]
				if val, ok := newSecrets[key]; ok {
					// Preserve comment if exists
					comment := ""
					if idx := strings.Index(match[2], "#"); idx != -1 {
						comment = " " + strings.TrimSpace(match[2][idx:])
					}

					formatted := ""
					if !keysOnly {
						formatted = formatValue(val)
					}
					lines = append(lines, fmt.Sprintf("%s=%s%s", key, formatted, comment))
					existingKeys[key] = true
					continue
				}
				existingKeys[key] = true
			}
			lines = append(lines, line)
		}
	}

	// Append any new secrets that weren't in the file
	for key, val := range newSecrets {
		if !existingKeys[key] {
			formatted := ""
			if !keysOnly {
				formatted = formatValue(val)
			}
			lines = append(lines, fmt.Sprintf("%s=%s", key, formatted))
		}
	}

	return writeLines(path, lines)
}

// Delete removes a key from the environment file.
func (m *EnvManager) Delete(key string) error {
	mode := config.GetStorageMode()
	if mode != 1 {
		if err := m.removeFromFile(m.EnvPath, key); err != nil {
			return err
		}
	}
	return nil
}

func (m *EnvManager) removeFromFile(path string, keyToDelete string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	}

	file, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("delete from %s: %w", path, err)
	}
	defer file.Close()

	var lines []string
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		match := envLineRegex.FindStringSubmatch(line)
		if len(match) <= 1 || match[1] != keyToDelete {
			lines = append(lines, line)
		}
	}

	return writeLines(path, lines)
}

// --- Helpers ---

func formatValue(val string) string {
	if strings.ContainsAny(val, " #") {
		return fmt.Sprintf("\"%s\"", val)
	}
	return val
}

func writeLines(path string, lines []string) error {
	content := strings.Join(lines, "\n")
	if len(lines) > 0 && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	// .env files hold plaintext secret values — keep them owner-readable only.
	return os.WriteFile(path, []byte(content), 0600)
}
