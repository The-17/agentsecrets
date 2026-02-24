package secrets

import (
	"bufio"
	"fmt"
	"os"
	"regexp"
	"strings"
)

// EnvManager handles reading and writing .env files while preserving comments.
type EnvManager struct {
	EnvPath        string
	EnvExamplePath string
}

// NewEnvManager creates a manager for the current directory.
func NewEnvManager() *EnvManager {
	return &EnvManager{
		EnvPath:        ".env",
		EnvExamplePath: ".env.example",
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

// Write merges the provided secrets into .env and updates .env.example.
func (m *EnvManager) Write(newSecrets map[string]string) error {
	if err := m.updateFile(m.EnvPath, newSecrets, false); err != nil {
		return err
	}
	return m.updateFile(m.EnvExamplePath, newSecrets, true)
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
					// We need to preserve the comment if it exists
					comment := ""
					if idx := strings.Index(match[2], "#"); idx != -1 {
						comment = " " + strings.TrimSpace(match[2][idx:])
					}

					if keysOnly {
						lines = append(lines, fmt.Sprintf("%s=%s", key, comment))
					} else {
						// Quote if value has spaces or special chars
						formattedVal := val
						if strings.Contains(val, " ") || strings.Contains(val, "#") {
							formattedVal = fmt.Sprintf("\"%s\"", val)
						}
						lines = append(lines, fmt.Sprintf("%s=%s%s", key, formattedVal, comment))
					}
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
			if keysOnly {
				lines = append(lines, key+"=")
			} else {
				formattedVal := val
				if strings.Contains(val, " ") || strings.Contains(val, "#") {
					formattedVal = fmt.Sprintf("\"%s\"", val)
				}
				lines = append(lines, fmt.Sprintf("%s=%s", key, formattedVal))
			}
		}
	}

	// Write back to file
	content := strings.Join(lines, "\n")
	if len(lines) > 0 && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}
	
	return os.WriteFile(path, []byte(content), 0644)
}

// Delete removes a key from both files.
func (m *EnvManager) Delete(key string) error {
	if err := m.removeFromFile(m.EnvPath, key); err != nil {
		return err
	}
	return m.removeFromFile(m.EnvExamplePath, key)
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
		if len(match) > 1 && match[1] == keyToDelete {
			continue // Skip the line we want to delete
		}
		lines = append(lines, line)
	}

	content := strings.Join(lines, "\n")
	if len(lines) > 0 && !strings.HasSuffix(content, "\n") {
		content += "\n"
	}

	return os.WriteFile(path, []byte(content), 0644)
}
