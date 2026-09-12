package commands

import (
	"net/url"
	"regexp"
	"strings"

	"github.com/The-17/agentsecrets/pkg/keyring"
)

// filterSecrets backs `--only`: it returns just the named secrets and the names
// that were not present. Whitespace around names is ignored.
func filterSecrets(secrets map[string]string, only []string) (map[string]string, []string) {
	filtered := make(map[string]string, len(only))
	var missing []string
	for _, k := range only {
		k = strings.TrimSpace(k)
		if k == "" {
			continue
		}
		if v, ok := secrets[k]; ok {
			filtered[k] = v
		} else {
			missing = append(missing, k)
		}
	}
	return filtered, missing
}

// unallowlistedHosts returns the hosts not covered by the workspace allowlist. If
// the allowlist cannot be read we return nil rather than nag: this is advisory
// guidance, never enforcement.
func unallowlistedHosts(workspaceID string, hosts []string) []string {
	if len(hosts) == 0 {
		return nil
	}
	allow, err := keyring.GetWorkspaceAllowlist(workspaceID)
	if err != nil {
		return nil
	}
	var missing []string
	for _, h := range hosts {
		if !hostAllowed(h, allow) {
			missing = append(missing, h)
		}
	}
	return missing
}

// hostsFromSecrets extracts candidate network hosts from secret values. It exists
// to show the user which destinations their credentials imply, so they can add
// them to the workspace allowlist in one command — it never stores or logs a
// secret value, only the hostname it names.
//
// Only the hostname is returned: from a URL/URI (scheme://user:pass@host:port/db),
// from a bare host or host:port value, and from key=host forms common in
// connection strings.
func hostsFromSecrets(secrets map[string]string) []string {
	seen := map[string]bool{}
	var hosts []string
	add := func(h string) {
		h = normalizeHost(h)
		if h == "" || !looksLikeHost(h) || seen[h] {
			return
		}
		seen[h] = true
		hosts = append(hosts, h)
	}

	for _, v := range secrets {
		v = strings.TrimSpace(v)
		if v == "" {
			continue
		}
		// Full URL / connection string: postgres://user:pass@db.internal:5432/app
		if strings.Contains(v, "://") {
			if u, err := url.Parse(v); err == nil {
				add(u.Hostname())
			}
			continue
		}
		// Host embedded in a larger value: "host=db.internal", "Server=db.internal;"
		for _, m := range embeddedHostRe.FindAllStringSubmatch(v, -1) {
			add(m[1])
		}
		// Bare host or host:port: value is only the endpoint.
		if isBareEndpoint(v) {
			add(stripPort(v))
		}
	}
	return hosts
}

var (
	// host=name, host: name, Server=name — common in connection-string syntaxes.
	embeddedHostRe = regexp.MustCompile(`(?i)(?:host|server|endpoint|address|hostname)\s*[=:]\s*([A-Za-z0-9._-]+)`)
	// A value that is only an endpoint: host[:port] with no spaces or path.
	bareEndpointRe = regexp.MustCompile(`^[A-Za-z0-9._-]+(?::\d{1,5})?$`)
)

func isBareEndpoint(v string) bool {
	return !strings.ContainsAny(v, " \t\r\n/\\") && bareEndpointRe.MatchString(v)
}

func stripPort(v string) string {
	if i := strings.LastIndexByte(v, ':'); i > 0 {
		return v[:i]
	}
	return v
}

func normalizeHost(h string) string {
	h = strings.ToLower(strings.TrimSpace(h))
	h = strings.Trim(h, "[]")
	return h
}

// looksLikeHost filters out values that are clearly not hostnames (bare words,
// credentials, base64 blobs). A host must contain a dot, be an IP, or be localhost.
func looksLikeHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	if h == "localhost" {
		return true
	}
	if strings.ContainsAny(h, " \t/\\@") {
		return false
	}
	return strings.Contains(h, ".")
}

// hostAllowed reports whether host is covered by the allowlist, honouring
// wildcard entries such as "*.example.com" and ".example.com".
func hostAllowed(host string, allow []string) bool {
	host = normalizeHost(host)
	for _, a := range allow {
		a = normalizeHost(a)
		switch {
		case a == "":
			continue
		case a == host:
			return true
		case strings.HasPrefix(a, "*.") && strings.HasSuffix(host, a[1:]):
			return true
		case strings.HasPrefix(a, ".") && strings.HasSuffix(host, a):
			return true
		}
	}
	return false
}
