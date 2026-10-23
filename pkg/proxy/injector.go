package proxy

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

// Inject applies a single credential injection to the outbound request.
// Dispatches to the appropriate injection function based on style.
func Inject(req *http.Request, cred string, inj Injection) error {
	switch inj.Style {
	case "bearer":
		return injectBearer(req, cred)
	case "basic":
		return injectBasic(req, cred)
	case "header":
		return injectHeader(req, cred, inj.Target)
	case "query":
		return injectQuery(req, cred, inj.Target)
	case "body":
		return injectBody(req, cred, inj.Target)
	case "form":
		return injectForm(req, cred, inj.Target)
	default:
		return fmt.Errorf("unknown auth style: %q — must be bearer, basic, header, query, body, or form", inj.Style)
	}
}

// InjectAll applies every injection to the outbound request in one pass.
//
// Header/query/bearer/basic styles are cheap per-injection. Body and form
// styles are the expensive ones: each call re-reads and re-marshals the whole
// body. When multiple body/form injections target the same request, doing them
// one-by-one via Inject() means N parses + N marshals and the intermediate
// bodies are thrown away. InjectAll groups them: it parses the raw body once,
// applies all body and form injections in memory, then serializes once.
//
// The caller's Content-Type is preserved when it is already set; only a
// missing one is defaulted based on the injection styles actually applied.
func InjectAll(req *http.Request, creds []string, injs []Injection) error {
	// Fast path: nothing body/form-related — behave exactly like per-injection.
	hasBodyStyle := false
	for _, inj := range injs {
		if inj.Style == "body" || inj.Style == "form" {
			hasBodyStyle = true
			break
		}
	}
	if !hasBodyStyle {
		for i, inj := range injs {
			if err := Inject(req, creds[i], inj); err != nil {
				return err
			}
		}
		return nil
	}

	// Snapshot the original body once. Subsequent per-injection reads must see
	// the same bytes, not whatever the previous injection wrote.
	var raw []byte
	if req.Body != nil {
		raw, _ = io.ReadAll(req.Body)
	}

	// Handle all body and form injections against an in-memory representation.
	var bodyMap map[string]interface{}
	var form url.Values
	contentType := strings.ToLower(req.Header.Get("Content-Type"))
	bodyDirty := false
	formDirty := false

	for i, inj := range injs {
		switch inj.Style {
		case "body":
			if bodyMap == nil {
				bodyMap = make(map[string]interface{})
				if len(raw) > 0 {
					if err := json.Unmarshal(raw, &bodyMap); err != nil {
						return fmt.Errorf("body is not valid JSON: %w", err)
					}
				}
			}
			if err := SetNested(bodyMap, inj.Target, creds[i]); err != nil {
				return err
			}
			bodyDirty = true
		case "form":
			if form == nil {
				form = make(url.Values)
				if len(raw) > 0 {
					parsed, err := url.ParseQuery(string(raw))
					if err != nil {
						return fmt.Errorf("body is not valid form data: %w", err)
					}
					form = parsed
				}
			}
			form.Set(inj.Target, creds[i])
			formDirty = true
		default:
			// Non-body styles apply directly to the request.
			if err := Inject(req, creds[i], inj); err != nil {
				return err
			}
		}
	}

	// Serialize each dirty representation exactly once.
	if bodyDirty {
		newBody, err := json.Marshal(bodyMap)
		if err != nil {
			return fmt.Errorf("failed to marshal body: %w", err)
		}
		req.Body = io.NopCloser(bytes.NewReader(newBody))
		req.ContentLength = int64(len(newBody))
		if contentType == "" {
			req.Header.Set("Content-Type", "application/json")
		}
	}
	if formDirty {
		encoded := form.Encode()
		req.Body = io.NopCloser(strings.NewReader(encoded))
		req.ContentLength = int64(len(encoded))
		if contentType == "" {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	}

	return nil
}

// SetNested sets value at a dot-separated path inside m, creating nested maps
// as needed (shared by InjectAll and injectBody). Exported so the cloud
// resolver's {{KEY}} body-handle builder applies the exact same path semantics
// as local injection: `--body-field a.b` must mean the same thing in both modes.
func SetNested(m map[string]interface{}, path, value string) error {
	parts := strings.Split(path, ".")
	current := m
	for i, part := range parts {
		if i == len(parts)-1 {
			current[part] = value
			return nil
		}
		next, ok := current[part]
		if !ok {
			next = make(map[string]interface{})
			current[part] = next
		}
		nested, ok := next.(map[string]interface{})
		if !ok {
			return fmt.Errorf("body path conflict: %q is not an object", part)
		}
		current = nested
	}
	return nil
}

// injectBearer sets Authorization: Bearer <token>.
func injectBearer(req *http.Request, token string) error {
	if token == "" {
		return fmt.Errorf("bearer token is empty")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	return nil
}

// injectBasic sets Authorization: Basic base64(username:password).
// The credential must be in "username:password" format.
func injectBasic(req *http.Request, credentials string) error {
	parts := strings.SplitN(credentials, ":", 2)
	if len(parts) != 2 {
		return fmt.Errorf("basic auth secret must be in format username:password")
	}
	encoded := base64.StdEncoding.EncodeToString([]byte(credentials))
	req.Header.Set("Authorization", "Basic "+encoded)
	return nil
}

// injectHeader sets a custom header: <headerName>: <value>.
func injectHeader(req *http.Request, value string, headerName string) error {
	if headerName == "" {
		return fmt.Errorf("header name is required for auth style \"header\"")
	}
	req.Header.Set(headerName, value)
	return nil
}

// injectQuery appends a query parameter: ?paramName=<value>.
func injectQuery(req *http.Request, value string, paramName string) error {
	if paramName == "" {
		return fmt.Errorf("query param name is required for auth style \"query\"")
	}
	q := req.URL.Query()
	q.Set(paramName, value)
	req.URL.RawQuery = q.Encode()
	return nil
}

// injectBody injects a value into a JSON request body at the given dot-separated path.
// For example, path "auth.key" sets {"auth": {"key": "<value>"}} in the body.
// If the body is empty, a new JSON object is created.
func injectBody(req *http.Request, value string, path string) error {
	if path == "" {
		return fmt.Errorf("body path is required for auth style \"body\"")
	}

	// Read existing body (may be empty)
	var bodyMap map[string]interface{}
	if req.Body != nil {
		existing, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		if len(existing) > 0 {
			if err := json.Unmarshal(existing, &bodyMap); err != nil {
				return fmt.Errorf("body is not valid JSON: %w", err)
			}
		}
	}
	if bodyMap == nil {
		bodyMap = make(map[string]interface{})
	}

	// Set value at nested path (e.g. "auth.key" → bodyMap["auth"]["key"])
	if err := SetNested(bodyMap, path, value); err != nil {
		return err
	}

	// Marshal back and replace body
	newBody, err := json.Marshal(bodyMap)
	if err != nil {
		return fmt.Errorf("failed to marshal body: %w", err)
	}
	req.Body = io.NopCloser(bytes.NewReader(newBody))
	req.ContentLength = int64(len(newBody))
	// Don't clobber a caller-set Content-Type; only default it when absent.
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/json")
	}
	return nil
}

// injectForm injects a value into a URL-encoded form body.
// If the body already has form data it is preserved; the new key is added/overwritten.
func injectForm(req *http.Request, value string, key string) error {
	if key == "" {
		return fmt.Errorf("form key is required for auth style \"form\"")
	}

	// Parse existing form body
	var form url.Values
	if req.Body != nil {
		existing, err := io.ReadAll(req.Body)
		if err != nil {
			return fmt.Errorf("failed to read request body: %w", err)
		}
		if len(existing) > 0 {
			form, err = url.ParseQuery(string(existing))
			if err != nil {
				return fmt.Errorf("body is not valid form data: %w", err)
			}
		}
	}
	if form == nil {
		form = make(url.Values)
	}

	form.Set(key, value)

	encoded := form.Encode()
	req.Body = io.NopCloser(strings.NewReader(encoded))
	req.ContentLength = int64(len(encoded))
	// Don't clobber a caller-set Content-Type; only default it when absent.
	if req.Header.Get("Content-Type") == "" {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	return nil
}
