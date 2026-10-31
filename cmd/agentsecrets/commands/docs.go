package commands

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/errors"
	"github.com/The-17/agentsecrets/pkg/ui"
)

type searchResult struct {
	ID      string  `json:"id"`
	URL     string  `json:"url"`
	Title   string  `json:"title"`
	Group   string  `json:"group"`
	Label   string  `json:"label"`
	Snippet string  `json:"snippet"`
	Score   float64 `json:"score"`
}

type searchResponse struct {
	Query   string         `json:"query"`
	Results []searchResult `json:"results"`
}

// docEntry is one article in the documentation index (llms.txt).
type docEntry struct {
	ID    string `json:"id"`
	Title string `json:"title"`
	URL   string `json:"url"`
}

// docContent is the machine-readable form of a single fetched article.
type docContent struct {
	ID      string `json:"id"`
	Content string `json:"content"`
}

var (
	docsJSON       bool
	docsList       bool
	docsID         string
	docsLimit      int
	docsSearchOnly bool
)

// docsHTTPClient bounds every docs request so an agent can never hang on a
// stalled network call.
var docsHTTPClient = &http.Client{Timeout: 15 * time.Second}

var docsCmd = &cobra.Command{
	Use:   "docs [query]",
	Short: "Search and read the official documentation",
	Long: `Search and read the official AgentSecrets documentation.

Agent / script usage (no TTY required, structured output):
  agentsecrets docs "domain allowlist" --json        # ranked results as JSON
  agentsecrets docs "domain allowlist" --search-only  # ranked results as text
  agentsecrets docs --id proxy/overview               # raw markdown for one article
  agentsecrets docs --id proxy/overview --json        # {"id":...,"content":...}
  agentsecrets docs --list --json                     # every article (id,title,url)

Human usage (interactive terminal):
  agentsecrets docs proxy                             # picker + reader`,
	RunE: runDocs,
}

func init() {
	docsCmd.Flags().BoolVar(&docsJSON, "json", false, "output machine-readable JSON")
	docsCmd.Flags().BoolVar(&docsList, "list", false, "list every documentation article")
	docsCmd.Flags().StringVar(&docsID, "id", "", "fetch one article by id, URL, or /docs/ path")
	docsCmd.Flags().IntVar(&docsLimit, "limit", 10, "maximum search results to return (0 = all)")
	docsCmd.Flags().BoolVar(&docsSearchOnly, "search-only", false, "print search results without fetching an article")
}

func getDocsBaseURL() string {
	if envVal := os.Getenv("AGENTSECRETS_DOCS_URL"); envVal != "" {
		return strings.TrimSuffix(envVal, "/")
	}
	return "https://docs.agentsecrets.tech"
}

func runDocs(cmd *cobra.Command, args []string) error {
	interactive := term.IsTerminal(int(os.Stdin.Fd()))
	// Decorations (spinners, dividers, styled warnings) only make sense on a
	// real terminal and when we are not emitting machine JSON.
	decorated := interactive && term.IsTerminal(int(os.Stdout.Fd())) && !docsJSON

	baseURL := getDocsBaseURL()

	// --- List mode: enumerate every article ---
	if docsList {
		entries, err := fetchDocIndex(baseURL)
		if err != nil {
			return err
		}
		if docsJSON {
			return json.NewEncoder(os.Stdout).Encode(entries)
		}
		for _, e := range entries {
			fmt.Printf("%s\t%s\n", e.ID, e.Title)
		}
		return nil
	}

	// --- Fetch-by-id mode: read a single article ---
	if docsID != "" {
		if len(args) > 0 {
			return errors.WithSuggestions(errors.ErrUsage,
				"--id cannot be combined with a search query", nil,
				"agentsecrets docs --id proxy/overview")
		}
		content, err := fetchDocContent(baseURL, docsID)
		if err != nil {
			return err
		}
		if docsJSON {
			return json.NewEncoder(os.Stdout).Encode(docContent{ID: normalizeDocID(docsID), Content: content})
		}
		fmt.Println(strings.TrimSpace(content))
		return nil
	}

	// --- Search mode ---
	query := strings.TrimSpace(strings.Join(args, " "))
	if query == "" {
		if !interactive {
			return errors.WithSuggestions(errors.ErrUsage,
				"docs needs a search query (or --id / --list) when no terminal is attached", nil,
				`agentsecrets docs "installation" --json`,
				"agentsecrets docs --list --json")
		}
		form := huh.NewForm(
			huh.NewGroup(
				huh.NewInput().
					Title("Search Docs").
					Placeholder("e.g. installation, proxy, mcp").
					Value(&query),
			),
		)
		if err := form.Run(); err != nil {
			return err
		}
		query = strings.TrimSpace(query)
		if query == "" {
			ui.Info("No search query provided.")
			return nil
		}
	}

	searchResp, err := searchDocs(baseURL, query, decorated)
	if err != nil {
		return err
	}
	results := searchResp.Results
	if docsLimit > 0 && len(results) > docsLimit {
		results = results[:docsLimit]
	}
	searchResp.Results = results

	if len(results) == 0 {
		if docsJSON {
			return json.NewEncoder(os.Stdout).Encode(searchResp)
		}
		fmt.Printf("\n%s\n\n", ui.WarningStyle.Render("No matching documentation articles found."))
		return nil
	}

	// Machine / non-interactive search output stops at the ranked list.
	if docsJSON || docsSearchOnly {
		if docsJSON {
			return json.NewEncoder(os.Stdout).Encode(searchResp)
		}
		printSearchResults(results)
		return nil
	}

	var selectedID string
	if !interactive {
		printSearchResults(results)
		selectedID = results[0].ID
	} else {
		options := make([]huh.Option[string], len(results))
		for i, r := range results {
			snippet := r.Snippet
			if len(snippet) > 80 {
				snippet = snippet[:77] + "..."
			}
			label := fmt.Sprintf("%s (%s)\n  %s", ui.BrandStyle.Render(r.Title), ui.DimStyle.Render(r.Group), ui.LabelStyle.Render(snippet))
			options[i] = huh.NewOption(label, r.ID)
		}

		form := huh.NewForm(
			huh.NewGroup(
				huh.NewSelect[string]().
					Title("Select an article to read").
					Options(options...).
					Value(&selectedID),
			),
		)
		if err := form.Run(); err != nil {
			return err
		}
	}

	if selectedID == "" {
		return nil
	}

	content, err := fetchDocContent(baseURL, selectedID)
	if err != nil {
		return err
	}
	if decorated {
		printDoc(content)
	} else {
		fmt.Println(strings.TrimSpace(content))
	}
	return nil
}

// searchDocs queries /api/search and decodes the JSON result. It returns a
// non-nil error on any network or HTTP failure so callers exit non-zero.
func searchDocs(baseURL, query string, decorated bool) (*searchResponse, error) {
	searchURL := fmt.Sprintf("%s/api/search?q=%s", baseURL, url.QueryEscape(query))
	var out *searchResponse

	run := func() error {
		req, err := http.NewRequest(http.MethodGet, searchURL, nil)
		if err != nil {
			return err
		}
		req.Header.Set("Accept", "application/json")
		resp, err := docsHTTPClient.Do(req)
		if err != nil {
			return err
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("search API returned status %d", resp.StatusCode)
		}
		var s searchResponse
		if err := json.NewDecoder(resp.Body).Decode(&s); err != nil {
			return err
		}
		out = &s
		return nil
	}

	var err error
	if decorated {
		err = ui.Spinner("Searching documentation...", run)
	} else {
		err = run()
	}
	if err != nil {
		return nil, errors.New(errors.ErrConnection, "failed to search docs: "+err.Error(), err)
	}
	return out, nil
}

// fetchDocContent fetches a single article's markdown. It accepts a bare id, a
// search-result id (path::anchor), a URL, or a /docs/ path. Falls back to the
// consolidated llms-full.txt cache when the API is unavailable.
func fetchDocContent(baseURL, id string) (string, error) {
	normalized := normalizeDocID(id)
	docURL := fmt.Sprintf("%s/api/docs?id=%s", baseURL, url.QueryEscape(normalized))

	req, err := http.NewRequest(http.MethodGet, docURL, nil)
	if err != nil {
		return "", err
	}
	resp, err := docsHTTPClient.Do(req)
	if err != nil {
		return "", errors.New(errors.ErrConnection, "failed to fetch article: "+err.Error(), err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusOK {
		b, err := io.ReadAll(resp.Body)
		if err != nil {
			return "", errors.New(errors.ErrConnection, "failed to read article: "+err.Error(), err)
		}
		return string(b), nil
	}

	// API did not serve the article; try the consolidated cache before failing.
	if cached, cerr := fetchDocFromCache(baseURL, normalized); cerr == nil && cached != "" {
		return cached, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return "", errors.New(errors.ErrDocNotFound, fmt.Sprintf("document %q not found", normalized), nil)
	}
	return "", errors.New(errors.ErrConnection, fmt.Sprintf("docs API returned status %d", resp.StatusCode), nil)
}

// fetchDocFromCache extracts an article from the cached llms-full.txt,
// refreshing the cache when it is missing or older than 24 hours.
func fetchDocFromCache(baseURL, id string) (string, error) {
	paths, err := config.GetPaths()
	if err != nil {
		return "", err
	}
	cachePath := filepath.Join(paths.GlobalDir, "llms-full.txt")

	if info, statErr := os.Stat(cachePath); statErr == nil && time.Since(info.ModTime()) < 24*time.Hour {
		if b, readErr := os.ReadFile(cachePath); readErr == nil {
			if doc, exErr := extractDocFromConsolidated(string(b), id); exErr == nil {
				return doc, nil
			}
		}
	}

	resp, err := docsHTTPClient.Get(fmt.Sprintf("%s/llms-full.txt", baseURL))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("consolidated docs returned status %d", resp.StatusCode)
	}
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	_ = os.MkdirAll(filepath.Dir(cachePath), 0700)
	_ = os.WriteFile(cachePath, b, 0600)
	return extractDocFromConsolidated(string(b), id)
}

var docsLinkRe = regexp.MustCompile(`^\s*-\s*\[(.+?)\]\((.+?)\)`)

// fetchDocIndex parses llms.txt into a stable list of {id,title,url}.
func fetchDocIndex(baseURL string) ([]docEntry, error) {
	resp, err := docsHTTPClient.Get(fmt.Sprintf("%s/llms.txt", baseURL))
	if err != nil {
		return nil, errors.New(errors.ErrConnection, "failed to fetch docs index: "+err.Error(), err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, errors.New(errors.ErrConnection, fmt.Sprintf("docs index returned status %d", resp.StatusCode), nil)
	}

	var entries []docEntry
	sc := bufio.NewScanner(resp.Body)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		m := docsLinkRe.FindStringSubmatch(sc.Text())
		if m == nil {
			continue
		}
		title, link := m[1], m[2]
		id := normalizeDocID(link)
		if id == "" {
			id = slugify(title)
		}
		entries = append(entries, docEntry{ID: id, Title: title, URL: link})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return entries, nil
}

// normalizeDocID turns a URL, a /docs/ path, or a bare id into the id the
// /api/docs endpoint expects. URL fragments (#anchor) become the ::anchor form
// that search results already use.
func normalizeDocID(s string) string {
	s = strings.TrimSpace(s)
	if i := strings.Index(s, "/docs/"); i >= 0 {
		s = s[i+len("/docs/"):]
	} else {
		s = strings.TrimPrefix(s, "docs/")
	}
	if i := strings.Index(s, "#"); i >= 0 {
		s = s[:i] + "::" + s[i+1:]
	}
	return strings.TrimSuffix(s, "/")
}

// slugify lowercases and dash-joins a title, for index entries whose URL is the
// docs root and therefore has no id path.
func slugify(s string) string {
	var b strings.Builder
	prevDash := false
	for _, r := range strings.ToLower(s) {
		switch {
		case (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9'):
			b.WriteRune(r)
			prevDash = false
		default:
			if !prevDash && b.Len() > 0 {
				b.WriteByte('-')
				prevDash = true
			}
		}
	}
	return strings.Trim(b.String(), "-")
}

func printSearchResults(results []searchResult) {
	fmt.Printf("%d match(es):\n", len(results))
	for i, r := range results {
		fmt.Printf("%2d. %s\n    id:  %s\n    url: %s\n", i+1, r.Title, r.ID, r.URL)
	}
	fmt.Println()
}

func extractDocFromConsolidated(fullText, docID string) (string, error) {
	lines := strings.Split(fullText, "\n")
	var result []string
	found := false

	// Anchored ids (path::anchor) map to the base document in the consolidated
	// file, which only carries one header per document.
	baseID := strings.SplitN(docID, "::", 2)[0]
	marker := fmt.Sprintf("(ID: %s)", baseID)

	for _, line := range lines {
		if strings.HasPrefix(line, "# DOCUMENT:") {
			if found {
				// We reached the start of the next document, stop extracting
				break
			}
			if strings.Contains(line, marker) {
				found = true
				continue // Skip the header line itself
			}
		}

		if found {
			result = append(result, line)
		}
	}

	if !found {
		return "", fmt.Errorf("document ID %q not found in consolidated file", docID)
	}

	return strings.Join(result, "\n"), nil
}

func printDoc(markdown string) {
	fmt.Println()
	ui.Divider()
	fmt.Println(strings.TrimSpace(markdown))
	ui.Divider()
	fmt.Println()
}
