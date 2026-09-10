package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/huh"
	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
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

var docsCmd = &cobra.Command{
	Use:   "docs [query]",
	Short: "Search and browse the official documentation",
	Long:  `Query the official AgentSecrets documentation directly from the CLI and read articles interactively.`,
	RunE:  runDocs,
}

func getDocsBaseURL() string {
	if envVal := os.Getenv("AGENTSECRETS_DOCS_URL"); envVal != "" {
		return strings.TrimSuffix(envVal, "/")
	}
	return "https://agentsecrets.tech"
}

func runDocs(cmd *cobra.Command, args []string) error {
	var query string
	if len(args) > 0 {
		query = strings.Join(args, " ")
	} else {
		// Prompt the user for a search query
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
	}

	query = strings.TrimSpace(query)
	if query == "" {
		ui.Info("No search query provided.")
		return nil
	}

	baseURL := getDocsBaseURL()
	searchURL := fmt.Sprintf("%s/api/search?q=%s", baseURL, url.QueryEscape(query))

	var searchResp searchResponse
	if err := ui.Spinner("Searching documentation...", func() error {
		resp, err := http.Get(searchURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			return fmt.Errorf("search API returned status %d", resp.StatusCode)
		}

		return json.NewDecoder(resp.Body).Decode(&searchResp)
	}); err != nil {
		ui.Error(fmt.Sprintf("Failed to search docs: %v", err))
		return nil
	}

	if len(searchResp.Results) == 0 {
		fmt.Printf("\n%s\n\n", ui.WarningStyle.Render("No matching documentation articles found."))
		return nil
	}

	// Prepare options for selection
	options := make([]huh.Option[string], len(searchResp.Results))
	for i, r := range searchResp.Results {
		snippet := r.Snippet
		if len(snippet) > 80 {
			snippet = snippet[:77] + "..."
		}
		// Render title with the group category
		label := fmt.Sprintf("%s (%s)\n  %s", ui.BrandStyle.Render(r.Title), ui.DimStyle.Render(r.Group), ui.LabelStyle.Render(snippet))
		options[i] = huh.NewOption(label, r.ID)
	}

	var selectedID string
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

	if selectedID == "" {
		return nil
	}

	// Fetch doc content
	var docContent string

	// Try the /api/docs endpoint first
	docURL := fmt.Sprintf("%s/api/docs?id=%s", baseURL, url.QueryEscape(selectedID))
	if err := ui.Spinner("Fetching article...", func() error {
		resp, err := http.Get(docURL)
		if err != nil {
			return err
		}
		defer resp.Body.Close()

		if resp.StatusCode == http.StatusOK {
			bodyBytes, err := io.ReadAll(resp.Body)
			if err == nil {
				docContent = string(bodyBytes)
				return nil
			}
		}
		return fmt.Errorf("status %d", resp.StatusCode)
	}); err == nil && docContent != "" {
		printDoc(docContent)
		return nil
	}

	// Fallback: Use llms-full.txt (downloading and caching locally)
	paths, err := config.GetPaths()
	if err != nil {
		ui.Error(fmt.Sprintf("Failed to resolve config paths: %v", err))
		return nil
	}
	cachePath := filepath.Join(paths.GlobalDir, "llms-full.txt")

	useCache := false
	if info, err := os.Stat(cachePath); err == nil {
		// Cache is valid if it's less than 24 hours old
		if time.Since(info.ModTime()) < 24*time.Hour {
			useCache = true
		}
	}

	if !useCache {
		if err := ui.Spinner("Updating documentation cache...", func() error {
			fullURL := fmt.Sprintf("%s/llms-full.txt", baseURL)
			resp, err := http.Get(fullURL)
			if err != nil {
				return err
			}
			defer resp.Body.Close()

			if resp.StatusCode != http.StatusOK {
				return fmt.Errorf("failed to download consolidated docs: status %d", resp.StatusCode)
			}

			out, err := os.OpenFile(cachePath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0600)
			if err != nil {
				return err
			}
			defer out.Close()

			_, err = io.Copy(out, resp.Body)
			return err
		}); err != nil {
			ui.Error(fmt.Sprintf("Failed to update cache: %v", err))
			return nil
		}
	}

	// Read from local cache and extract the document
	cacheBytes, err := os.ReadFile(cachePath)
	if err != nil {
		ui.Error(fmt.Sprintf("Failed to read documentation cache: %v", err))
		return nil
	}

	extracted, err := extractDocFromConsolidated(string(cacheBytes), selectedID)
	if err != nil {
		ui.Error(fmt.Sprintf("Failed to extract article content: %v", err))
		return nil
	}

	printDoc(extracted)
	return nil
}

func extractDocFromConsolidated(fullText, docID string) (string, error) {
	lines := strings.Split(fullText, "\n")
	var result []string
	found := false

	marker := fmt.Sprintf("(ID: %s)", docID)

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
