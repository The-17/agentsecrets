// Package ui provides centralized styling and output helpers for the CLI.
//
// Uses charmbracelet/lipgloss for styled terminal output.
// All commands import this package for consistent branding.
package ui

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"

	"github.com/The-17/agentsecrets/pkg/errors"
)

// CLIVersion is the version of the CLI tool, dynamically set on start.
var CLIVersion = "dev"

// Brand colors
var (
	PrimaryColor = lipgloss.Color("#00C6A5") // Brand Teal Accent
	Secondary    = lipgloss.Color("#5EEAD4") // Teal 300 — readable highlight
	SuccessColor = lipgloss.Color("#34D399") // Emerald
	ErrorColor   = lipgloss.Color("#F87171") // Red 400
	WarningColor = lipgloss.Color("#FBBF24") // Amber 400
	Dim          = lipgloss.Color("8")       // ANSI Dark Gray / Bright Black
	White        = lipgloss.Color("7")       // ANSI Light Gray / White
	DimText      = lipgloss.Color("244")     // 256-color palette medium gray
	FaintBorder  = lipgloss.Color("#1F2937") // Gray 800
)

// Reusable styles
var (
	BrandStyle = lipgloss.NewStyle().
			Foreground(PrimaryColor).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(SuccessColor).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(ErrorColor).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(WarningColor).
			Bold(true)

	DimStyle = lipgloss.NewStyle().
			Foreground(Dim)

	LabelStyle = lipgloss.NewStyle().
			Foreground(DimText)

	ValueStyle = lipgloss.NewStyle().
			Foreground(White).
			Bold(true)

	// Banner for init/welcome screens
	BannerStyle = lipgloss.NewStyle().
			Foreground(PrimaryColor).
			Bold(true).
			MarginBottom(1)

	// Status key-value pair styling
	KeyStyle = lipgloss.NewStyle().
			Foreground(DimText).
			Width(30)

	ValStyle = lipgloss.NewStyle().
			Foreground(White)

	// Divider
	DividerStyle = lipgloss.NewStyle().
			Foreground(Dim)
)

// Success prints a green success message with an asterisk.
func Success(msg string) {
	fmt.Println(SuccessStyle.Render("* " + msg))
}

// Error prints a red error message with an x.
func Error(msg string) {
	fmt.Println(ErrorStyle.Render("x " + msg))
}

// Warning prints a yellow warning message.
func Warning(msg string) {
	fmt.Println(WarningStyle.Render("! " + msg))
}

// Info prints a dimmed info message.
func Info(msg string) {
	fmt.Println(DimStyle.Render(msg))
}

// ErrorDetails defines structured error help text
type ErrorDetails struct {
	Title       string
	Description string
	Suggestions []string
	QuickAction string
}

// ErrorRegistry maps structured ErrorCodes to user remedies
var ErrorRegistry = map[errors.ErrorCode]ErrorDetails{
	errors.ErrSecretNotFound: {
		Title:       "Secret Not Found",
		Description: "The requested secret key does not exist in your active environment.",
		Suggestions: []string{
			"Verify the secret name is spelled correctly (keys are case-sensitive).",
			"Ensure you are working in the correct environment (run 'agentsecrets env switch').",
			"Sync your workspace by running 'agentsecrets secrets pull' or 'agentsecrets secrets push'.",
		},
		QuickAction: "agentsecrets secrets list",
	},
	errors.ErrAgentNotFound: {
		Title:       "Agent Not Found",
		Description: "The specified agent name does not exist in the active workspace.",
		Suggestions: []string{
			"Verify the agent name is spelled correctly.",
			"Check the registered agents list by running 'agentsecrets agent list'.",
			"If the agent is project-scoped, ensure your command runs inside the correct project directory.",
		},
		QuickAction: "agentsecrets agent list",
	},
	errors.ErrKeychainLocked: {
		Title:       "OS Keychain Locked",
		Description: "The native OS Keychain or Credential Manager is currently locked and unreachable.",
		Suggestions: []string{
			"Unlock your system keyring/credential manager via your desktop manager or password prompt.",
			"Restart the keychain daemon if it has hung.",
		},
	},
	errors.ErrKeychainHeadless: {
		Title:       "Headless Keyring Unconfigured",
		Description: "The native keychain cannot be initialized in a headless, non-desktop SSH environment.",
		Suggestions: []string{
			"Configure DBus or start a local gnome-keyring/kwallet daemon session.",
			"Unlock the keyring programmatically before running CLI commands.",
		},
	},
	errors.ErrUnauthorized: {
		Title:       "Session Expired / Unauthorized",
		Description: "Your local session token is invalid, revoked, or has expired.",
		Suggestions: []string{
			"Run 'agentsecrets login' to re-authenticate this machine.",
			"Check if your account has been deactivated in the workspace settings.",
		},
		QuickAction: "agentsecrets login",
	},
	errors.ErrInvalidCredentials: {
		Title:       "Invalid Credentials",
		Description: "The email or password you entered is incorrect.",
		Suggestions: []string{
			"Double check your email spelling and password.",
			"If you don't have an account, run 'agentsecrets init' to sign up.",
		},
	},
	errors.ErrForbidden: {
		Title:       "Permission Denied (Forbidden)",
		Description: "You do not have the required role or capabilities to perform this action.",
		Suggestions: []string{
			"Verify that your agent token or account has the required access policy set.",
			"Check your role assignment in this workspace: 'agentsecrets workspace members'.",
		},
	},
	errors.ErrServerInternal: {
		Title:       "Internal Server Error",
		Description: "The AgentSecrets Cloud service encountered an unexpected database or system failure.",
		Suggestions: []string{
			"Please wait a few moments and try your command again.",
			"Submit the copy-paste report below to engineering@theseventeen.co to help resolve this issue.",
		},
	},
	errors.ErrConnection: {
		Title:       "Connection Failed",
		Description: "Failed to connect to the remote AgentSecrets server.",
		Suggestions: []string{
			"Check your internet connection and DNS settings.",
			"Verify that your local security proxy, VPN, or firewall is not blocking outbound API calls.",
		},
	},
	errors.ErrConnectionTimeout: {
		Title:       "Request Timeout",
		Description: "The remote API call timed out before a response was received.",
		Suggestions: []string{
			"The API service or endpoint might be under heavy load. Retry in a few moments.",
			"Increase your local client connection timeout if running on a slow network.",
		},
	},
	errors.ErrPermissionDenied: {
		Title:       "OS Permission Denied",
		Description: "Operating system access permission was denied for a required configuration file or socket.",
		Suggestions: []string{
			"Check filesystem permissions for the ~/.agentsecrets directory.",
			"Ensure the active user process has read/write privileges on local state paths.",
		},
	},
	errors.ErrFileNotFound: {
		Title:       "Config File Missing",
		Description: "A required config, database, or socket path does not exist.",
		Suggestions: []string{
			"Run 'agentsecrets init' to regenerate missing workspace configurations.",
			"Check if your ~/.agentsecrets state directory has been deleted or moved.",
		},
		QuickAction: "agentsecrets init",
	},
	errors.ErrBinaryUnapproved: {
		Title:       "Binary Unapproved",
		Description: "keychain-auth has not authorized this AgentSecrets binary to read your secrets. This normally happens right after an upgrade, when the binary's signature changes.",
		Suggestions: []string{
			"Run 'agentsecrets doctor' to re-authorize this binary and restart the daemon automatically.",
		},
		QuickAction: "agentsecrets doctor",
	},
	errors.ErrLogNotFound: {
		Title:       "Log Entry Not Found",
		Description: "The requested log ID was not found in your local database.",
		Suggestions: []string{
			"Verify that you specified the actual Log ID (e.g. 'log_01J0A...'), not the list index number.",
			"Run 'agentsecrets logs' and enter the row index number interactively to view detailed forensic details.",
			"Export all logs in JSON format via 'agentsecrets logs export --since 24h --format jsonl' to find the correct Log ID.",
		},
	},
	errors.ErrUnknown: {
		Title:       "Unexpected Error",
		Description: "The command failed with an unhandled runtime error.",
		Suggestions: []string{
			"Check the error details above for troubleshooting clues.",
			"Submit a report to engineering@theseventeen.co.",
		},
	},
}

// ErrorWithSuggestions prints an error message and a bulleted list of helpful suggestions.
func ErrorWithSuggestions(err error, suggestions ...string) {
	if err == nil {
		return
	}

	// Identify Cobra CLI parsing and validation errors to avoid overwhelming on typos
	errStr := strings.ToLower(err.Error())
	isCobraError := strings.Contains(errStr, "unknown command") ||
		strings.Contains(errStr, "unknown flag") ||
		strings.Contains(errStr, "accepts ") ||
		strings.Contains(errStr, "invalid argument") ||
		strings.Contains(errStr, "flag needs an argument") ||
		strings.Contains(errStr, "required flag") ||
		strings.Contains(errStr, "missing argument") ||
		strings.Contains(errStr, "unknown shorthand flag")

	if isCobraError {
		fmt.Println(ErrorStyle.Render("x " + err.Error()))
		return
	}

	cliErr := errors.FromError(err)

	// Print primary error code and message
	fmt.Println(ErrorStyle.Render(fmt.Sprintf("x [%s] %s", cliErr.Code, cliErr.Message)))
	if cliErr.Err != nil && cliErr.Err.Error() != cliErr.Message {
		fmt.Println(DimStyle.Render(fmt.Sprintf("  Detail: %v", cliErr.Err)))
	}

	details, exists := ErrorRegistry[cliErr.Code]
	if !exists {
		details = ErrorRegistry[errors.ErrUnknown]
	}

	// Add dynamic suggestions if none are in the registry for unknown error
	allSuggestions := append([]string{}, suggestions...)
	allSuggestions = append(allSuggestions, details.Suggestions...)

	if len(allSuggestions) > 0 {
		fmt.Println()
		fmt.Println(DimStyle.Render(fmt.Sprintf("💡 Actionable suggestions to resolve this (%s):", details.Title)))
		if details.Description != "" {
			fmt.Println(DimStyle.Render(fmt.Sprintf("  %s", details.Description)))
			fmt.Println()
		}
		for _, s := range allSuggestions {
			fmt.Println(DimStyle.Render(fmt.Sprintf("  • %s", s)))
		}
		if details.QuickAction != "" {
			fmt.Println()
			fmt.Printf("  %s %s\n", LabelStyle.Render("Quick Run:"), ValueStyle.Render(details.QuickAction))
		}
	}

	// Only show the copy-paste report for internal server errors
	if cliErr.Code == errors.ErrServerInternal {
		cmdStr := scrubCmdArgs(os.Args)
		nowStr := time.Now().UTC().Format(time.RFC3339)
		fmt.Println()
		fmt.Println(DimStyle.Render("📋 Copy-paste report for engineering@theseventeen.co:"))
		fmt.Println(DimStyle.Render("--------------------------------------------------"))
		fmt.Printf("Command Run: %s\n", cmdStr)
		fmt.Printf("CLI Version: %s\n", CLIVersion)
		fmt.Printf("Timestamp:   %s\n", nowStr)
		fmt.Printf("Error Code:  %s\n", cliErr.Code)
		if cliErr.Err != nil {
			fmt.Printf("Error:       %s\n", cliErr.Err.Error())
		} else {
			fmt.Printf("Error:       %s\n", cliErr.Message)
		}
		fmt.Printf("Platform:    %s/%s\n", runtime.GOOS, runtime.GOARCH)
		fmt.Println(DimStyle.Render("--------------------------------------------------"))
		fmt.Println()
	}
}

func scrubCmdArgs(args []string) string {
	scrubbed := make([]string, len(args))
	copy(scrubbed, args)

	isSecretsSet := false
	for i, arg := range args {
		lower := strings.ToLower(arg)
		if lower == "set" && i > 0 && strings.ToLower(args[i-1]) == "secrets" {
			isSecretsSet = true
			break
		}
	}

	if isSecretsSet {
		for i, arg := range scrubbed {
			if strings.Contains(arg, "=") {
				parts := strings.SplitN(arg, "=", 2)
				scrubbed[i] = parts[0] + "=[REDACTED]"
			}
		}
	}

	return strings.Join(scrubbed, " ")
}

// SuccessWithSuggestions prints a success message and a list of next steps.
func SuccessWithSuggestions(msg string, nextSteps ...string) {
	fmt.Println(SuccessStyle.Render("* " + msg))
	if len(nextSteps) > 0 {
		fmt.Println()
		fmt.Println(BrandStyle.Render("➡️ Next steps you can take:"))
		for _, step := range nextSteps {
			fmt.Println(DimStyle.Render(fmt.Sprintf("  • %s", step)))
		}
		fmt.Println()
	}
}

// Brand prints text in the brand teal color.
func Brand(msg string) string {
	return BrandStyle.Render(msg)
}

// StatusRow prints a key-value pair for status output.
func StatusRow(key, value string) {
	fmt.Printf("  %s %s\n", KeyStyle.Render(key), ValStyle.Render(value))
}

// StatusRowDim prints a key-value pair with dimmed value.
func StatusRowDim(key, value string) {
	fmt.Printf("  %s %s\n", KeyStyle.Render(key), DimStyle.Render(value))
}

// Divider prints a styled horizontal line.
func Divider() {
	fmt.Println(DividerStyle.Render("  ──────────────────────────────"))
}

// Banner prints a styled banner heading.
func Banner(text string) {
	fmt.Println(BannerStyle.Render(text))
}

// BannerStr returns a styled banner heading as a string.
func BannerStr(text string) string {
	return BannerStyle.Render(text)
}

// RenderTable returns a styled table as a string.
func RenderTable(headers []string, rows [][]string) string {
	t := table.New().
		Border(lipgloss.RoundedBorder()).
		BorderStyle(lipgloss.NewStyle().Foreground(FaintBorder)).
		Headers(headers...).
		Rows(rows...)

	// Style headers and rows
	t.StyleFunc(func(row, col int) lipgloss.Style {
		style := lipgloss.NewStyle().Padding(0, 1).Align(lipgloss.Left)
		if row == table.HeaderRow {
			style = style.Foreground(PrimaryColor).Bold(true)
		}
		return style
	})

	return t.Render()
}
