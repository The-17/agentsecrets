// Package ui provides centralized styling and output helpers for the CLI.
//
// Uses charmbracelet/lipgloss for styled terminal output.
// All commands import this package for consistent branding.
package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
)

// Brand colors
var (
	Teal    = lipgloss.Color("#2DD4BF")
	Cyan    = lipgloss.Color("#22D3EE")
	Green   = lipgloss.Color("#4ADE80")
	Red     = lipgloss.Color("#F87171")
	Yellow  = lipgloss.Color("#FBBF24")
	Dim     = lipgloss.Color("#6B7280")
	White   = lipgloss.Color("#F9FAFB")
	DimText = lipgloss.Color("#9CA3AF")
)

// Reusable styles
var (
	BrandStyle = lipgloss.NewStyle().
			Foreground(Teal).
			Bold(true)

	SuccessStyle = lipgloss.NewStyle().
			Foreground(Green).
			Bold(true)

	ErrorStyle = lipgloss.NewStyle().
			Foreground(Red).
			Bold(true)

	WarningStyle = lipgloss.NewStyle().
			Foreground(Yellow).
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
			Foreground(Teal).
			Bold(true).
			MarginBottom(1)

	// Status key-value pair styling
	KeyStyle = lipgloss.NewStyle().
			Foreground(DimText).
			Width(14)

	ValStyle = lipgloss.NewStyle().
			Foreground(White)

	// Divider
	DividerStyle = lipgloss.NewStyle().
			Foreground(Dim)
)

// Success prints a green success message with a checkmark.
func Success(msg string) {
	fmt.Println(SuccessStyle.Render("✓ " + msg))
}

// Error prints a red error message with an X.
func Error(msg string) {
	fmt.Println(ErrorStyle.Render("✗ " + msg))
}

// Warning prints a yellow warning message.
func Warning(msg string) {
	fmt.Println(WarningStyle.Render("! " + msg))
}

// Info prints a dimmed info message.
func Info(msg string) {
	fmt.Println(DimStyle.Render(msg))
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
