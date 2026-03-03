// Package ui provides centralized styling and output helpers for the CLI.
//
// Uses charmbracelet/lipgloss for styled terminal output.
// All commands import this package for consistent branding.
package ui

import (
	"fmt"

	"github.com/charmbracelet/lipgloss"
	"github.com/charmbracelet/lipgloss/table"
)

// Brand colors
var (
	PrimaryColor = lipgloss.Color("#7DD3FC") // Sky Blue
	Secondary    = lipgloss.Color("#BAE6FD") // Light Sky Blue
	SuccessColor = lipgloss.Color("#34D399") // Emerald
	ErrorColor   = lipgloss.Color("#FB7185") // Rose
	WarningColor = lipgloss.Color("#FCD34D") // Soft Amber
	Dim          = lipgloss.Color("#71717A") // Zinc 500 (Clean grey)
	White        = lipgloss.Color("#F4F4F5") // Zinc 100
	DimText      = lipgloss.Color("#A1A1AA") // Zinc 400
	FaintBorder  = lipgloss.Color("#27272A") // Zinc 800 (Faint Border)
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
			Width(20)

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
		if row == 0 {
			style = style.Foreground(PrimaryColor).Bold(true)
		}
		return style
	})

	return t.Render()
}