package ui

import "github.com/charmbracelet/huh/spinner"

// Spinner runs fn inside a spinner with the given title.
// Returns any error from fn, or from the spinner itself.
func Spinner(title string, fn func() error) error {
	var fnErr error
	if err := spinner.New().Title(title).Action(func() { fnErr = fn() }).Run(); err != nil {
		return err
	}
	return fnErr
}