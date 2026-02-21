package main

import (
	"os"

	"github.com/The-17/agentsecrets/cmd/agentsecrets/commands"
)

func main() {
	if err := commands.Execute(); err != nil {
		os.Exit(1)
	}
}
