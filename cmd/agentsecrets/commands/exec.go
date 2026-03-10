package commands

import (
	"encoding/json"
	"fmt"
	"io"
	"os"

	"github.com/spf13/cobra"

	"github.com/The-17/agentsecrets/pkg/config"
	"github.com/The-17/agentsecrets/pkg/keyring"
)

type ExecRequest struct {
	ProtocolVersion int      `json:"protocolVersion"`
	Provider        string   `json:"provider"`
	IDs             []string `json:"ids"`
}

type ExecSecretError struct {
	Message string `json:"message"`
}

type ExecResponse struct {
	ProtocolVersion int                        `json:"protocolVersion"`
	Values          map[string]string          `json:"values"`
	Errors          map[string]ExecSecretError `json:"errors,omitempty"`
}

func NewExecCmd() *cobra.Command {
	return &cobra.Command{
		Use:           "exec",
		Short:         "Resolve secrets for OpenClaw exec provider (reads JSON from stdin, writes JSON to stdout)",
		SilenceUsage:  true,
		SilenceErrors: true,
		Run:           runExec,
	}
}

func runExec(cmd *cobra.Command, args []string) {
	input, err := io.ReadAll(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to read stdin: %v\n", err)
		os.Exit(1)
	}

	if len(input) == 0 {
		fmt.Fprintln(os.Stderr, "empty stdin")
		os.Exit(1)
	}

	var req ExecRequest
	if err := json.Unmarshal(input, &req); err != nil {
		fmt.Fprintf(os.Stderr, "invalid JSON: %v\n", err)
		os.Exit(1)
	}

	if req.ProtocolVersion != 1 {
		fmt.Fprintf(os.Stderr, "unsupported protocol version: %d\n", req.ProtocolVersion)
		os.Exit(1)
	}

	resp := ExecResponse{
		ProtocolVersion: 1,
		Values:          make(map[string]string),
	}

	if len(req.IDs) == 0 {
		out, _ := json.Marshal(resp)
		fmt.Println(string(out))
		os.Exit(0)
	}

	project, err := config.LoadProjectConfig()
	if err != nil || project == nil || project.ProjectID == "" {
		// Fall back to globally selected project (set by `agentsecrets project use`)
		globalProjectID := config.GetSelectedProjectID()
		if globalProjectID == "" {
			fmt.Fprintln(os.Stderr, "no project configured in current directory")
			os.Exit(1)
		}
		project = &config.ProjectConfig{ProjectID: globalProjectID}
	}

	for _, id := range req.IDs {
		val, err := keyring.GetSecret(project.ProjectID, id)
		if err != nil || val == "" {
			if resp.Errors == nil {
				resp.Errors = make(map[string]ExecSecretError)
			}
			msg := "secret not found in keychain"
			if err != nil {
				msg = err.Error()
			}
			resp.Errors[id] = ExecSecretError{Message: msg}
		} else {
			resp.Values[id] = val
		}
	}

	out, err := json.Marshal(resp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to serialize response: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(out))
	os.Exit(0)
}

