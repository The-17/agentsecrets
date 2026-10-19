# Command Aliases & Shortcuts

> Fast, intuitive verb-noun shortcuts and dual-number nouns supported by AgentSecrets CLI.

## Verb-Noun Shortcuts

| Natural Shortcut | Canonical Command | Description |
| :--- | :--- | :--- |
| `agentsecrets list-secrets` | `agentsecrets secrets list` | List all secret keys for active project |
| `agentsecrets get-secret <KEY>` | `agentsecrets secrets get <KEY>` | Fetch a specific secret value |
| `agentsecrets set-secret <KEY=VAL>` | `agentsecrets secrets set <KEY=VAL>` | Store or update a secret value |
| `agentsecrets delete-secret <KEY>` | `agentsecrets secrets delete <KEY>` | Remove a secret |
| `agentsecrets pull-secrets` | `agentsecrets secrets pull` | Pull and decrypt secrets to local store |
| `agentsecrets push-secrets` | `agentsecrets secrets push` | Encrypt and push `.env` to server |
| `agentsecrets diff-secrets` | `agentsecrets secrets diff` | Compare local and server secrets |
| `agentsecrets create-project <NAME>` | `agentsecrets project create <NAME>` | Create and initialize a new project |
| `agentsecrets list-projects` | `agentsecrets project list` | List all projects in workspace |
| `agentsecrets use-project <NAME>` | `agentsecrets project use <NAME>` | Switch active project context |
| `agentsecrets switch-workspace <ID>` | `agentsecrets workspace switch <ID>` | Switch active workspace |
| `agentsecrets list-workspaces` | `agentsecrets workspace list` | List all accessible workspaces |
| `agentsecrets switch-env <NAME>` | `agentsecrets environment switch <NAME>`| Switch environment (dev/staging/prod) |
| `agentsecrets list-envs` | `agentsecrets environment list` | List all environment branches |
| `agentsecrets issue-token <AGENT>` | `agentsecrets agent issue-token <AGENT>`| Issue cryptographic agent token |
| `agentsecrets list-agents` | `agentsecrets agent list` | List registered AI agents |

For the complete cheatsheet and integration patterns, visit:
👉 **[Command Aliases & Shortcuts](https://docs.agentsecrets.tech/cli/aliases)**