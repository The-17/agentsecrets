# `agentsecrets workspace`

Workspaces encompass organizations or teams. They manage the highest structural boundary of isolated projects and define explicit Access Control Lists (ACL) among members.

## `workspace list` (or `ls`)
Lists all workspaces accessible by the authenticated user.
- Prints the CLI cache representing the decrypted keys held in `~/.agentsecrets/config.json`.
- Neatly outputs the Workspace ID, logical Name, and ownership Type (`personal` or `shared`). Uniquely flags your currently active workspace with an arrow `→`.

## `workspace switch [name]`
Sets the default target workspace for subsequent `project` generation and viewing commands.
- If run without an argument, it launches a `huh` interactive picker displaying all accessible workspaces.
- If run with `[name]`, it immediately forces the context to switch to the exact workspace matching the string.
- Modifies the authoritative `SelectedWorkspaceID` root target within the global `config.json`. 

## `workspace create [name]`
Provisions a new shared collaborative environment boundary using your connected account.
- The CLI invokes the API to generate the workspace, then automatically rotates your `SelectedWorkspaceID` to the new space immediately so any subsequent `project create` maps into it.

## `workspace members`
Retrieves a live list of the Access Control List (ACL) connected to your currently selected workspace scope.
- Evaluates against the remote API and outputs every connected Email, their Status (e.g. `active`, `pending`), and their Role (`owner`, `admin`, `member`) within a visually styled table.

## `workspace invite [email]`
Instructs the central server to generate a secure invitation allocating the target `email` access to your current workspace keys.
- Operates interactively if no arguments are provided, otherwise prompts the user for the structural ACL Role (`Admin` or `Member`) to apply. 
- *Note: You must have Admin or Owner permissions on the selected workspace to execute this.*

## `workspace remove [email]`
Forces the excision of a previously linked structural member email from your current workspace.
- The command explicitly mandates a confirmation `Yes/No` prompt to prevent accidental permission destruction.
