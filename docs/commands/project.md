# `agentsecrets project`

The `project` command handles configuring the immediate working directory so it behaves cohesively with an exact remote AgentSecrets environment.

## `project list`
Iterates across the remote API to display all initialized projects spanning your currently active `workspace`. Outputs project names, descriptions, and linked environments inside a structured terminal table.

## `project create [name] [description]`
Attempts to bootstrap a new environment configuration on the cloud.
- Automatically links the new project mapping to whatever `SelectedWorkspaceID` maps inside the global cache.
- The command natively invokes `InitProjectConfig()` if successful, actively writing an `./.agentsecrets/project.json` containing the newly acquired `project_id`.

## `project use [project_id]` or `project link [project_id]`
These two mutually interchangeable commands instruct the CLI to forcefully map an existing cloud directory down to the local file system.
- If multiple developers are working on `Staging DB`, one creates the project and subsequent developers run `agentsecrets project link {proj_id}` to inherit the namespace.
- Generates the authoritative `./.agentsecrets/project.json` linking file required by `secrets pull`.

## `project update [name]`
Updates the `name` or `description` of an existing project natively configured inside the ecosystem.
- Provides interactive prompts to input the new name or summary using the CLI via `charmbracelet/huh`.
- Leaves original fields unchanged if input arguments are entirely blank during prompt invocation.

## `project invite [email]`
Instructs the active server to invite a new developer into a project container by associating an encrypted `workspace_key` mapping. 
- Automatically identifies if the acting Workspace is labeled as `personal`.
- If migrating from `personal`, the API constructs an on-the-fly `shared` workspace and completely re-encrypts all underlying project secrets securely using the new user's `public_key`.
- Inherits specific permission subsets (`admin` vs `member`).

## `project delete [name]`
Fully tears down an existing project framework across the entire backend index, preventing further interaction from all historically authorized developers. 
- Safely severs local filesystem ties if the deleted project matched the actively routed project embedded inside `./.agentsecrets/project.json`.
- Requires an explicit dual-confirmation prompt to mitigate accidental destruction.
