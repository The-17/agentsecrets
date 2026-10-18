# AgentSecrets MCP Bridge

> You are in `agentsecrets/integrations/mcp` — the TypeScript package published as `@the-17/agentsecrets-mcp`. It gives AI assistants secure, zero-knowledge access to your credentials over the Model Context Protocol.

## What is this?

AI assistants are useful with your APIs and dangerous with your API keys. Today people paste keys into chat, into MCP config files, into environment blocks — and from there keys leak into logs, transcripts, screenshots, and model context windows, where prompt injection can lift them.

This bridge flips that around. Your assistant gets 27 tools, and every one of them works on **key names, never key values**. When the assistant needs to call your Stripe API, it says "use `STRIPE_KEY`" — the value is injected outside the assistant's reach, and only the API's response comes back. There is deliberately no tool that returns a secret, and no tool that returns a token.

## Why it matters

- Keys stop living in chat transcripts, config files, and dotfiles repos.
- A compromised or tricked assistant cannot exfiltrate what it was never given.
- Every credentialed call is logged server-side under an identity you can audit and revoke.
- One install serves **all your projects** — scope resolves per call, not per install.

## How it works (the short version)

The bridge runs on your machine (or wherever your MCP client runs it) and picks one of two modes automatically:

- **Local mode** — the AgentSecrets CLI is installed. Every tool delegates to it, inheriting your OS-keychain session, proxy, and encryption keys. Zero setup, zero tokens anywhere.
- **Cloud mode** — no CLI. The bridge talks HTTPS directly: management through the AgentSecrets API, credentialed calls through the cloud resolver (which substitutes credentials server-side). You connect once via browser login or a token file.

A workload token (an agent identity, `agt_...`) carries its exact scope — workspace, project, environment — and the bridge refuses to mix scopes: if you ask about project A while holding project B's token, it fails loudly *before* spending quota, and every result tells you which scope acted.

## Get started in five minutes

**1. Install.** Add this to your MCP client config (Claude Desktop, Cursor, or any MCP client) and restart it. There are deliberately no credentials here:

```json
{
  "mcpServers": {
    "agentsecrets": {
      "command": "npx",
      "args": ["-y", "@the-17/agentsecrets-mcp@latest"]
    }
  }
}
```

**2. Check state.** Ask your assistant: *"Use agentsecrets auth_status."* It reports the mode, what's connected, and the exact next step.

**3. Connect.** If you have the CLI, you're already done. Otherwise ask for `auth_login`: open the URL it returns **yourself in a browser**, approve, then `auth_status` again. On machines without a browser, run `agentsecrets login` in a terminal, then `agentsecrets mcp bridge auth.export > ~/.agentsecrets/mcp-token && chmod 600 ~/.agentsecrets/mcp-token`, and point `AGENTSECRETS_TOKEN_FILE` at that path.

**4. Pin an identity (cloud mode).** Ask for `auth_use_identity`. It lists your agent identities, issues a scoped token for the bridge, and stores it directly — the value is never shown, not even to you in chat. Repeat once per workspace.

**5. Make a call.** *"Check my Stripe balance using STRIPE_KEY."* The assistant calls `proxy_call` with the key name; the value is injected outside its reach; you get the balance. Then `logs_summary` shows you the audit trail.

## The 27 tools

- **Credentialed calls** — `proxy_call` (call any HTTPS API by key name), `proxy_status` (what can serve calls right now)
- **Secrets** — `secrets_list/set/delete/pull/push/diff` (names and sync state; values never returned — `pull` writes your local `.env`, `set` encrypts before transit)
- **Projects & workspaces** — `project_list/create/use/update/delete`, `workspace_list/create/switch/members` (selecting here pins what later calls act on)
- **Agent identities** — `agent_list/delete/token_issue` (token metadata only; issued values go straight to secure storage, never displayed)
- **Audit** — `logs_list/summary/detail` (who called what, where, and whether it was allowed — the paper trail)
- **Auth** — `auth_status/login/logout/use_identity` (the guided setup above)

Destructive tools need `confirm: true` **and** your say-so in chat. There are no terminal prompts over MCP, so the human confirmation is the safety rail — never let an agent confirm for you.

## Running without the CLI (headless, CI, remote agents)

Cloud mode needs two things: an identity and a scope. Identity comes from OAuth login or a token file; scope comes from your project directory (`.agentsecrets/project.json` if the agent runs in a checkout), explicit `project`/`workspace` parameters, or pinned defaults. Writes and pulls additionally need your workspace data key (`AGENTSECRETS_WORKSPACE_KEY_FILE`) because encryption happens client-side — without it you'll get a clear error naming exactly what's missing, never a silent downgrade.

## Configuration reference

Everything the bridge reads from the environment. Nothing secret belongs in MCP client config — secrets live in 0600 files whose *paths* are config, or in environment the operator controls:

| Variable | Purpose |
|---|---|
| `AGENTSECRETS_MCP_MODE` | `auto` (default) \| `local` \| `cloud` |
| `AGENTSECRETS_USE_CLOUD` | `true` forces cloud mode |
| `AGENTSECRETS_BINARY` | Explicit CLI path for local mode |
| `AGENTSECRETS_TOKEN` / `AGENTSECRETS_TOKEN_FILE` | Your login (management) or workload token |
| `AS_AGENT_TOKEN` / `AGENTSECRETS_AGENT_TOKEN` (+`_FILE`) | Workload token = agent identity |
| `AGENTSECRETS_AGENT_ID` | Display name for audit attribution |
| `AGENTSECRETS_SESSION_TOKEN` | Local proxy session (only without the CLI) |
| `AGENTSECRETS_CLOUD_RESOLVER_URL` | Cloud resolver base (has a sane default) |
| `AGENTSECRETS_SERVER_URL` / `AGENTSECRETS_API_URL` | Control-plane base, e.g. self-hosted |
| `AGENTSECRETS_PROJECT` / `AGENTSECRETS_WORKSPACE` | Session context hints (names) |
| `AGENTSECRETS_ENV` | `development` \| `staging` \| `production` |
| `AGENTSECRETS_PROXY_PORT` / `AGENTSECRETS_PORT` | Local proxy port hint |
| `AGENTSECRETS_WORKSPACE_KEY` (+`_FILE`) | Base64 data key for headless encrypt/decrypt |
| `AGENTSECRETS_EMAIL` | Login email (workspace creation) |
| `AGENTSECRETS_HOME` | Override home dir (tests, containers) |

Credential lookup order, by design: explicit env → login sessions → legacy CLI session → static files last. Run `auth_status` anytime to see exactly which source is active.

## Security model, honestly stated

The guarantee boundary is the **tool boundary**: no secret or token value ever appears in tool input (except the one `secrets_set` write, which is encrypted before transit) or output. Issued tokens go straight from the API into 0600 storage without being displayed — not even to you in chat.

What files do and don't buy you: a 0600 file keeps secrets out of synced configs, screenshots, repos, and other OS users' hands. It does *not* hide them from your own shell-capable agent — nothing file-based can, since that agent could equally run the CLI directly. Against a compromised agent, your defenses are: it never receives values (tool boundary), tokens are short-lived and narrowly scoped, mismatched scopes fail closed, and everything is auditable and revocable (`auth_logout` revokes bridge tokens). Prefer local mode wherever a machine boundary exists — then credentials never leave the OS keychain at all.

## Telemetry

Each tool call adds usage counts (tool name, error category, secret counts on pull/push) to the CLI's own `~/.agentsecrets/telemetry.json`, which the CLI syncs roughly daily. No emails, IDs, URLs, key names, values, or tokens are recorded by the bridge, and it makes no network calls for telemetry.

## Develop

Requires Node 20+. Dependencies: `@modelcontextprotocol/server` (v2), `zod` (v4), `tweetnacl` (sealed-box for workspace creation).

```bash
npm ci
npm run typecheck   # strict tsc, no emit
npm test            # builds + runs 80+ tests including a live stdio wire test
npm run build       # dist/ output
```
