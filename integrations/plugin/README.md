# AgentSecrets plugin

Zero-knowledge credential tool for framework-native agent harnesses.

One tool, `agentsecrets_call`, proxies an HTTP request using secret **key
names**. The model never sees a secret value, and the tool never returns one.
Values stay in the AgentSecrets keychain (local mode) or in the resolver
(cloud mode).

This package is a harness plugin, not a VS Code extension, browser extension,
or a replacement for the AgentSecrets MCP server.

## Install

Python:

```bash
pip install agentsecrets-plugin
pip install "agentsecrets-plugin[langchain]"
pip install "agentsecrets-plugin[crewai]"
pip install "agentsecrets-plugin[autogen]"
pip install "agentsecrets-plugin[llamaindex]"
```

TypeScript:

```bash
npm install @the-17/agentsecrets-plugin
```

Local mode also needs the `agentsecrets` CLI on `PATH`. Cloud mode needs a
workload token.

## The one tool

```json
{
  "name": "agentsecrets_call",
  "parameters": {
    "url": "https://api.stripe.com/v1/customers",
    "method": "GET",
    "injections": { "bearer": "STRIPE_SECRET_KEY" },
    "headers": { "Accept": "application/json" },
    "environment": "development"
  }
}
```

`injections` maps an injection spec to a key **name**:

| Spec | Result |
|---|---|
| `bearer` | `Authorization: Bearer <value>` |
| `basic` | `Authorization: Basic <base64(value)>` (local only) |
| `header:X-Api-Key` | `X-Api-Key: <value>` |
| `query:api_key` | `?api_key=<value>` (local only) |
| `body:auth.token` | JSON path set to `<value>` |
| `form:api_key` | form field set to `<value>` |

`environment` is optional. It asserts `development`, `staging`, or
`production`. Cloud mode sends it in `scope.environment`. Local mode compares
it with the helper's active environment before the call. The result reports
the asserted environment.

## Python

```python
from agentsecrets_plugin import AgentSecretsClient

client = AgentSecretsClient()  # local if the CLI is installed, else cloud if a token exists
result = client.call(
    {
        "url": "https://api.example.com/v1/things",
        "injections": {"bearer": "EXAMPLE_API_KEY"},
        "method": "GET",
    }
)
print(result.status_code, result.body)
```

`client.tool_call(args)` returns the same result as a compact JSON string,
ready for a framework tool handler.

### LangChain

```python
from agentsecrets_plugin import AgentSecretsClient
from agentsecrets_plugin.langchain import make_tool

client = AgentSecretsClient()
tool = make_tool(client)
```

### CrewAI

```python
from agentsecrets_plugin import AgentSecretsClient
from agentsecrets_plugin.crewai import make_tool

tool = make_tool(AgentSecretsClient())
```

### AutoGen

```python
from agentsecrets_plugin import AgentSecretsClient
from agentsecrets_plugin.autogen import make_tool

tool = make_tool(AgentSecretsClient())
```

### LlamaIndex

```python
from agentsecrets_plugin import AgentSecretsClient
from agentsecrets_plugin.llamaindex import make_tool

tool = make_tool(AgentSecretsClient())
```

The framework modules import their framework lazily. Installing the core
package does not install LangChain, CrewAI, AutoGen, or LlamaIndex.

## TypeScript

```ts
import { AgentSecretsClient } from "@the-17/agentsecrets-plugin";

const client = new AgentSecretsClient();
const result = await client.call({
  url: "https://api.example.com/v1/things",
  injections: { bearer: "EXAMPLE_API_KEY" },
});
console.log(result.status_code, result.body);
```

### OpenAI function calling

```ts
import { AgentSecretsClient, openAIHandler, openAITool } from "@the-17/agentsecrets-plugin";

const client = new AgentSecretsClient();
const tools = [openAITool()];
const handleToolCall = openAIHandler(client);

const output = await handleToolCall({
  url: "https://api.example.com/v1/things",
  injections: { bearer: "EXAMPLE_API_KEY" },
});
```

### dsh / Cordis

```ts
import { apply } from "@the-17/agentsecrets-plugin/dsh";

export { apply };
```

`apply(ctx)` registers `agentsecrets_call` with a structural `ctx.tool` and
returns the client. The adapter does not depend on a Cordis runtime.

## Modes

The plugin picks a mode in this order:

1. `AGENTSECRETS_PLUGIN_MODE=local` or `cloud`, if set.
2. `local` when the `agentsecrets` binary is found.
3. `cloud` when a workload token is found.
4. Otherwise it raises a configuration error.

Local mode delegates to:

```bash
agentsecrets mcp proxy.call
```

with JSON on stdin. The plugin never reads the keychain, the session token, or
a `.env` file.

Cloud mode sends one request to:

```text
POST https://resolver.agentsecrets.tech/v1/resolve
Authorization: Bearer <workload token>
```

The body carries `{{KEY}}` handles. Cloud mode rejects `basic` and `query`
because the resolver contract cannot encode them. Use local mode for those.

| Variable | Purpose |
|---|---|
| `AGENTSECRETS_PLUGIN_MODE` | `local` or `cloud` |
| `AGENTSECRETS_BINARY` | Path to the CLI |
| `AGENTSECRETS_ENV` | Active environment passed to the helper |
| `AGENTSECRETS_PROXY_PORT` | Local proxy port passed to the helper |
| `AGENTSECRETS_TOKEN` | Cloud workload token |
| `AGENTSECRETS_TOKEN_FILE` | File containing the cloud token; preferred |
| `AGENTSECRETS_CLOUD_RESOLVER_URL` | Resolver base URL override |

## Security model

- **Key names only.** The tool schema and both transports accept key names,
  not values. `secrets set KEY=VALUE` is a CLI compatibility path, not a
  plugin path.
- **Values never cross back.** The plugin returns the upstream status,
  headers, and body. It does not resolve, cache, log, or echo a secret value.
  An upstream API can still echo a credential in its response; that is the
  upstream's behavior, not the plugin's.
- **The helper child gets an allowlist.** The plugin does not forward the
  parent environment. It passes the CLI configuration, keychain basics,
  locale, temp, TLS, and proxy variables. It strips `AGENTSECRETS_TOKEN`,
  `AGENTSECRETS_TOKEN_FILE`, `AGENTSECRETS_USE_CLOUD`,
  `AGENTSECRETS_SESSION_TOKEN`, the plugin's own mode variables, provider keys,
  and unrelated values.
- **Prefer `AGENTSECRETS_TOKEN_FILE`.** Environment variables are visible to
  child processes, crash dumps, and same-user inspection. The plugin never
  includes a token in an error or log line.
- **Cloud is HTTPS-only.** Local mode can call an HTTP target, which is useful
  for a local fake upstream during tests.

### Environment assertion

Local mode reads `environment.active` from `agentsecrets mcp status`
before the call and caches it for 60 seconds. A mismatch fails before the
proxy call. This is a best-effort check: a long-running daemon resolves its
own environment at start, and 3.3.x does not expose the daemon's environment.
Start the daemon from the environment you intend to use, or omit `environment`
when you do not need the assertion.

## Not in V1

- No `agentsecrets env` tool. The CLI's child-process plaintext injection stays
  a developer command. There is no developer-only runner in this package.
- No per-call environment selection. `environment` asserts; it does not switch.
- No OAuth, project management, or metadata tools.
- No Semantic Kernel adapter.
- No direct HTTP proxy path. The plugin uses the CLI helper so the CLI owns the
  local wire format, keychain, and daemon.

## Test

Python, from `python/`:

```bash
python -m unittest discover -s tests -v
```

TypeScript, from `typescript/`:

```bash
npm install
npm test
```

Both suites use a fake helper and a fake resolver. They assert the helper
payload, the child environment scrub, the resolver handles, and the tool
schema fixture. They do not need a real keychain or a network.

## Layout

```text
integrations/plugin/
  README.md
  openapi.yaml
  schema/tool.json
  python/
  typescript/
```

`schema/tool.json` is the shared wire contract. The Python and TypeScript
schemas are checked against it.
