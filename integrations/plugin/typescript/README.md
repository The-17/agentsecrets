# @the-17/agentsecrets-plugin

Zero-knowledge credential tool for OpenAI function calling and dsh/Cordis.

```bash
npm install @the-17/agentsecrets-plugin
```

```ts
import { AgentSecretsClient } from "@the-17/agentsecrets-plugin";

const result = await new AgentSecretsClient().call({
  url: "https://api.example.com/v1/things",
  injections: { bearer: "EXAMPLE_API_KEY" },
});
```

See the [main README](../README.md) for the tool schema, modes, adapters, and
security model.
