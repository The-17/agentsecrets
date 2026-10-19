# agentsecrets-plugin (Python)

Zero-knowledge credential tool for LangChain, CrewAI, AutoGen, and LlamaIndex.

```bash
pip install agentsecrets-plugin
```

```python
from agentsecrets_plugin import AgentSecretsClient

result = AgentSecretsClient().call(
    {
        "url": "https://api.example.com/v1/things",
        "injections": {"bearer": "EXAMPLE_API_KEY"},
    }
)
```

See the [main README](../README.md) for the tool schema, modes, framework
adapters, and security model.
