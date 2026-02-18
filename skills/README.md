# AgentSecrets AI Skills

This directory contains skills/instructions for different AI platforms to use AgentSecrets effectively.

## What Are Skills?

Skills teach AI assistants how to:
- Use AgentSecrets commands properly
- Never display secret values
- Help users with secrets management workflows
- Write code that uses secrets securely

## Available Skills

### Claude (MCP)

**File**: `claude/SKILL.md`

Teaches Claude how to use AgentSecrets in computer use mode. When users ask for help with deployments, environment setup, or secrets, Claude knows to use AgentSecrets commands.

**Key Features**:
- Zero-knowledge: Claude never sees secret values
- Workflow automation: Pull secrets, switch environments
- Code generation: Write code using environment variables
- Security first: Always reference secrets by key, never value

### ChatGPT (Custom Instructions)

**File**: `chatgpt/custom_instructions.md` (coming soon)

Custom instructions for ChatGPT to use AgentSecrets in Code Interpreter or when helping with deployments.

### GitHub Copilot

**File**: `copilot/integration.md` (coming soon)

Instructions for integrating AgentSecrets into GitHub Copilot workflows.

## Using These Skills

### For Claude

1. The Claude skill is in `claude/SKILL.md`
2. When using Claude with computer use, it will automatically recognize AgentSecrets commands
3. You can also manually reference this skill when asking Claude for help

### For Other AI Platforms

Each platform has different integration methods. Check the specific skill file for instructions.

## Creating New Skills

Want to create a skill for a different AI platform? 

1. Create a new directory: `skills/[platform-name]/`
2. Add your skill instructions
3. Submit a PR

We welcome skills for:
- Cursor
- Tabnine
- Amazon Q
- Codeium
- Any other AI coding assistant

## Principles

All skills should follow these principles:

1. **Zero-Knowledge**: AI never sees secret values
2. **Security First**: Always reference secrets by key
3. **Helpful**: Guide users through workflows
4. **Clear**: Explain what commands do
5. **Safe**: Never log or display secrets

## Testing Skills

Test your skill by:
1. Using it with the target AI platform
2. Asking for help with secrets management
3. Verifying the AI never displays secret values
4. Checking it uses AgentSecrets commands correctly

## Contributing

See [CONTRIBUTING.md](../CONTRIBUTING.md) for contribution guidelines.

For skill-specific questions, open an issue tagged with `ai-integration`.

---

**Goal**: Make AgentSecrets the default way ALL AI assistants handle secrets.