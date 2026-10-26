package commands

// workflowContentTemplate is what `init` writes into
// .agent/workflows/agentsecrets.md.
//
// It is generated from skill_content.go so that `init` and `mcp install` ship
// one procedure, not two that drift. See that file for the scope rules and why
// they are what they are.
var workflowContentTemplate = WorkflowSkill()
