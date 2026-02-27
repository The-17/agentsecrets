# `agentsecrets call`

The `call` command operates completely outside standard development loops and exists exclusively to handle proxy routing across integrated environments.

## Overview
It allows end-users and integrated Autonomous Agents (like OpenClaw) to silently query external 3rd party APIs mapping headers, endpoints, or data-frames against secrets stowed inside a `project` vault without ever explicitly revealing or downloading those configurations directly to the executing node machine.

## Behavior
If an AI agent needs to `GET /api/v1/stripe/balance`, instead of injecting standard `.env` configuration files filled with production Bearer tokens into the filesystem context, the agent blindly queries `agentsecrets call`. 

The central platform extracts linked configuration variables and safely negotiates the proxy transaction entirely server-side.
