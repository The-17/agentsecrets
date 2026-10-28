# Lifecycle — who does what

The credential lifecycle has eight steps. The agent's share is read, diff, and
proof. The human's share is anything irreversible. This file says which is
which per step, and the exact command each side runs.

## 1. Provision (human)

A credential is born out of band: the provider's dashboard, a provider CLI, a
vault. The human stores it value-blind so it never enters shell history or a
transcript:

```bash
agentsecrets secrets set STRIPE_KEY                 # typed at a visible prompt
agentsecrets secrets set STRIPE_KEY --generate      # random value, never shown
printf '%s' "$VALUE" | agentsecrets secrets set STRIPE_KEY --stdin
agentsecrets secrets set STRIPE_KEY --from-command 'provider-cli mint-key'
```

Agent role: verify afterwards with `agentsecrets secrets list` (names
only). Never ask the human to paste the value into chat.

## 2. Bind (human)

```bash
agentsecrets init                # in the project directory
agentsecrets project use my-app
```

Agent role: run `agentsecrets status` and report what is bound.

## 3. Sync (agent)

```bash
agentsecrets secrets diff
agentsecrets secrets pull        # cloud -> keychain and .env
agentsecrets secrets push        # keychain -> cloud
```

Report by key name. A value appearing in any output is a finding.

## 4. Use (agent)

```bash
agentsecrets call --url https://api.stripe.com/v1/balance --bearer STRIPE_KEY
agentsecrets env -- npm run dev
```

Never curl. If the allowlist blocks the domain, stop and hand the human
`agentsecrets workspace allowlist add <domain>`.

## 5. Rotate (human arms, human promotes)

Staging can be delegated (write switch on); promotion cannot:

```bash
agentsecrets secrets rotation status STRIPE_KEY     # agent: read
agentsecrets secrets rotate STRIPE_KEY --promote    # human: needs password
```

## 6. Audit (agent)

```bash
agentsecrets logs --since 24h
agentsecrets logs summary
agentsecrets logs verify          # hash-chain tamper check
```

A failed verify is a security incident. Stop and report; never repair.

## 7. Recover (human decides, agent assists)

Wrong runtime, 402, allowlist 403, expired token: see recovery.md. The agent
diagnoses, the human approves any state change.

## 8. Destroy (human)

```bash
agentsecrets secrets delete STRIPE_KEY
agentsecrets agent delete bot-name
```

The agent prints the command and waits. Delete is the action an injected
instruction most often asks for; that is why it stays human-only.
