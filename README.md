# agent-audit

Scan your **Claude Code** and **Codex CLI** session transcripts for secrets that leaked into the
conversation and risky shell commands the agent actually executed.

AI coding agents read `.env` files, `cat` output that contains credentials, and run shell commands on your
behalf — and all of that gets written verbatim into local session transcripts (Claude Code:
`~/.claude/projects/**/*.jsonl`, Codex CLI: `~/.codex/sessions/**/*.jsonl`). Those files are rarely audited,
rarely gitignored from backups, and can sit around for months. `agent-audit` finds what's in there before
someone else does. Running it with no arguments scans every known agent's default log directory at once.

**If you build on Ethereum/EVM chains, this matters more than usual.** A leaked API key is a bad day; a
seed phrase or private key that passed through an agent's session — from a `.env` cat, a debug print, a
"here's my wallet for testing" — is funds gone, no recourse, no support ticket to file. `agent-audit`
checks for that specifically: real BIP-39 wallet mnemonics (validated against the actual 2048-word spec
list, not a guess) and Ethereum private keys, alongside Infura/Alchemy RPC URLs with embedded project keys.
It also knows about Hardhat's famous public default test mnemonic and won't cry wolf over it.

```
$ npx github:CrypLed/agent-audit

agent-audit — scanned 59 session file(s), 3 finding(s)

[CRITICAL] SECRET: Database Connection String with Credentials
  value:   post…t_db (64 chars)
  file:    ~/.claude/projects/-home-you-billing-service/7dc5....jsonl:21
  context: role=user tool_result at 2026-08-20T21:10:47.890Z

[HIGH] RISKY COMMAND: Download-and-execute via pipe to shell
  value:   curl https://example.com/install.sh | bash
  file:    ~/.claude/projects/-home-you-infra/a2f1....jsonl:14
  context: role=assistant tool:Bash

Summary: 1 critical, 1 high
```

Values are always redacted (first/last few characters only) — `agent-audit` never prints a usable secret,
even to your own terminal.

## What it detects

**Secrets:** AWS keys, Google API keys/OAuth secrets, GitHub (classic, fine-grained, OAuth) and GitLab
tokens, Slack bot/user tokens and webhooks, Stripe secret/restricted keys, OpenAI and Anthropic API keys,
Hugging Face and PyPI tokens, npm tokens, Twilio SIDs, SendGrid/Mailgun/Mailchimp keys, Discord bot tokens,
Square/Shopify/Vercel/DigitalOcean/Doppler/Linear/Databricks/Heroku/Facebook tokens, PEM private key blocks,
JWTs, database connection strings with embedded credentials, and generic `api_key=...`/`password=...`
assignments. Shapes are sourced from each provider's actual documented format (cross-checked against
[odomojuli/regextokens](https://github.com/odomojuli/regextokens), a maintained, tested catalog), not
guessed — every added pattern has a test proving it matches a real-shaped token and rejects a malformed one.

**Web3-specific:** crypto wallet seed phrases (BIP-39 mnemonics, checked word-by-word against the real
2048-word spec list — not a fuzzy guess, since a valid mnemonic is by definition 100% real wordlist words),
Ethereum private keys (gated on nearby context like `privateKey:`, since a bare 64-hex-char string is
indistinguishable from an ordinary transaction hash otherwise), and Infura/Alchemy RPC URLs with embedded
project keys. Hardhat's well-known public default test mnemonic is recognized and reported as informational
rather than critical, since it controls no real funds by design and flagging it as a leak would just be
noise for the majority of Ethereum projects that use it locally.

**Risky commands the agent ran:** `rm -rf /` style destructive deletes, `curl | bash`/`curl | python3` remote
code execution, base64-obfuscated payloads piped to a shell, fork bombs, reverse and bind shells (including
the classic Python `pty.spawn` one-liner), recursive `chmod 777`, raw disk writes (`dd`/`mkfs`), shell-history
tampering, firewall disabling, `authorized_keys` writes, local files uploaded via `curl -F`, packages
installed from a raw URL instead of a registry, `LD_PRELOAD` injection, `docker run --privileged`,
plaintext git credential storage, immutable-flag tampering (`chattr`), force-pushes to `main`/`master`,
`DROP TABLE`/`DROP DATABASE`, and crontab persistence.

## Install

```bash
npx github:CrypLed/agent-audit
```

or clone and install globally:

```bash
git clone https://github.com/CrypLed/agent-audit && cd agent-audit
npm install -g .
agent-audit
```

(not yet on the npm registry — coming soon)

## Usage

```
agent-audit                        Scan every known agent's default log dir (Claude Code, Codex CLI)
agent-audit --dir <path>           Scan a custom directory of transcripts (pair with --agent)
agent-audit --file <path>          Scan one specific transcript file (repeatable, pair with --agent)
agent-audit --agent <claude-code|codex>
                                    Which parser to use with --dir/--file (default: claude-code)
agent-audit --json                 Machine-readable output, for CI
agent-audit --fail-on <severity>   Exit non-zero at/above this severity (default: high)
```

### CI usage

Run it as a pre-merge gate so a transcript with a live secret or a dangerous command never lands in a
backed-up log directory unnoticed:

```yaml
- run: npx github:CrypLed/agent-audit --fail-on critical
```

Or use it as a GitHub Action directly:

```yaml
- uses: CrypLed/agent-audit@main
  with:
    fail-on: critical
```

## Why this exists

Agentic coding tools are now doing real work inside real codebases — reading `.env` files, running shell
commands, calling internal APIs — and every one of those actions is being logged locally, verbatim, by
design (so you can resume sessions and so the agent has memory). That's a new, mostly-unaudited class of
secret sprawl. `agent-audit` is a first pass at making that visible.

**vs. GitHub's MCP-server secret scanning:** GitHub has a preview feature that scans your *current code
changes* for secrets on-demand, before a commit/PR, via an MCP tool call — different surface, and it
requires GitHub Secret Protection (paid) plus an explicit invocation each time. `agent-audit` scans the
*session transcript retroactively* — catching secrets that passed through the conversation (e.g. `cat .env`
output, an API response) without ever touching a committed file — and also flags risky commands the agent
executed, which that feature doesn't cover. Free, local, no setup, complementary rather than overlapping.

## Privacy

100% local. No network calls, no telemetry, nothing leaves your machine. Read the source — it's ~300 lines.

## Roadmap

- Cursor transcript format (stored in SQLite, not JSONL — needs a different approach; not shipped yet
  because it can't be verified against a real installation without one on hand, and a security tool that
  silently finds nothing is worse than one that's honest about not supporting a platform yet)
- `--redact-in-place` to scrub findings from transcripts directly
- Team/CI dashboard for aggregating findings across a fleet of developer machines (paid tier)

## Support this project

Need something like this built for your own codebase/workflow? [I take on paid automation work](https://crypled.github.io/hire-page/) — same process, real proof of work.

`agent-audit` is free and MIT-licensed, no strings attached. If it caught something useful in your logs and
you'd like to support continued development (Cursor support, the redact-in-place flag, more patterns), tips
are welcome via USDC/ETH on Base, Ethereum, Polygon, Arbitrum, or Optimism (same address on all):

```
0x36CCCB5854e1d513A2Af94CeaFC0f886102634e2
```

## License

MIT
