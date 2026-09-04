# agent-audit

Scan your **Claude Code** (and soon Codex CLI / Cursor) session transcripts for secrets that leaked into
the conversation and risky shell commands the agent actually executed.

AI coding agents read `.env` files, `cat` output that contains credentials, and run shell commands on your
behalf — and all of that gets written verbatim into local session transcripts (`~/.claude/projects/**/*.jsonl`).
Those files are rarely audited, rarely gitignored from backups, and can sit around for months. `agent-audit`
finds what's in there before someone else does.

```
$ npx agent-audit

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

**Secrets:** AWS keys, GCP API keys, GitHub/GitLab tokens, Slack tokens, Stripe live/restricted keys, OpenAI
and Anthropic API keys, npm tokens, Twilio keys, Discord bot tokens, PEM private key blocks, JWTs, database
connection strings with embedded credentials, and generic `api_key=...`/`password=...` assignments.

**Risky commands the agent ran:** `rm -rf /` style destructive deletes, `curl | bash` remote code execution,
base64-obfuscated payloads piped to a shell, fork bombs, reverse shells, recursive `chmod 777`, raw disk
writes (`dd`/`mkfs`), shell-history tampering, firewall disabling, `authorized_keys` writes, force-pushes to
`main`/`master`, `DROP TABLE`/`DROP DATABASE`, and crontab persistence.

## Install

```bash
npx agent-audit
```

or install globally:

```bash
npm install -g agent-audit
agent-audit
```

## Usage

```
agent-audit                        Scan the default Claude Code log dir (~/.claude/projects)
agent-audit --dir <path>           Scan a custom directory of *.jsonl transcripts
agent-audit --file <path>          Scan one specific *.jsonl file (repeatable)
agent-audit --json                 Machine-readable output, for CI
agent-audit --fail-on <severity>   Exit non-zero at/above this severity (default: high)
```

### CI usage

Run it as a pre-merge gate so a transcript with a live secret or a dangerous command never lands in a
backed-up log directory unnoticed:

```yaml
- run: npx agent-audit --fail-on critical
```

## Why this exists

Agentic coding tools are now doing real work inside real codebases — reading `.env` files, running shell
commands, calling internal APIs — and every one of those actions is being logged locally, verbatim, by
design (so you can resume sessions and so the agent has memory). That's a new, mostly-unaudited class of
secret sprawl. `agent-audit` is a first pass at making that visible.

## Privacy

100% local. No network calls, no telemetry, nothing leaves your machine. Read the source — it's ~300 lines.

## Roadmap

- Codex CLI and Cursor transcript formats
- `--redact-in-place` to scrub findings from transcripts directly
- Team/CI dashboard for aggregating findings across a fleet of developer machines (paid tier)

## License

MIT
