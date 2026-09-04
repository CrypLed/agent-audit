#!/usr/bin/env node
"use strict";

const { scan, textReport, jsonReport, AGENTS } = require("../lib");

function parseArgs(argv) {
  const args = { dir: null, files: [], json: false, help: false, failOn: "high", agent: null };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === "--json") args.json = true;
    else if (a === "--dir") args.dir = argv[++i];
    else if (a === "--file") args.files.push(argv[++i]);
    else if (a === "--fail-on") args.failOn = argv[++i];
    else if (a === "--agent") args.agent = argv[++i];
    else if (a === "--help" || a === "-h") args.help = true;
  }
  return args;
}

function printHelp() {
  const agentIds = AGENTS.map((a) => a.id).join("|");
  console.log(`agent-audit — scan AI coding agent session transcripts for leaked secrets and risky commands

Usage:
  agent-audit [scan]                Scan every known agent's default log dir (Claude Code, Codex CLI)
  agent-audit --dir <path>          Scan a custom directory of transcripts (requires --agent)
  agent-audit --file <path>         Scan one specific transcript file (repeatable, requires --agent)
  agent-audit --agent <${agentIds}>
                                     Which parser to use with --dir/--file (default: claude-code)
  agent-audit --json                Output findings as JSON (for CI / tooling)
  agent-audit --fail-on <severity>  Exit non-zero if a finding >= severity exists
                                     (critical|high|medium|low, default: high)
  agent-audit --help                Show this help

Exit codes:
  0  clean, or only findings below --fail-on threshold
  1  findings at/above --fail-on threshold were detected
  2  unexpected error
`);
}

const SEVERITY_RANK = { critical: 0, high: 1, medium: 2, low: 3 };

async function main() {
  const argv = process.argv.slice(2).filter((a) => a !== "scan");
  const args = parseArgs(argv);

  if (args.help) {
    printHelp();
    process.exit(0);
  }

  try {
    const result = await scan({ dir: args.dir, files: args.files, agent: args.agent });

    if (args.json) {
      console.log(jsonReport(result));
    } else {
      console.log(textReport(result));
      if (!args.dir && !args.files.length) {
        const dirs = AGENTS.map((a) => `${a.label}: ${a.defaultLogDir()}`).join("; ");
        console.log(`\n(scanned default log directories — ${dirs})`);
      }
    }

    const threshold = SEVERITY_RANK[args.failOn] ?? SEVERITY_RANK.high;
    const hasBlockingFinding = result.findings.some((f) => SEVERITY_RANK[f.severity] <= threshold);
    process.exit(hasBlockingFinding ? 1 : 0);
  } catch (err) {
    console.error("agent-audit error:", err.message);
    process.exit(2);
  }
}

main();
