"use strict";

const { PATTERNS, redactMatch } = require("./secretPatterns");
const { COMMAND_PATTERNS } = require("./commandPatterns");
const { AGENTS, getAgent } = require("./parsers");
const { findMnemonics } = require("./mnemonicDetector");

async function scanFiles(agentDef, targetFiles) {
  const findings = [];

  for (const filePath of targetFiles) {
    for await (const chunk of agentDef.iterateFile(filePath)) {
      if (chunk.kind === "text") {
        for (const pattern of PATTERNS) {
          pattern.regex.lastIndex = 0;
          let m;
          while ((m = pattern.regex.exec(chunk.text)) !== null) {
            findings.push({
              category: "secret",
              id: pattern.id,
              label: pattern.label,
              severity: pattern.severity,
              redacted: redactMatch(m[0]),
              agent: agentDef.id,
              file: chunk.source.file,
              line: chunk.source.line,
              role: chunk.source.role,
              context: chunk.source.tool ? `tool:${chunk.source.tool}` : chunk.source.block,
              timestamp: chunk.source.timestamp,
            });
            if (m[0].length === 0) pattern.regex.lastIndex++;
          }
        }

        for (const hit of findMnemonics(chunk.text)) {
          findings.push({
            category: "secret",
            id: hit.isKnownTestMnemonic ? "bip39-known-test-mnemonic" : "bip39-mnemonic",
            label: hit.isKnownTestMnemonic
              ? `Known Public Dev-Tool Test Mnemonic (${hit.wordCount} words, e.g. Hardhat's default — controls no real funds)`
              : `Crypto Wallet Seed Phrase (${hit.wordCount} words)`,
            severity: hit.isKnownTestMnemonic ? "low" : "critical",
            redacted: redactMatch(hit.phrase),
            agent: agentDef.id,
            file: chunk.source.file,
            line: chunk.source.line,
            role: chunk.source.role,
            context: chunk.source.tool ? `tool:${chunk.source.tool}` : chunk.source.block,
            timestamp: chunk.source.timestamp,
          });
        }
      } else if (chunk.kind === "command") {
        for (const pattern of COMMAND_PATTERNS) {
          if (pattern.regex.test(chunk.command)) {
            findings.push({
              category: "risky-command",
              id: pattern.id,
              label: pattern.label,
              severity: pattern.severity,
              redacted: chunk.command.length > 120 ? chunk.command.slice(0, 117) + "..." : chunk.command,
              agent: agentDef.id,
              file: chunk.source.file,
              line: chunk.source.line,
              role: chunk.source.role,
              context: `tool:${chunk.source.tool}`,
              timestamp: chunk.source.timestamp,
            });
          }
        }
      }
    }
  }

  return findings;
}

async function scan({ dir, files, agent } = {}) {
  // Explicit files/dir: scan with one named agent's parser (defaults to claude-code for
  // backward compatibility with existing --dir/--file usage).
  if (files && files.length) {
    const agentDef = getAgent(agent || "claude-code");
    const findings = await scanFiles(agentDef, files);
    return { filesScanned: files.length, findings };
  }

  if (dir) {
    const agentDef = getAgent(agent || "claude-code");
    const targetFiles = agentDef.findSessionFiles(dir);
    const findings = await scanFiles(agentDef, targetFiles);
    return { filesScanned: targetFiles.length, findings };
  }

  // Auto mode: scan every known agent's default log directory.
  let filesScanned = 0;
  let findings = [];
  for (const agentDef of AGENTS) {
    const targetFiles = agentDef.findSessionFiles(agentDef.defaultLogDir());
    filesScanned += targetFiles.length;
    findings = findings.concat(await scanFiles(agentDef, targetFiles));
  }
  return { filesScanned, findings };
}

module.exports = { scan, AGENTS };
