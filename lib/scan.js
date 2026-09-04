"use strict";

const { PATTERNS, redactMatch } = require("./secretPatterns");
const { COMMAND_PATTERNS } = require("./commandPatterns");
const { defaultLogDir, findSessionFiles, iterateFile } = require("./parsers/claudeCode");

async function scan({ dir, files } = {}) {
  const targetFiles = files && files.length ? files : findSessionFiles(dir || defaultLogDir());
  const findings = [];

  for (const filePath of targetFiles) {
    for await (const chunk of iterateFile(filePath)) {
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
              file: chunk.source.file,
              line: chunk.source.line,
              role: chunk.source.role,
              context: chunk.source.tool ? `tool:${chunk.source.tool}` : chunk.source.block,
              timestamp: chunk.source.timestamp,
            });
            if (m[0].length === 0) pattern.regex.lastIndex++; // avoid infinite loop on zero-length match
          }
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

  return { filesScanned: targetFiles.length, findings };
}

module.exports = { scan };
