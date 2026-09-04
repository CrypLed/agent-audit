"use strict";

const SEVERITY_ORDER = { critical: 0, high: 1, medium: 2, low: 3 };
const SEVERITY_COLOR = {
  critical: "\x1b[41m\x1b[97m", // white on red
  high: "\x1b[31m", // red
  medium: "\x1b[33m", // yellow
  low: "\x1b[36m", // cyan
};
const RESET = "\x1b[0m";

function sortFindings(findings) {
  return [...findings].sort((a, b) => SEVERITY_ORDER[a.severity] - SEVERITY_ORDER[b.severity]);
}

function textReport({ filesScanned, findings }, { color = true } = {}) {
  const lines = [];
  lines.push(`agent-audit — scanned ${filesScanned} session file(s), ${findings.length} finding(s)\n`);

  if (findings.length === 0) {
    lines.push("No secrets or risky commands detected. Clean.");
    return lines.join("\n");
  }

  const sorted = sortFindings(findings);
  for (const f of sorted) {
    const tag = color ? `${SEVERITY_COLOR[f.severity] || ""}[${f.severity.toUpperCase()}]${RESET}` : `[${f.severity.toUpperCase()}]`;
    const kind = f.category === "secret" ? "SECRET" : "RISKY COMMAND";
    lines.push(`${tag} ${kind}: ${f.label}`);
    lines.push(`  value:   ${f.redacted}`);
    lines.push(`  agent:   ${f.agent || "claude-code"}`);
    lines.push(`  file:    ${f.file}:${f.line}`);
    lines.push(`  context: role=${f.role} ${f.context}${f.timestamp ? ` at ${f.timestamp}` : ""}`);
    lines.push("");
  }

  const counts = sorted.reduce((acc, f) => {
    acc[f.severity] = (acc[f.severity] || 0) + 1;
    return acc;
  }, {});
  lines.push(
    "Summary: " +
      Object.entries(counts)
        .map(([sev, n]) => `${n} ${sev}`)
        .join(", ")
  );

  return lines.join("\n");
}

function jsonReport(result) {
  return JSON.stringify(result, null, 2);
}

module.exports = { textReport, jsonReport, sortFindings };
