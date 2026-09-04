"use strict";

// Each pattern: id, label, severity, regex (global), and a redact() to show a safe fragment.
// Kept intentionally conservative on generic patterns to limit false positives.
const PATTERNS = [
  { id: "aws-access-key", label: "AWS Access Key ID", severity: "high", regex: /AKIA[0-9A-Z]{16}/g },
  { id: "aws-secret-context", label: "AWS Secret Access Key (near-match)", severity: "high", regex: /aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9\/+=]{40}['"]?/gi },
  { id: "gcp-api-key", label: "Google API Key", severity: "high", regex: /AIza[0-9A-Za-z_\-]{35}/g },
  { id: "github-token", label: "GitHub Token", severity: "high", regex: /gh[pousr]_[A-Za-z0-9]{36,}/g },
  { id: "gitlab-token", label: "GitLab Token", severity: "high", regex: /glpat-[A-Za-z0-9_\-]{20,}/g },
  { id: "slack-token", label: "Slack Token", severity: "high", regex: /xox[baprs]-[0-9A-Za-z-]{10,}/g },
  { id: "stripe-live-key", label: "Stripe Live Secret Key", severity: "critical", regex: /sk_live_[0-9a-zA-Z]{20,}/g },
  { id: "stripe-restricted-key", label: "Stripe Restricted Key", severity: "high", regex: /rk_live_[0-9a-zA-Z]{20,}/g },
  { id: "openai-key", label: "OpenAI API Key", severity: "high", regex: /sk-[A-Za-z0-9]{20,}(?!ant-)/g },
  { id: "anthropic-key", label: "Anthropic API Key", severity: "high", regex: /sk-ant-[A-Za-z0-9_\-]{20,}/g },
  { id: "npm-token", label: "npm Access Token", severity: "high", regex: /npm_[A-Za-z0-9]{36}/g },
  { id: "twilio-key", label: "Twilio API Key", severity: "medium", regex: /SK[0-9a-fA-F]{32}/g },
  { id: "discord-bot-token", label: "Discord Bot Token", severity: "high", regex: /[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27,}/g },
  { id: "private-key-block", label: "Private Key Block", severity: "critical", regex: /-----BEGIN (RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----/g },
  { id: "jwt", label: "JWT Token", severity: "medium", regex: /eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { id: "db-connection-string", label: "Database Connection String with Credentials", severity: "critical", regex: /(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[^:\/\s]+:[^@\/\s]+@[^\s'"]+/gi },
  { id: "generic-secret-assignment", label: "Generic Secret/Key/Token Assignment", severity: "low", regex: /\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/gi },
];

function redactMatch(match) {
  if (match.length <= 10) return "*".repeat(match.length);
  return match.slice(0, 4) + "…" + match.slice(-4) + ` (${match.length} chars)`;
}

module.exports = { PATTERNS, redactMatch };
