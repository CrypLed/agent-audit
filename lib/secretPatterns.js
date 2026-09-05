"use strict";

// Each pattern: id, label, severity, regex (global). Shapes are sourced from each provider's actual
// documented token format (cross-checked against odomojuli/regextokens, a maintained catalog of
// sourced+tested provider token formats) rather than guessed, so a scan is neither missing real leaks
// nor flooding on lookalike strings. Kept intentionally conservative on generic/context-based patterns
// to limit false positives.
const PATTERNS = [
  { id: "aws-access-key", label: "AWS Access Key ID", severity: "high", regex: /\b(?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16}\b/g },
  { id: "aws-secret-context", label: "AWS Secret Access Key (near-match)", severity: "high", regex: /aws_secret_access_key\s*[:=]\s*['"]?[A-Za-z0-9\/+=]{40}['"]?/gi },
  { id: "gcp-api-key", label: "Google API Key", severity: "high", regex: /AIza[0-9A-Za-z_\-]{35}/g },
  { id: "google-oauth-client-secret", label: "Google OAuth Client Secret", severity: "high", regex: /GOCSPX-[0-9A-Za-z_-]{28}/g },
  { id: "google-oauth-refresh-token", label: "Google OAuth Refresh Token", severity: "high", regex: /1\/\/[0-9A-Za-z_-]{43,128}/g },
  { id: "github-pat-classic", label: "GitHub Personal Access Token", severity: "high", regex: /ghp_[0-9A-Za-z]{36,}/g },
  { id: "github-pat-fine-grained", label: "GitHub Fine-Grained Token", severity: "high", regex: /github_pat_[0-9A-Za-z_]{82,}/g },
  { id: "github-oauth-token", label: "GitHub OAuth/App Token", severity: "high", regex: /gh[ousr]_[0-9A-Za-z]{36,}/g },
  { id: "gitlab-token", label: "GitLab Token", severity: "high", regex: /gl(?:pat|oas|ptt|rt)-[0-9A-Za-z_-]{20,}/g },
  { id: "slack-bot-token", label: "Slack Bot Token", severity: "high", regex: /xoxb-[0-9]{10,13}-[0-9]{10,13}-[0-9A-Za-z]{24,34}/g },
  { id: "slack-user-token", label: "Slack User Token", severity: "high", regex: /xoxp-(?:[0-9]{10,13}-){3}[0-9A-Za-z]{28,34}/g },
  { id: "slack-webhook", label: "Slack Incoming Webhook URL", severity: "medium", regex: /https:\/\/hooks\.slack\.com\/services\/T[0-9A-Za-z_]{8,12}\/B[0-9A-Za-z_]{8,12}\/[0-9A-Za-z_]{20,24}/g },
  { id: "stripe-secret-key", label: "Stripe Secret/Restricted Key", severity: "critical", regex: /(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{24,99}/g },
  { id: "openai-key", label: "OpenAI API Key", severity: "high", regex: /sk-(?:proj-|svcacct-|admin-)?[0-9A-Za-z_-]{20,74}T3BlbkFJ[0-9A-Za-z_-]{20,74}|sk-[0-9A-Za-z]{48}/g },
  { id: "anthropic-key", label: "Anthropic API Key", severity: "high", regex: /sk-ant-(?:api03|admin01)-[0-9A-Za-z_-]{93}AA/g },
  { id: "huggingface-token", label: "Hugging Face Token", severity: "medium", regex: /hf_[0-9A-Za-z]{34}/g },
  { id: "npm-token", label: "npm Access Token", severity: "high", regex: /npm_[0-9A-Za-z]{36}/g },
  { id: "pypi-token", label: "PyPI Token", severity: "high", regex: /pypi-AgEIcHlwaS5vcmc[0-9A-Za-z_-]{50,1000}/g },
  { id: "twilio-sid", label: "Twilio Account/API Key SID", severity: "medium", regex: /\b(?:AC|SK)[0-9a-fA-F]{32}\b/g },
  { id: "sendgrid-key", label: "SendGrid API Key", severity: "high", regex: /SG\.[0-9A-Za-z_-]{22}\.[0-9A-Za-z_-]{43}/g },
  { id: "mailgun-key", label: "Mailgun Private Key", severity: "medium", regex: /key-[0-9a-f]{32}/g },
  { id: "mailchimp-key", label: "Mailchimp API Key", severity: "medium", regex: /[0-9a-f]{32}-us[0-9]{1,2}/g },
  { id: "discord-bot-token", label: "Discord Bot Token", severity: "high", regex: /[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27,38}/g },
  { id: "square-token", label: "Square Access Token", severity: "high", regex: /EAAA[0-9A-Za-z_-]{60}|sq0atp-[0-9A-Za-z_-]{22}/g },
  { id: "shopify-token", label: "Shopify Access Token", severity: "high", regex: /shp(?:at|ss|pa|ca)_[0-9a-fA-F]{32}/g },
  { id: "vercel-token", label: "Vercel Access Token", severity: "high", regex: /vcp_[A-Za-z0-9]{24}/g },
  { id: "digitalocean-pat", label: "DigitalOcean Personal Access Token", severity: "high", regex: /dop_v1_[0-9a-f]{64}/g },
  { id: "doppler-token", label: "Doppler Token", severity: "high", regex: /dp\.pt\.[0-9A-Za-z]{43}/g },
  { id: "linear-key", label: "Linear API Key", severity: "medium", regex: /lin_api_[0-9A-Za-z]{40}/g },
  { id: "databricks-token", label: "Databricks Token", severity: "high", regex: /dapi[0-9a-f]{32}(?:-\d)?/g },
  { id: "heroku-key-v2", label: "Heroku API Key", severity: "high", regex: /HRKU-[0-9A-Za-z_-]{58,}/g },
  { id: "facebook-token", label: "Facebook Access Token", severity: "medium", regex: /EAA[0-9A-Za-z]{90,}/g },
  { id: "private-key-block", label: "Private Key Block", severity: "critical", regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----/g },
  { id: "jwt", label: "JWT Token", severity: "medium", regex: /ey[A-Za-z0-9_-]{10,}\.ey[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  { id: "db-connection-string", label: "Database Connection String with Credentials", severity: "critical", regex: /(postgres|postgresql|mysql|mongodb(\+srv)?):\/\/[^:\/\s]+:[^@\/\s]+@[^\s'"]+/gi },
  { id: "generic-secret-assignment", label: "Generic Secret/Key/Token Assignment", severity: "low", regex: /\b(api[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token|password)\s*[:=]\s*['"][A-Za-z0-9_\-+/=]{16,}['"]/gi },

  // Web3/crypto — a leaked key here doesn't mean a compromised account, it means drained funds with no
  // recourse. Private key hex is context-gated (a bare 64-hex-char string is extremely ambiguous in a
  // Web3 session — it's also the exact shape of a transaction hash or block hash, both constantly
  // present in completely benign logs) so this only fires next to a variable name that says what it is.
  { id: "eth-private-key-context", label: "Ethereum Private Key (hex)", severity: "critical", regex: /(?:private[_-]?key|priv[_-]?key|wallet[_-]?key)\s*[:=]\s*['"]?(0x)?[0-9a-fA-F]{64}['"]?/gi },
  { id: "infura-project-url", label: "Infura Project URL (embedded key)", severity: "high", regex: /https?:\/\/[a-z0-9-]+\.infura\.io\/v3\/[0-9a-fA-F]{32}/gi },
  { id: "alchemy-api-url", label: "Alchemy API URL (embedded key)", severity: "high", regex: /https?:\/\/[a-z0-9-]+\.g\.alchemy\.com\/v2\/[A-Za-z0-9_-]{32,}/gi },
];

function redactMatch(match) {
  if (match.length <= 10) return "*".repeat(match.length);
  return match.slice(0, 4) + "…" + match.slice(-4) + ` (${match.length} chars)`;
}

module.exports = { PATTERNS, redactMatch };
