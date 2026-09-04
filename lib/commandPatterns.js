"use strict";

// Risky shell command patterns that AI coding agents have been observed to run,
// either accidentally (destructive cleanup) or as a sign of a prompt-injection /
// jailbreak having succeeded (exfiltration, reverse shells, disabling logging).
const COMMAND_PATTERNS = [
  { id: "rm-rf-root", label: "Recursive force-delete of root or home", severity: "critical", regex: /rm\s+(-[a-z]*r[a-z]*f[a-z]*|-[a-z]*f[a-z]*r[a-z]*)\s+(\/(\s|$)|~(\s|$)|\*(\s|$)|\$HOME)/ },
  { id: "curl-pipe-shell", label: "Download-and-execute via pipe to shell", severity: "critical", regex: /(curl|wget)\s+[^\n|]+\|\s*(sudo\s+)?(sh|bash|zsh)\b/ },
  { id: "base64-pipe-shell", label: "Obfuscated payload executed via base64 decode pipe", severity: "critical", regex: /base64\s+(-d|--decode)[^\n|]*\|\s*(sh|bash)/ },
  { id: "fork-bomb", label: "Shell fork bomb", severity: "critical", regex: /:\(\)\s*\{\s*:\|:&\s*\};:/ },
  { id: "reverse-shell", label: "Reverse shell invocation", severity: "critical", regex: /(bash\s+-i\s+>&\s*\/dev\/tcp\/|nc\s+-e\s+\/bin\/(ba)?sh|\/dev\/tcp\/\d+\.\d+\.\d+\.\d+)/ },
  { id: "chmod-777-recursive", label: "Recursive world-writable permissions", severity: "high", regex: /chmod\s+-R\s+777/ },
  { id: "disk-overwrite", label: "Raw disk write (dd/mkfs) to a device", severity: "critical", regex: /(dd\s+if=.*of=\/dev\/(sd|nvme|hd)|mkfs\.\w+\s+\/dev\/)/ },
  { id: "history-tamper", label: "Shell history / audit trail tampering", severity: "high", regex: /(history\s+-c\b|unset\s+HISTFILE|rm\s+.*\.bash_history|shred\s+.*history)/ },
  { id: "firewall-disable", label: "Firewall disabled or flushed", severity: "high", regex: /(iptables\s+-F|ufw\s+disable|systemctl\s+(disable|stop)\s+(firewalld|ufw))/ },
  { id: "ssh-key-write", label: "Write to authorized_keys (persistence)", severity: "high", regex: />>\s*.*\.ssh\/authorized_keys/ },
  { id: "force-push-main", label: "Force-push to a protected branch", severity: "medium", regex: /git\s+push\s+.*--force.*\b(origin\s+)?(main|master)\b/ },
  { id: "sql-drop", label: "SQL DROP TABLE/DATABASE", severity: "high", regex: /\bDROP\s+(TABLE|DATABASE)\b/i },
  { id: "crontab-persistence", label: "Crontab modification (possible persistence)", severity: "medium", regex: /crontab\s+-e|echo\s+.*>>\s*\/etc\/cron/ },
  { id: "curl-exfil-env", label: "Environment variables piped to a remote host", severity: "critical", regex: /env\s*\|\s*curl\s+/ },
  { id: "curl-pipe-interpreter", label: "Download-and-execute via pipe to a script interpreter", severity: "critical", regex: /(curl|wget)\s+[^\n|]+\|\s*(sudo\s+)?(python[23]?|perl|ruby|node)(\s+-)?\s*$/ },
  { id: "python-pty-spawn", label: "Python-spawned interactive shell (common exploitation technique)", severity: "critical", regex: /python[23]?\s+-c\s+["'].*pty\.spawn/ },
  { id: "bind-shell-listener", label: "Netcat listening for inbound connections (possible bind shell)", severity: "high", regex: /nc\s+(-[a-zA-Z]*l[a-zA-Z]*\s+|.*-l\s+-p\s+)/ },
  { id: "curl-exfil-upload", label: "Local file uploaded to a remote host via curl", severity: "high", regex: /curl\s+[^\n]*-F\s+["']?[^"'\s]*=@/ },
  { id: "package-install-raw-url", label: "Package installed directly from a raw URL instead of a registry", severity: "high", regex: /(pip3?\s+install|npm\s+install)\s+[^\n]*(https?:\/\/|git\+http:\/\/)/ },
  { id: "ld-preload-injection", label: "LD_PRELOAD set before running a binary (library injection)", severity: "high", regex: /\bLD_PRELOAD=\S+\s+\S+/ },
  { id: "docker-privileged", label: "Container started with --privileged (host escape risk)", severity: "high", regex: /docker\s+run\s+[^\n]*--privileged/ },
  { id: "git-credential-plaintext", label: "Git configured to store credentials in plaintext", severity: "medium", regex: /git\s+config\s+.*credential\.helper\s+store/ },
  { id: "immutable-flag-tamper", label: "Filesystem immutable flag set/unset (chattr) on a file", severity: "medium", regex: /chattr\s+[+-]i\s+/ },
];

module.exports = { COMMAND_PATTERNS };
