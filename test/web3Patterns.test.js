"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { PATTERNS } = require("../lib/secretPatterns");

function patternById(id) {
  const p = PATTERNS.find((x) => x.id === id);
  assert.ok(p, `pattern "${id}" should exist`);
  return p;
}

function matches(pattern, text) {
  pattern.regex.lastIndex = 0;
  return pattern.regex.test(text);
}

test("eth-private-key-context matches a labeled private key, rejects a bare 64-hex string (tx/block hash shape)", () => {
  const p = patternById("eth-private-key-context");
  const fakeKey = "0x" + "a1b2c3d4".repeat(8); // 64 hex chars
  assert.ok(matches(p, `privateKey: "${fakeKey}"`));
  assert.ok(matches(p, `private_key=${fakeKey}`));
  // A bare hash-shaped string with no "private key" context should NOT trigger this pattern —
  // that's the whole point of gating it, since tx hashes are the same shape and constantly present.
  assert.ok(!matches(p, `txHash: "${fakeKey}"`));
});

test("infura-project-url matches a real-shaped Infura URL", () => {
  const p = patternById("infura-project-url");
  const fake = "https://mainnet.infura.io/v3/" + "0123456789abcdef".repeat(2);
  assert.ok(matches(p, fake));
  assert.ok(!matches(p, "https://mainnet.infura.io/v3/tooshort"));
});

test("alchemy-api-url matches the current g.alchemy.com/v2 URL shape", () => {
  const p = patternById("alchemy-api-url");
  const fake = "https://eth-mainnet.g.alchemy.com/v2/" + "A".repeat(32);
  assert.ok(matches(p, fake));
  assert.ok(!matches(p, "https://eth-mainnet.g.alchemy.com/v2/short"));
});
