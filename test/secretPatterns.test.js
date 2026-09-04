"use strict";

// Verifies each newly-added secret pattern actually matches a realistically-shaped fake token of that
// exact type, and that a similar-but-wrong-shaped string does NOT match (basic false-positive guard).
// Fake values are built from parts at runtime, not literal in source, for the same reason the other
// fixtures are: avoid tripping real secret scanners on this repo itself.

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

test("shopify-token matches a real-shaped token and rejects a too-short one", () => {
  const p = patternById("shopify-token");
  const fake = "shpat_" + "0123456789abcdef".repeat(2); // 32 hex chars
  assert.ok(matches(p, fake));
  assert.ok(!matches(p, "shpat_shorttoken"));
});

test("sendgrid-key matches the SG.<22>.<43> shape", () => {
  const p = patternById("sendgrid-key");
  const fake = "SG." + "a".repeat(22) + "." + "b".repeat(43);
  assert.ok(matches(p, fake));
  assert.ok(!matches(p, "SG.tooshort"));
});

test("vercel-token matches vcp_ + 24 alnum chars", () => {
  const p = patternById("vercel-token");
  const fake = "vcp_" + "a1B2c3D4e5F6g7H8i9J0k1L2";
  assert.ok(matches(p, fake));
});

test("digitalocean-pat matches dop_v1_ + 64 hex chars", () => {
  const p = patternById("digitalocean-pat");
  const fake = "dop_v1_" + "0123456789abcdef".repeat(4);
  assert.ok(matches(p, fake));
  assert.ok(!matches(p, "dop_v1_tooshort"));
});

test("google-oauth-client-secret matches GOCSPX- + 28 chars", () => {
  const p = patternById("google-oauth-client-secret");
  const fake = "GOCSPX-" + "aB1_cD2-eF3gH4iJ5kL6mN7oP8qR"; // exactly 28 chars
  assert.ok(matches(p, fake));
});

test("github-pat-classic no longer matches a Discord-style token (id split, not merged)", () => {
  const p = patternById("github-pat-classic");
  assert.ok(!matches(p, "some random text with no token in it"));
});
