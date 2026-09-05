"use strict";

const test = require("node:test");
const assert = require("node:assert");
const { findMnemonics } = require("../lib/mnemonicDetector");

// Test values are arbitrary consecutive slices of the *public* BIP-39 wordlist, used only to verify
// the sliding-window mechanism works — not anyone's real wallet (a 12-word phrase from a wallet also
// needs the exact right words in the exact right order out of 2048^12 possibilities to be valid; an
// arbitrary alphabetical slice isn't a real recoverable seed for any wallet).
const TWELVE_WORD_SLICE = "abandon ability able about above absent absorb abstract absurd abuse access accident";
const TWENTY_FOUR_WORD_SLICE =
  "abandon ability able about above absent absorb abstract absurd abuse access accident " +
  "account accuse achieve acid acoustic acquire across act action actor actress actual";

test("detects a 12-word sequence of real BIP-39 words", () => {
  const found = findMnemonics(`Here is the seed phrase: ${TWELVE_WORD_SLICE} - keep it safe`);
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].wordCount, 12);
});

test("detects a 24-word sequence and doesn't double-report it as two 12-word hits", () => {
  const found = findMnemonics(TWENTY_FOUR_WORD_SLICE);
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].wordCount, 24);
});

test("does not flag ordinary prose, even though individual words overlap the BIP-39 list", () => {
  // BIP-39 deliberately uses common English words, so ordinary text often contains scattered matches
  // (about, above, zone, legal, magic, world, music, matter, future, garden are all real BIP-39 words).
  // The point of the sliding window + 90% threshold is that scattered matches in normal prose don't
  // form a long enough *consecutive* run to trigger a false positive.
  const prose = `About above the garden wall, the world felt like magic. The music mattered more than
  any legal argument about the future of the zone. Nothing here is a wallet seed, just a paragraph
  written to contain a lot of individually-common words that happen to appear on a 2048-word list.`;
  const found = findMnemonics(prose);
  assert.strictEqual(found.length, 0);
});

test("does not flag a short run of a few real words mixed into a normal sentence", () => {
  const found = findMnemonics("I need to abandon this idea about the ability to access the accident report.");
  assert.strictEqual(found.length, 0);
});

test("does not stitch words together across code punctuation into a fake phrase", () => {
  // Regression test: an earlier version extracted every lowercase run in the whole document (ignoring
  // what separated them) and slid a window over that flat list, so unrelated short identifiers across
  // underscores/dots/braces got glued into a bogus "phrase". Confirmed happening in practice against
  // real decompiled game-code logs before this fix.
  const codeLike = `const item_room_time = { level: 1, speed: 2 };
function access_ability_about() { return absent.absorb.abstract; }
let absurd_abuse = accident.above;`;
  const found = findMnemonics(codeLike);
  assert.strictEqual(found.length, 0);
});

test("flags Hardhat's well-known public default test mnemonic as low-severity, not critical", () => {
  const found = findMnemonics("MNEMONIC=test test test test test test test test test test test junk");
  assert.strictEqual(found.length, 1);
  assert.strictEqual(found[0].isKnownTestMnemonic, true);
});
