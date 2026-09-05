"use strict";

// Detects crypto wallet seed phrases (BIP-39 mnemonics) leaked into text. A valid mnemonic is, by spec,
// 100% real BIP-39 words, so no fuzzy tolerance is used — a genuine leaked phrase is always an exact
// match, and any tolerance just makes it easier for unrelated text to coincidentally qualify.
//
// Word extraction only follows genuine space/tab-separated runs of lowercase letters, not every
// lowercase substring in the document. That distinction matters: naively extracting every [a-z]+ run
// and sliding a window over the flat result stitches together words from *unrelated* code identifiers
// across underscores, dots, parens, and camelCase boundaries into a fake "phrase" that never existed as
// contiguous text — confirmed in practice by dogfooding against real decompiled-game-code session logs,
// where short common identifiers (item, room, time, ...) got glued into bogus 12-word runs this way.
// Requiring an actual unbroken run of space-separated lowercase words closes that gap: code naturally
// breaks such runs (snake_case, dots, braces, `=`), while both prose and a genuinely pasted mnemonic are
// real contiguous word sequences.

const { BIP39_WORDLIST } = require("./bip39Wordlist");

const WINDOW_LENGTHS = [24, 12]; // check the longer window first so a 24-word phrase isn't reported twice
const MIN_MATCH_RATIO = 1.0;
const WORD_RUN_REGEX = /[a-z]+(?:[ \t]+[a-z]+)*/g;

// Publicly documented dev-tool default mnemonics that control zero real funds by design (Hardhat
// initializes its local network with exactly this phrase, confirmed against hardhat.org's own docs).
// Flagging these as an unqualified "critical leaked wallet" would just be noise for the Web3 developers
// this feature targets, since literally every Hardhat project on earth generates it locally by default.
const KNOWN_PUBLIC_TEST_MNEMONICS = new Set(["test test test test test test test test test test test junk"]);

function findMnemonics(text) {
  const findings = [];

  for (const runMatch of text.matchAll(WORD_RUN_REGEX)) {
    const run = runMatch[0];
    const wordMatches = [...run.matchAll(/[a-z]+/g)];
    if (wordMatches.length < Math.min(...WINDOW_LENGTHS)) continue;

    const words = wordMatches.map((m) => m[0]);
    const claimed = new Array(words.length).fill(false);

    for (const windowLen of WINDOW_LENGTHS) {
      if (words.length < windowLen) continue;
      for (let start = 0; start <= words.length - windowLen; start++) {
        if (claimed.slice(start, start + windowLen).some(Boolean)) continue;
        let hits = 0;
        for (let i = start; i < start + windowLen; i++) {
          if (BIP39_WORDLIST.has(words[i])) hits++;
        }
        if (hits / windowLen >= MIN_MATCH_RATIO) {
          for (let i = start; i < start + windowLen; i++) claimed[i] = true;
          const startOffset = runMatch.index + wordMatches[start].index;
          const endMatch = wordMatches[start + windowLen - 1];
          const endOffset = runMatch.index + endMatch.index + endMatch[0].length;
          const phrase = text.slice(startOffset, endOffset);
          const isKnownTestMnemonic = KNOWN_PUBLIC_TEST_MNEMONICS.has(phrase.toLowerCase());
          findings.push({ phrase, wordCount: windowLen, isKnownTestMnemonic });
        }
      }
    }
  }

  return findings;
}

module.exports = { findMnemonics, MIN_MATCH_RATIO };
