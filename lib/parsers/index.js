"use strict";

const claudeCode = require("./claudeCode");
const codex = require("./codex");

const AGENTS = [
  { id: "claude-code", label: "Claude Code", ...claudeCode },
  { id: "codex", label: "Codex CLI", ...codex },
];

function getAgent(id) {
  const agent = AGENTS.find((a) => a.id === id);
  if (!agent) throw new Error(`Unknown agent: ${id}. Known agents: ${AGENTS.map((a) => a.id).join(", ")}`);
  return agent;
}

module.exports = { AGENTS, getAgent };
