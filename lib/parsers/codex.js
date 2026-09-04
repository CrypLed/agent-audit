"use strict";

// Parser for Codex CLI rollout transcripts.
//
// Format verified against the actual openai/codex source (codex-rs/history/src/rollout_payload.rs
// and codex-rs/protocol/src/models.rs), not guessed: each line is
//   { "type": <RolloutItem variant, snake_case>, "payload": {...}, ... }
// The variant that carries real conversation content is "response_item", whose payload is a
// ResponseItem tagged by its own "type": message | agent_message | reasoning | function_call |
// function_call_output | local_shell_call | ...

const fs = require("fs");
const readline = require("readline");
const os = require("os");
const path = require("path");

function defaultLogDir() {
  return path.join(process.env.CODEX_HOME || path.join(os.homedir(), ".codex"), "sessions");
}

function findSessionFiles(rootDir) {
  const results = [];
  if (!fs.existsSync(rootDir)) return results;
  const stack = [rootDir];
  while (stack.length) {
    const dir = stack.pop();
    let entries;
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch (_) {
      continue;
    }
    for (const entry of entries) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
      } else if (entry.isFile() && entry.name.endsWith(".jsonl")) {
        results.push(full);
      }
    }
  }
  return results;
}

const SHELL_TOOL_NAME = /shell|exec|bash|local_shell/i;

function extractOutputBodyText(body) {
  if (typeof body === "string") return body;
  if (Array.isArray(body)) {
    return body
      .filter((c) => c && typeof c === "object" && typeof c.text === "string")
      .map((c) => c.text)
      .join("\n");
  }
  return "";
}

async function* iterateFile(filePath) {
  const rl = readline.createInterface({
    input: fs.createReadStream(filePath, { encoding: "utf8" }),
    crlfDelay: Infinity,
  });

  let lineNum = 0;
  for await (const line of rl) {
    lineNum++;
    if (!line.trim()) continue;
    let entry;
    try {
      entry = JSON.parse(line);
    } catch (_) {
      continue;
    }

    if (entry.type !== "response_item") continue;
    const item = entry.payload;
    if (!item || typeof item !== "object") continue;

    const baseSource = { file: filePath, line: lineNum, timestamp: entry.timestamp };

    switch (item.type) {
      case "message": {
        const role = item.role || "unknown";
        for (const content of item.content || []) {
          if ((content.type === "input_text" || content.type === "output_text") && typeof content.text === "string") {
            yield { kind: "text", text: content.text, source: { ...baseSource, role, block: content.type } };
          }
        }
        break;
      }
      case "agent_message": {
        for (const content of item.content || []) {
          if (content.type === "input_text" && typeof content.text === "string") {
            yield { kind: "text", text: content.text, source: { ...baseSource, role: item.author || "agent", block: "agent_message" } };
          }
        }
        break;
      }
      case "function_call": {
        const name = item.name || "unknown";
        yield {
          kind: "text",
          text: `${name} ${item.arguments || ""}`,
          source: { ...baseSource, role: "assistant", block: "function_call", tool: name },
        };

        if (SHELL_TOOL_NAME.test(name) && typeof item.arguments === "string") {
          let parsedArgs;
          try {
            parsedArgs = JSON.parse(item.arguments);
          } catch (_) {
            parsedArgs = null;
          }
          const cmd = parsedArgs && parsedArgs.command;
          if (Array.isArray(cmd)) {
            yield {
              kind: "command",
              command: cmd.join(" "),
              source: { ...baseSource, role: "assistant", block: "function_call", tool: name },
            };
          } else if (typeof cmd === "string") {
            yield {
              kind: "command",
              command: cmd,
              source: { ...baseSource, role: "assistant", block: "function_call", tool: name },
            };
          }
        }
        break;
      }
      case "function_call_output": {
        const text = extractOutputBodyText(item.output && item.output.body);
        if (text) {
          yield { kind: "text", text, source: { ...baseSource, role: "tool", block: "function_call_output" } };
        }
        break;
      }
      case "local_shell_call": {
        const action = item.action;
        const cmd = action && action.type === "exec" && Array.isArray(action.command) ? action.command : null;
        if (cmd) {
          yield {
            kind: "command",
            command: cmd.join(" "),
            source: { ...baseSource, role: "assistant", block: "local_shell_call", tool: "local_shell" },
          };
        }
        break;
      }
      default:
        break;
    }
  }
}

module.exports = { defaultLogDir, findSessionFiles, iterateFile };
