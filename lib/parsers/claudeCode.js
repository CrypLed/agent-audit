"use strict";

const fs = require("fs");
const readline = require("readline");
const os = require("os");
const path = require("path");

function defaultLogDir() {
  return path.join(os.homedir(), ".claude", "projects");
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

// Yields { text, source } chunks worth scanning for secrets, and
// { command, source } chunks worth scanning for risky shell commands.
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

    if (entry.type !== "user" && entry.type !== "assistant") continue;
    const message = entry.message || {};
    const content = message.content;
    if (!Array.isArray(content)) continue;

    const baseSource = {
      file: filePath,
      line: lineNum,
      role: entry.type,
      timestamp: entry.timestamp,
      uuid: entry.uuid,
    };

    for (const block of content) {
      if (!block || typeof block !== "object") continue;

      if ((block.type === "text" || block.type === "thinking") && typeof block.text === "string") {
        yield { kind: "text", text: block.text, source: { ...baseSource, block: block.type } };
      }

      if (block.type === "tool_use" && block.input && typeof block.input === "object") {
        const toolName = block.name || "unknown";
        const inputStr = safeStringify(block.input);
        yield { kind: "text", text: inputStr, source: { ...baseSource, block: "tool_use", tool: toolName } };

        if (/^bash$/i.test(toolName) && typeof block.input.command === "string") {
          yield {
            kind: "command",
            command: block.input.command,
            source: { ...baseSource, block: "tool_use", tool: toolName },
          };
        }
      }

      if (block.type === "tool_result") {
        const text = extractToolResultText(block.content);
        if (text) {
          yield { kind: "text", text, source: { ...baseSource, block: "tool_result" } };
        }
      }
    }
  }
}

function extractToolResultText(content) {
  if (typeof content === "string") return content;
  if (Array.isArray(content)) {
    return content
      .filter((c) => c && typeof c === "object" && typeof c.text === "string")
      .map((c) => c.text)
      .join("\n");
  }
  return "";
}

function safeStringify(obj) {
  try {
    return JSON.stringify(obj);
  } catch (_) {
    return "";
  }
}

module.exports = { defaultLogDir, findSessionFiles, iterateFile };
