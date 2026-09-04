"use strict";

const { scan } = require("./scan");
const { textReport, jsonReport } = require("./report");
const { AGENTS, getAgent } = require("./parsers");

module.exports = { scan, textReport, jsonReport, AGENTS, getAgent };
