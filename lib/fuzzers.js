/**
 * Big Bounty — Fuzzing & API Discovery Suite
 * Native implementation of:
 * 1. Burp Suite Intruder — fuzz path segments (e.g. 101/topa, /101, /topa, id/token) with controlled payload wordlist
 * 2. ffuf — high-throughput automated path/segment discovery with baseline calibration (words, lines, byte-length filters)
 * 3. Kiterunner — API route and spec discovery (Kite/routes discovery: OpenAPI, Swagger, GraphQL, /api/v1/v2/v3, actuator, rpc, prefixes)
 * 4. OWASP ZAP Fuzzer — multi-vector fuzzer against parameters, headers, and endpoints for anomalies, error disclosures, and bypasses
 * 5. Burp Repeater — automated diff engine that compares responses between baseline and probe payloads, analyzing status, length, headers, and reflections
 */

'use strict';

const { runBurpIntruder: runIntruderInternal } = require('./burp-intruder');
const { runFfuf } = require('./ffuf');
const { runKiterunner: runKiterunnerInternal } = require('./kiterunner');
const { runZapFuzzer: runZapFuzzerInternal } = require('./zap-fuzzer');
const { runBurpRepeater: runBurpRepeaterInternal } = require('./burp-repeater');

// Adapter functions to ensure consistent array return for scanner.js
async function runBurpIntruder(opts) {
  const res = await runIntruderInternal(opts);
  return res && Array.isArray(res.findings) ? res.findings : (Array.isArray(res) ? res : []);
}

async function runFfufDiscovery(opts) {
  const res = await runFfuf(opts);
  return res && Array.isArray(res.findings) ? res.findings : (Array.isArray(res) ? res : []);
}

async function runKiterunner(opts) {
  const res = await runKiterunnerInternal(opts);
  return res && Array.isArray(res.findings) ? res.findings : (Array.isArray(res) ? res : []);
}

async function runZapFuzzer(opts) {
  const res = await runZapFuzzerInternal(opts);
  return res && Array.isArray(res.findings) ? res.findings : (Array.isArray(res) ? res : []);
}

async function runBurpRepeater(opts) {
  const res = await runBurpRepeaterInternal(opts);
  return res && Array.isArray(res.findings) ? res.findings : (Array.isArray(res) ? res : []);
}

module.exports = {
  runBurpIntruder,
  runFfufDiscovery,
  runKiterunner,
  runZapFuzzer,
  runBurpRepeater,
};
