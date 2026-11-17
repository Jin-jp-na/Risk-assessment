const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const elements = new Map();
const requests = [];
let responseBody, responseOK = true;
function element(id) {
  if (!elements.has(id)) elements.set(id, {value: "", textContent: "", innerHTML: ""});
  return elements.get(id);
}
const context = vm.createContext({
  document: {addEventListener() {}, getElementById: element},
  window: {location: {href: ""}},
  async fetch(url) {requests.push(url); return {ok: responseOK, async json() {return responseBody;}};},
});
const source = fs.readFileSync(path.join(__dirname, "../frontend/static/app.js"), "utf8");
vm.runInContext(source, context);
(async () => {
  await vm.runInContext("compareSelectedScans()", context);
  assert.match(element("comparison-results").textContent, /Select baseline/);
  element("compare-old").value = "baseline";
  element("compare-new").value = "current";
  responseBody = {added: [{component: "http", kind: "security_header", key: "x-content-type-options", before: null, after: "<script>untrusted</script>", reason: "Saved values"}], removed: [], changed: [], uncertain: []};
  await vm.runInContext("compareSelectedScans()", context);
  assert.equal(requests[0], "/scans/current/compare/baseline");
  assert.match(element("comparison-results").innerHTML, /Before/);
  assert.match(element("comparison-results").innerHTML, /After/);
  assert.match(element("comparison-results").innerHTML, /&lt;script&gt;/);
  assert.doesNotMatch(element("comparison-results").innerHTML, /<script>/);
  responseBody = {added: [], removed: [], changed: [], uncertain: []};
  await vm.runInContext("compareSelectedScans()", context);
  assert.match(element("comparison-results").innerHTML, /No comparable exposure changes/);
  responseOK = false; responseBody = {detail: "Saved target identities differ"};
  await vm.runInContext("compareSelectedScans()", context);
  assert.match(element("comparison-results").textContent, /Comparison unavailable: Saved target/);
  vm.runInContext('exportComparison("pdf")', context);
  assert.equal(context.window.location.href, "/scan/current/report.pdf?baseline=baseline");
  const template = fs.readFileSync(path.join(__dirname, "../frontend/templates/index.html"), "utf8");
  assert.match(template, /data-tab="tab-compare"/);
  assert.doesNotMatch(template, /(?:src|href)="https?:\/\//);
  assert.match(source, /network_scan: profile !== "web"/);
  console.log("PASS: comparison selection, escaped before/after, empty/error states and export links");
})().catch(error => {console.error(error); process.exitCode = 1;});
