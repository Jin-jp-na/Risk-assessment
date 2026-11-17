const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const table = {innerHTML: "", appendChild(row) {this.innerHTML += row.innerHTML;}};
const state = {textContent: ""};
let result;
const calls = [];
const context = vm.createContext({
  document: {addEventListener() {}, querySelector() {return table;},
    getElementById() {return state;}, createElement() {return {innerHTML: ""};}},
  localStorage: {setItem() {}},
  async fetch(url) {calls.push(url); return {ok: true, async json() {return result;}};},
});
const source = fs.readFileSync(path.join(__dirname, "../frontend/static/app.js"), "utf8");
vm.runInContext(source, context);
(async () => {
  result = {results: [{path: "/<script>alert(1)</script>", status: 200, size: 10}], discovery_status: "completed"};
  await vm.runInContext('loadGobusterResults("saved")', context);
  assert.match(table.innerHTML, /&lt;script&gt;/);
  assert.doesNotMatch(table.innerHTML, /<script>|critical|vulnerable/);
  assert.match(state.textContent, /completed/);
  result = {results: [], discovery_status: "skipped"};
  await vm.runInContext('loadGobusterResults("saved")', context);
  assert.match(table.innerHTML, /not requested/);
  result = {results: [], discovery_status: "completed"};
  await vm.runInContext('loadGobusterResults("saved")', context);
  assert.match(table.innerHTML, /No paths observed/);
  result = {results: [], discovery_status: "timed_out", partial: true, error: "Discovery timed out"};
  await vm.runInContext('loadGobusterResults("saved")', context);
  assert.match(state.textContent, /incomplete coverage/);
  assert.match(table.innerHTML, /Discovery timed out/);
  assert.ok(calls.every(url => url === "/webscan/saved/results"));
  const html = fs.readFileSync(path.join(__dirname, "../frontend/templates/index.html"), "utf8");
  assert.match(html, /id="path-discovery" type="checkbox" disabled/);
  assert.match(source, /path_discovery: profile === "web" && document.getElementById\("path-discovery"\).checked/);
  console.log("PASS: optional path observations render safely with honest job states");
})().catch(error => {console.error(error); process.exitCode = 1;});
