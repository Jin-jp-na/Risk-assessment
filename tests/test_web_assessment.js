// Render the actual saved-assessment reader without a server or target requests.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");
const container = {innerHTML: "", textContent: ""};
const findingsContainer = {innerHTML: "", textContent: ""};
let data;
const calls = [];
const context = vm.createContext({
  document: {addEventListener() {}, getElementById(id) {return id === "web-findings" ? findingsContainer : container;}},
  async fetch(url) {
    calls.push(url);
    return {ok: true, async json() {return url.endsWith("/findings") ? {findings: [{rule_id: "WEB-TLS-001", title: "TLS certificate verification failed", severity: "low", evidence: "Untrusted <certificate>", remediation: "Keep verification enabled", retest: "Explicitly repeat Web assessment"}]} : data;}};
  },
});
vm.runInContext(fs.readFileSync(path.join(__dirname, "../frontend/static/app.js"), "utf8"), context);
(async () => {
  data = {url: "https://127.0.0.1/", http: {}, tls: {verification: "failed"}, checks: [],
    error_category: "certificate_verification_failed", error: "Untrusted <certificate>"};
  await vm.runInContext('loadWebAssessment("saved")', context);
  assert.match(container.innerHTML, /Unavailable/);
  assert.match(container.innerHTML, /certificate_verification_failed/);
  assert.match(container.innerHTML, /Untrusted &lt;certificate&gt;/);
  assert.doesNotMatch(container.innerHTML, /Not HTTPS/);
  assert.match(findingsContainer.innerHTML, /WEB-TLS-001/);
  assert.match(findingsContainer.innerHTML, /Keep verification enabled/);
  assert.match(findingsContainer.innerHTML, /Re-test: Explicitly repeat Web assessment/);
  data = {url: "http://127.0.0.1/", http: {status: 302, headers: {location: "http://outside.example/"}},
    tls: {verification: "not_applicable"}, checks: [], redirects: [{followed: false, decision: "blocked"}]};
  await vm.runInContext('loadWebAssessment("saved")', context);
  assert.match(container.innerHTML, /302/);
  assert.match(container.innerHTML, /blocked/);
  assert.match(container.innerHTML, /Configuration observations/);
  assert.deepEqual(calls, ["/webscan/saved/assessment", "/webscan/saved/findings", "/webscan/saved/assessment", "/webscan/saved/findings"]);
  console.log("PASS: saved web evidence and HTTPS failures render truthfully");
})().catch(error => {console.error(error); process.exitCode = 1;});
