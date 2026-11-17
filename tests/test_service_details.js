// Run the actual frontend handler without a browser, server, or third-party packages.
const assert = require("node:assert/strict");
const fs = require("node:fs");
const path = require("node:path");
const vm = require("node:vm");

const elements = new Map();
const context = vm.createContext({
  document: {
    addEventListener() {},
    getElementById(id) {
      if (!elements.has(id)) elements.set(id, { style: {}, innerHTML: "", textContent: "" });
      return elements.get(id);
    },
  },
  fetch() { throw new Error("Opening details must not make an HTTP request"); },
});
const source = fs.readFileSync(path.join(__dirname, "../frontend/static/app.js"), "utf8");
vm.runInContext(source, context);
vm.runInContext(`
  currentScanId = "synthetic-scan";
  currentServices = [{ip: "192.0.2.10", port: 22, protocol: "tcp", service: "ssh",
    remediation: "Restrict access to authorized clients.", weak_creds: {found: false, status: "not_tested"}}];
  onDetailsClick({target: {getAttribute(name) {
    return {"data-ip": "192.0.2.10", "data-port": "22", "data-proto": "tcp"}[name];
  }}});
`, context);
assert.equal(elements.get("service-details-modal").style.display, "flex");
assert.match(elements.get("modal-body").innerHTML, /Restrict access to authorized clients/);
assert.match(elements.get("modal-body").innerHTML, /Credential testing was not performed/);
assert.doesNotMatch(elements.get("modal-body").innerHTML, /llm-remediation|Generating remediation/);
assert.match(elements.get("modal-body").innerHTML, /Exposure review priority/);
assert.match(elements.get("modal-body").innerHTML, /Vulnerability severity: informational/);
assert.match(elements.get("modal-body").innerHTML, /Original network evidence/);
vm.runInContext(`
  currentServices[0].nvd = {cves: [{id: "SYNTHETIC-CVE", reported_severity: "CRITICAL", reported_cvss: 9.8}]};
  onDetailsClick({target: {getAttribute(name) {
    return {"data-ip": "192.0.2.10", "data-port": "22", "data-proto": "tcp"}[name];
  }}});
`, context);
assert.match(elements.get("modal-body").innerHTML, /unverified keyword candidate/);
assert.match(elements.get("modal-body").innerHTML, /not an asset rating/);
console.log("PASS: service details render local guidance without fetch");
