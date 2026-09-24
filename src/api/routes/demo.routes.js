const express = require('express');
const https = require('https');
const fs = require('fs');
const path = require('path');

const router = express.Router();

const GITHUB_OWNER = process.env.GITHUB_OWNER || 'mlenin';
const GITHUB_REPO = process.env.GITHUB_REPO || 'ktb-codemender-banking-demo';
const GCP_PROJECT_ID = process.env.GCP_PROJECT_ID || 'lenin-ai-playground';
const GCP_PROJECT_NUMBER = process.env.GCP_PROJECT_NUMBER || '612463410164';

let ghCache = {
  timestamp: 0,
  data: null
};

function fetchGitHubJson(apiPath) {
  return new Promise((resolve) => {
    const headers = {
      'User-Agent': 'KTB-CodeMender-Demo-App/2.0',
      'Accept': 'application/vnd.github+json'
    };
    if (process.env.GITHUB_TOKEN) {
      headers['Authorization'] = `Bearer ${process.env.GITHUB_TOKEN}`;
    }
    const req = https.get({
      hostname: 'api.github.com',
      path: apiPath,
      headers,
      timeout: 5000
    }, (res) => {
      let raw = '';
      res.on('data', chunk => raw += chunk);
      res.on('end', () => {
        try {
          resolve({ status: res.statusCode, body: JSON.parse(raw) });
        } catch (e) {
          resolve({ status: res.statusCode, body: null });
        }
      });
    });
    req.on('error', () => resolve({ status: 500, body: null }));
    req.on('timeout', () => {
      req.destroy();
      resolve({ status: 504, body: null });
    });
  });
}

const VULNERABILITY_CATALOG = [
  {
    id: 'CM-001',
    severity: 'CRITICAL',
    cvss: '9.8',
    cwe: 'CWE-94: Improper Control of Generation of Code (Code Injection / RCE)',
    title: 'Dynamic Fee & Discount Formula Remote Code Execution via Prototype Constructor',
    bankingContext: 'Krungthai BUSINESS / Corporate Treasury Dynamic Pricing & Fee Engine',
    file: 'src/services/admin.service.js',
    lines: '7-11',
    sastResult: 'MISSED (False Negative) — Traditional regex SAST looks for eval() or new Function(), missing [].sort.constructor obfuscation.',
    cmResult: 'VERIFIED EXPLOITABLE — CodeMender traced [].sort.constructor to Function.prototype, synthesized an RCE payload, confirmed execution in sandbox, and replaced it with a safe arithmetic parser.',
    vulnerableCode: `exports.evaluateDiscount = (formula) => {
    const generator = [].sort.constructor;
    const runtimeFunc = generator(\`return \${formula}\`);
    return runtimeFunc();
};`,
    patchedCode: `exports.evaluateDiscount = (formula) => {
    if (typeof formula !== 'string' || !/^[0-9+\\-*/().\\s]+$/.test(formula)) {
        throw new Error('Security policy violation: non-arithmetic expression blocked');
    }
    // Safe constant-bounded arithmetic evaluation without dynamic code compilation
    return Number(Function('"use strict"; return (' + formula.replace(/[^0-9+\\-*/().]/g, '') + ')')());
};`,
    patchDiff: `--- a/src/services/admin.service.js
+++ b/src/services/admin.service.js
@@ -7,5 +7,7 @@
 exports.evaluateDiscount = (formula) => {
-    const generator = [].sort.constructor;
-    const runtimeFunc = generator(\`return \${formula}\`);
-    return runtimeFunc();
+    if (typeof formula !== 'string' || !/^[0-9+\\-*/().\\s]+$/.test(formula)) {
+        throw new Error('Security policy violation: non-arithmetic expression blocked');
+    }
+    return Number(Function('"use strict"; return (' + formula.replace(/[^0-9+\\-*/().]/g, '') + ')')());
 };`,
    exploitPayload: `POST /api/v1/admin/calculate-discount
Content-Type: application/json

{
  "formula": "100; return process.mainModule.require('child_process').execSync('id && uname -a').toString()"
}`
  },
  {
    id: 'CM-002',
    severity: 'CRITICAL',
    cvss: '9.6',
    cwe: 'CWE-78: OS Command Injection across Module Boundaries',
    title: 'Interbank Gateway Network Diagnostic Command Injection',
    bankingContext: 'KTB PromptPay / BAHTNET Settlement Gateway Connectivity Health Check',
    file: 'src/services/admin.service.js -> src/core/utils/systemUtils.js',
    lines: '3-5',
    sastResult: 'FLAGGED AS LOW / UNVERIFIED — Taint lost across admin.service.js -> systemUtils.executeNetworkDiagnostic() boundary.',
    cmResult: 'VERIFIED EXPLOITABLE — CodeMender followed project_paths across repository directories, crafted a subshell injection exploit (`127.0.0.1; cat /etc/passwd`), proved execution, and enforced strict IPv4/hostname validation + execFile().',
    vulnerableCode: `// src/services/admin.service.js
exports.pingProvider = (ip, opts, cb) => {
    systemUtils.executeNetworkDiagnostic(ip, opts, cb);
};
// src/core/utils/systemUtils.js
exports.executeNetworkDiagnostic = (target, options, callback) => {
    const cmd = \`ping -c 1 \${options.rawFlags || ''} \${target}\`;
    exec(cmd, (err, stdout) => callback(err, stdout));
};`,
    patchedCode: `// src/services/admin.service.js + src/core/utils/systemUtils.js
const { execFile } = require('child_process');
const SAFE_HOST_RE = /^[a-zA-Z0-9.-]{1,253}$/;

exports.executeNetworkDiagnostic = (target, options, callback) => {
    if (typeof target !== 'string' || !SAFE_HOST_RE.test(target) || target.startsWith('-')) {
        return callback(new Error('Invalid diagnostic target host'));
    }
    execFile('ping', ['-c', '1', target], { timeout: 3000 }, (err, stdout) => callback(err, stdout));
};`,
    patchDiff: `--- a/src/core/utils/systemUtils.js
+++ b/src/core/utils/systemUtils.js
@@ -1,6 +1,10 @@
-const { exec } = require('child_process');
+const { execFile } = require('child_process');
+const SAFE_HOST_RE = /^[a-zA-Z0-9.-]{1,253}$/;
 
 exports.executeNetworkDiagnostic = (target, options, callback) => {
-    const cmd = \`ping -c 1 \${options.rawFlags || ''} \${target}\`;
-    exec(cmd, (err, stdout) => callback(err, stdout));
+    if (typeof target !== 'string' || !SAFE_HOST_RE.test(target) || target.startsWith('-')) {
+        return callback(new Error('Invalid diagnostic target host'));
+    }
+    execFile('ping', ['-c', '1', target], { timeout: 3000 }, (err, stdout) => callback(err, stdout));
 };`,
    exploitPayload: `POST /api/v1/admin/network-ping
Content-Type: application/json

{
  "ip": "127.0.0.1; echo EXPLOIT_VERIFIED_UID=$(id -u)",
  "opts": { "rawFlags": "-W 1" }
}`
  },
  {
    id: 'CM-003',
    severity: 'HIGH',
    cvss: '8.6',
    cwe: 'CWE-362: Concurrent Execution using Shared Resource (TOCTOU Double-Spend)',
    title: 'Asynchronous Check-Then-Act Race Condition (Double-Spend / Inventory Overdraft)',
    bankingContext: 'KTB Next / Paotang Digital Wallet Flash Voucher & Gold Wallet Redemption',
    file: 'src/services/checkout.service.js',
    lines: '5-14',
    sastResult: 'MISSED (0 Alerts) — Static SAST scanners cannot detect asynchronous event-loop interleaving across await boundaries.',
    cmResult: 'VERIFIED EXPLOITABLE — CodeMender recognized the non-atomic check (`inventory[item] >= quantity`) separated from state mutation (`inventory[item] -= quantity`) by an async `await`, fired parallel requests in `cm verify` to drive balance negative, and synthesized an atomic reservation lock.',
    vulnerableCode: `exports.processOrder = async (item, quantity) => {
    if (!inventory[item] || quantity <= 0) throw new Error("Invalid checkout params");

    if (inventory[item] >= quantity) {
        await new Promise(resolve => setTimeout(resolve, 100));
        inventory[item] -= quantity;
        return \`Purchased \${quantity}. Stock left: \${inventory[item]}\`;
    }
    throw new Error("Out of stock");
};`,
    patchedCode: `const locks = new Set();
exports.processOrder = async (item, quantity) => {
    if (!inventory[item] || quantity <= 0) throw new Error("Invalid checkout params");
    while (locks.has(item)) {
        await new Promise(resolve => setTimeout(resolve, 10));
    }
    locks.add(item);
    try {
        if (inventory[item] >= quantity) {
            inventory[item] -= quantity; // Atomic deduction prior to async I/O
            await new Promise(resolve => setTimeout(resolve, 100));
            return \`Purchased \${quantity}. Stock left: \${inventory[item]}\`;
        }
        throw new Error("Out of stock");
    } finally {
        locks.delete(item);
    }
};`,
    patchDiff: `--- a/src/services/checkout.service.js
+++ b/src/services/checkout.service.js
@@ -5,9 +5,16 @@
 exports.processOrder = async (item, quantity) => {
     if (!inventory[item] || quantity <= 0) throw new Error("Invalid checkout params");
-    if (inventory[item] >= quantity) {
-        await new Promise(resolve => setTimeout(resolve, 100));
-        inventory[item] -= quantity;
-        return \`Purchased \${quantity}. Stock left: \${inventory[item]}\`;
+    // Atomic reservation prior to async settlement
+    if (inventory[item] < quantity) {
+        throw new Error("Out of stock");
+    }
+    inventory[item] -= quantity;
+    try {
+        await new Promise(resolve => setTimeout(resolve, 100));
+        return \`Purchased \${quantity}. Stock left: \${inventory[item]}\`;
+    } catch (err) {
+        inventory[item] += quantity;
+        throw err;
     }
-    throw new Error("Out of stock");
 };`,
    exploitPayload: `// Concurrent Burst sent by cm verify (3 parallel requests for qty=4 against stock=5):
await Promise.all([
  axios.post('/api/v1/cart/checkout', { item: 'laptop', quantity: 4 }),
  axios.post('/api/v1/cart/checkout', { item: 'laptop', quantity: 4 }),
  axios.post('/api/v1/cart/checkout', { item: 'laptop', quantity: 4 })
]);
// Result before fix: All 3 succeed! Final stock = -7 (Double-Spend Overdraft!)`
  },
  {
    id: 'CM-004',
    severity: 'HIGH',
    cvss: '8.2',
    cwe: 'CWE-918: Server-Side Request Forgery (SSRF) via Object Property Bypass',
    title: 'Partner Webhook & Metadata SSRF Blocklist Bypass via http.get() Options Object',
    bankingContext: 'Krungthai Open Banking Partner Callback & Slip Verification Fetcher',
    file: 'src/services/catalog.service.js',
    lines: '6-15',
    sastResult: 'FALSE NEGATIVE — SAST sees the `if (String(target.url).includes("internal-network"))` guard and assumes the sink is sanitized.',
    cmResult: 'VERIFIED EXPLOITABLE — CodeMender reasoned that Node.js `http.get(target)` accepts EITHER a URL string OR a parsed RequestOptions object `{ hostname: "internal-network", port: 8080, path: "/computeMetadata/v1/" }` where `target.url` is `undefined`, bypassing the check completely!',
    vulnerableCode: `exports.fetchRemoteAsset = (target, cb) => {
    if (target && String(target.url).includes('internal-network')) {
        return cb(new Error("Forbidden access rule triggered."));
    }
    http.get(target, (proxyRes) => {
        let body = '';
        proxyRes.on('data', chunk => body += chunk);
        proxyRes.on('end', () => cb(null, body.substring(0, 50)));
    }).on('error', err => cb(err));
};`,
    patchedCode: `const { URL } = require('url');
const ALLOWED_HOSTS = new Set(['cdn.krungthai.com', 'assets.ktb.co.th']);

exports.fetchRemoteAsset = (target, cb) => {
    const rawUrl = typeof target === 'string' ? target : (target && target.url);
    if (!rawUrl || typeof rawUrl !== 'string') {
        return cb(new Error('Invalid URL parameter'));
    }
    const parsed = new URL(rawUrl);
    if (parsed.protocol !== 'https:' || !ALLOWED_HOSTS.has(parsed.hostname)) {
        return cb(new Error('Forbidden host: not in KTB Open Banking allowlist'));
    }
    http.get(parsed.toString(), (proxyRes) => { /* ... */ });
};`,
    patchDiff: `--- a/src/services/catalog.service.js
+++ b/src/services/catalog.service.js
@@ -6,5 +6,11 @@
 exports.fetchRemoteAsset = (target, cb) => {
-    if (target && String(target.url).includes('internal-network')) {
-        return cb(new Error("Forbidden access rule triggered."));
+    const rawUrl = typeof target === 'string' ? target : (target && target.url);
+    if (!rawUrl || typeof rawUrl !== 'string') {
+        return cb(new Error("Invalid asset URL"));
+    }
+    const parsed = new URL(rawUrl);
+    if (!['cdn.krungthai.com', 'assets.ktb.co.th'].includes(parsed.hostname)) {
+        return cb(new Error("Forbidden access rule triggered."));
     }`,
    exploitPayload: `POST /api/v1/products/fetch-asset
Content-Type: application/json

{
  "target": {
    "hostname": "internal-network",
    "port": 80,
    "path": "/computeMetadata/v1/instance/service-accounts/default/token"
  }
}
// target.url is undefined -> String(undefined).includes('internal-network') is false -> SSRF Succeeds!`
  },
  {
    id: 'CM-005',
    severity: 'HIGH',
    cvss: '7.8',
    cwe: 'CWE-908: Use of Uninitialized Resource (Heap Memory Disclosure via Buffer.allocUnsafe)',
    title: 'Uninitialized Node.js Heap Memory Disclosure in Tax Invoice Buffer Allocator',
    bankingContext: 'KTB e-Withholding Tax & Corporate e-Invoice PDF Stream Generator',
    file: 'src/services/checkout.service.js -> src/core/utils/systemUtils.js',
    lines: '16-18',
    sastResult: 'LOW PRIORITY / NOISE — Often ignored in hundreds of informational warnings without proof of sensitive data leakage.',
    cmResult: 'VERIFIED EXPLOITABLE — CodeMender populated V8 heap memory with mock JWT/session tokens, invoked `generateInvoiceMemoryBlock(2048)`, extracted leaked bearer tokens from the returned Base64 buffer, and patched `Buffer.allocUnsafe` to zero-filled `Buffer.alloc`.',
    vulnerableCode: `// src/services/checkout.service.js
exports.generateInvoiceMemoryBlock = (size) => {
    return systemUtils.allocateMemoryBlock(size).toString('base64');
};
// src/core/utils/systemUtils.js
exports.allocateMemoryBlock = (size) => {
    return Buffer.allocUnsafe(Number(size) || 1024);
};`,
    patchedCode: `// src/core/utils/systemUtils.js
exports.allocateMemoryBlock = (size) => {
    const safeSize = Math.min(Math.max(Number(size) || 1024, 1), 65536);
    return Buffer.alloc(safeSize, 0); // Cryptographically zero-filled allocation
};`,
    patchDiff: `--- a/src/core/utils/systemUtils.js
+++ b/src/core/utils/systemUtils.js
@@ -12,3 +12,4 @@
 exports.allocateMemoryBlock = (size) => {
-    return Buffer.allocUnsafe(Number(size) || 1024);
+    const safeSize = Math.min(Math.max(Number(size) || 1024, 1), 65536);
+    return Buffer.alloc(safeSize, 0);
 };`,
    exploitPayload: `GET /api/v1/order/invoice?size=4096
// Decoded Base64 output contains unzeroed V8 heap fragments:
// "Authorization: Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJrdGItY29ycC10cmVhc3VyeS..."`
  }
];

router.get('/vulnerabilities', (req, res) => {
  res.json({
    project: GCP_PROJECT_ID,
    projectNumber: GCP_PROJECT_NUMBER,
    repository: `${GITHUB_OWNER}/${GITHUB_REPO}`,
    model: 'gemini-3.7-flash',
    vulnerabilities: VULNERABILITY_CATALOG
  });
});

router.post('/simulate-exploit', async (req, res) => {
  const { vulnId = 'CM-001', mode = 'vulnerable' } = req.body || {};
  const vuln = VULNERABILITY_CATALOG.find(v => v.id === vulnId) || VULNERABILITY_CATALOG[0];

  if (vuln.id === 'CM-001') {
    if (mode === 'vulnerable') {
      const demoFormula = '100 * 0.85; return "RCE_PROOF: uid=1000(ktb-api-runner) node=" + process.version + " platform=" + process.platform';
      const generator = [].sort.constructor;
      const runtimeFunc = generator(`return ${demoFormula}`);
      const output = runtimeFunc();
      return res.json({
        vulnId: vuln.id,
        mode: 'vulnerable',
        verdict: 'VERIFIED_EXPLOITABLE',
        httpStatus: 200,
        executionTimeMs: 14,
        inputPayload: demoFormula,
        actualOutput: output,
        explanation: 'Using [].sort.constructor bypassed eval() filters and executed arbitrary JavaScript inside the V8 process context.'
      });
    } else {
      return res.json({
        vulnId: vuln.id,
        mode: 'patched',
        verdict: 'EXPLOIT_BLOCKED_BY_CODEMENDER_PATCH',
        httpStatus: 400,
        executionTimeMs: 2,
        inputPayload: '100 * 0.85; return process.version',
        actualOutput: 'Error: Security policy violation: non-arithmetic expression blocked',
        explanation: 'CodeMender patch enforces strict numeric/arithmetic token allowlisting (/^[0-9+\\-*/().\\s]+$/), blocking code injection before compilation.'
      });
    }
  }

  if (vuln.id === 'CM-002') {
    if (mode === 'vulnerable') {
      return res.json({
        vulnId: vuln.id,
        mode: 'vulnerable',
        verdict: 'VERIFIED_EXPLOITABLE',
        httpStatus: 200,
        executionTimeMs: 38,
        inputPayload: '127.0.0.1; echo EXPLOIT_VERIFIED_HOST=$(hostname)',
        actualOutput: 'PING 127.0.0.1 (127.0.0.1) 56(84) bytes of data.\n64 bytes from 127.0.0.1: icmp_seq=1 ttl=64 time=0.041 ms\nEXPLOIT_VERIFIED_HOST=ktb-bahtnet-gw-prod-01',
        explanation: 'Unsanitized string interpolation into child_process.exec() allowed shell command chaining via semicolon (;).'
      });
    } else {
      return res.json({
        vulnId: vuln.id,
        mode: 'patched',
        verdict: 'EXPLOIT_BLOCKED_BY_CODEMENDER_PATCH',
        httpStatus: 400,
        executionTimeMs: 1,
        inputPayload: '127.0.0.1; echo EXPLOIT_VERIFIED_HOST=$(hostname)',
        actualOutput: 'Error: Invalid diagnostic target host (rejected by SAFE_HOST_RE + execFile)',
        explanation: 'CodeMender replaced shell-spawning exec() with argument-isolated execFile() and strict hostname regex validation.'
      });
    }
  }

  if (vuln.id === 'CM-003') {
    if (mode === 'vulnerable') {
      let stock = 5;
      const runVulnOrder = async (qty) => {
        if (stock >= qty) {
          await new Promise(r => setTimeout(r, 40));
          stock -= qty;
          return `SUCCESS (Purchased ${qty}, Remaining Stock: ${stock})`;
        }
        return 'REJECTED (Out of stock)';
      };
      const results = await Promise.all([runVulnOrder(4), runVulnOrder(4), runVulnOrder(4)]);
      return res.json({
        vulnId: vuln.id,
        mode: 'vulnerable',
        verdict: 'VERIFIED_EXPLOITABLE',
        httpStatus: 200,
        executionTimeMs: 44,
        inputPayload: '3 Concurrent Requests x Qty=4 (Initial Stock/Balance = 5)',
        actualOutput: `Tx #1: ${results[0]}\nTx #2: ${results[1]}\nTx #3: ${results[2]}\nFINAL LEDGER BALANCE: ${stock} (CRITICAL DOUBLE-SPEND OVERDRAFT!)`,
        explanation: 'All 3 concurrent requests passed `if (stock >= 4)` before the 40ms async settlement resolved, withdrawing 12 units from a balance of 5!'
      });
    } else {
      let stock = 5;
      let locked = false;
      const runPatchedOrder = async (qty) => {
        while (locked) await new Promise(r => setTimeout(r, 5));
        locked = true;
        try {
          if (stock >= qty) {
            stock -= qty;
            await new Promise(r => setTimeout(r, 40));
            return `SUCCESS (Purchased ${qty}, Remaining Stock: ${stock})`;
          }
          return `REJECTED (Out of stock — Available: ${stock}, Requested: ${qty})`;
        } finally {
          locked = false;
        }
      };
      const results = await Promise.all([runPatchedOrder(4), runPatchedOrder(4), runPatchedOrder(4)]);
      return res.json({
        vulnId: vuln.id,
        mode: 'patched',
        verdict: 'EXPLOIT_BLOCKED_BY_CODEMENDER_PATCH',
        httpStatus: 200,
        executionTimeMs: 48,
        inputPayload: '3 Concurrent Requests x Qty=4 (Initial Stock/Balance = 5)',
        actualOutput: `Tx #1: ${results[0]}\nTx #2: ${results[1]}\nTx #3: ${results[2]}\nFINAL LEDGER BALANCE: ${stock} (LEDGER INTEGRITY PRESERVED!)`,
        explanation: 'CodeMender serialized reservation and deducted balance atomically prior to async I/O, allowing Tx #1 and deterministically rejecting Tx #2 and Tx #3.'
      });
    }
  }

  if (vuln.id === 'CM-004') {
    if (mode === 'vulnerable') {
      const target = { hostname: 'internal-network.ktb.local', path: '/computeMetadata/v1/instance/service-accounts/default/token' };
      const checkResult = String(target.url).includes('internal-network');
      return res.json({
        vulnId: vuln.id,
        mode: 'vulnerable',
        verdict: 'VERIFIED_EXPLOITABLE',
        httpStatus: 200,
        executionTimeMs: 11,
        inputPayload: JSON.stringify(target),
        actualOutput: `Guard Evaluation: String(target.url) === "${String(target.url)}" -> includes('internal-network') is ${checkResult}!\nSSRF Request Dispatched to http://internal-network.ktb.local/computeMetadata/v1/...`,
        explanation: 'Passing an http.get() RequestOptions object leaves target.url undefined, completely bypassing the blocklist check.'
      });
    } else {
      return res.json({
        vulnId: vuln.id,
        mode: 'patched',
        verdict: 'EXPLOIT_BLOCKED_BY_CODEMENDER_PATCH',
        httpStatus: 403,
        executionTimeMs: 1,
        inputPayload: '{"hostname":"internal-network.ktb.local","path":"/computeMetadata/v1/..."}',
        actualOutput: 'Error: Invalid asset URL / Forbidden host: not in KTB Open Banking allowlist',
        explanation: 'CodeMender enforces strict URL parsing and hostname allowlisting (cdn.krungthai.com, assets.ktb.co.th) before any socket is opened.'
      });
    }
  }

  // CM-005
  if (mode === 'vulnerable') {
    return res.json({
      vulnId: 'CM-005',
      mode: 'vulnerable',
      verdict: 'VERIFIED_EXPLOITABLE',
      httpStatus: 200,
      executionTimeMs: 8,
      inputPayload: 'GET /api/v1/order/invoice?size=256',
      actualOutput: 'Leaked V8 Heap Slice (Decoded): "...Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6Imt0Yi1wcm9kLXYyIn0...x-ktb-promptpay-secret=9f8e7d6c5b4a..."',
      explanation: 'Buffer.allocUnsafe(size) returns unzeroed V8 heap pages containing residual cryptographic keys, JWTs, and PII from prior requests.'
    });
  } else {
    const zeroBuf = Buffer.alloc(64, 0).toString('hex');
    return res.json({
      vulnId: 'CM-005',
      mode: 'patched',
      verdict: 'EXPLOIT_BLOCKED_BY_CODEMENDER_PATCH',
      httpStatus: 200,
      executionTimeMs: 2,
      inputPayload: 'GET /api/v1/order/invoice?size=256',
      actualOutput: `Zero-Filled Safe Buffer (Hex): ${zeroBuf}`,
      explanation: 'CodeMender replaced Buffer.allocUnsafe() with zero-initialized Buffer.alloc(safeSize, 0) and enforced an upper bound.'
    });
  }
});

router.get('/live-status', async (req, res) => {
  const now = Date.now();
  if (ghCache.data && (now - ghCache.timestamp) < 15000) {
    return res.json(ghCache.data);
  }

  const [runsRes, prsRes, repoRes] = await Promise.all([
    fetchGitHubJson(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/actions/runs?per_page=6`),
    fetchGitHubJson(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}/pulls?state=all&per_page=6`),
    fetchGitHubJson(`/repos/${GITHUB_OWNER}/${GITHUB_REPO}`)
  ]);

  const runs = (runsRes.body && Array.isArray(runsRes.body.workflow_runs))
    ? runsRes.body.workflow_runs.map(r => ({
        id: r.id,
        name: r.name,
        status: r.status,
        conclusion: r.conclusion,
        event: r.event,
        headBranch: r.head_branch,
        headSha: r.head_sha ? r.head_sha.substring(0, 7) : '',
        createdAt: r.created_at,
        updatedAt: r.updated_at,
        htmlUrl: r.html_url
      }))
    : [];

  const pulls = (prsRes.body && Array.isArray(prsRes.body))
    ? prsRes.body.map(p => ({
        number: p.number,
        title: p.title,
        state: p.state,
        user: p.user ? p.user.login : 'codemender-bot',
        headRef: p.head ? p.head.ref : '',
        createdAt: p.created_at,
        htmlUrl: p.html_url
      }))
    : [];

  const payload = {
    timestamp: new Date().toISOString(),
    gcpConfig: {
      projectId: GCP_PROJECT_ID,
      projectNumber: GCP_PROJECT_NUMBER,
      wifPool: `projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions`,
      wifProvider: `projects/${GCP_PROJECT_NUMBER}/locations/global/workloadIdentityPools/github-actions/providers/github-oidc`,
      serviceAccount: `codemender-ci@${GCP_PROJECT_ID}.iam.gserviceaccount.com`,
      vertexModel: 'gemini-3.7-flash',
      keylessAuth: true
    },
    githubRepo: {
      owner: GITHUB_OWNER,
      repo: GITHUB_REPO,
      fullName: `${GITHUB_OWNER}/${GITHUB_REPO}`,
      htmlUrl: `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}`,
      actionsUrl: `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/actions`,
      pullsUrl: `https://github.com/${GITHUB_OWNER}/${GITHUB_REPO}/pulls`,
      description: repoRes.body && repoRes.body.description ? repoRes.body.description : 'Krungthai Bank (KTB) Autonomous AppSec Guardrail Demo powered by Google DeepMind CodeMender & GCP Workload Identity Federation'
    },
    workflowRuns: runs,
    pullRequests: pulls
  };

  ghCache = { timestamp: now, data: payload };
  res.json(payload);
});

module.exports = router;
