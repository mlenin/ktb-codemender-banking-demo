# Krungthai Bank (KTB) × Google DeepMind CodeMender — Autonomous AppSec & Keyless WIF CI/CD Demo

> **🌐 Live Deployed KTB CodeMender Demo Portal (Cloud Run in `lenin-ai-playground`):**  
> **https://ktb-codemender-demo-612463410164.us-central1.run.app**  
> **⚙️ Live CodeMender WIF CI/CD Guardrail Runs:**  
> **https://github.com/mlenin/ktb-codemender-banking-demo/actions**

An executive and technical demonstration of **Google DeepMind CodeMender (`cm`)** built for **Krungthai Bank Public Company Limited (KTB) — Thailand**, running on the Google Cloud Argolis project **`lenin-ai-playground` (`612463410164`)** using **100% Keyless Workload Identity Federation (WIF)**.

---

## 1. Business Value for Krungthai Bank (KTB Next, Paotang, Krungthai BUSINESS, PromptPay)

| Dimension | Legacy Static SAST | Google DeepMind CodeMender (`cm`) |
| :--- | :--- | :--- |
| **False-Positive Rate** | **68%–82% False Positives** (requires manual triage) | **0% False Positives** (`cm verify` synthesizes & runs a live PoC exploit in an isolated sandbox to mathematically prove exploitability) |
| **Multi-Hop & Async Logic Bugs** | Misses prototype obfuscation (`[].sort.constructor`), TOCTOU double-spend race conditions, and object-type SSRF bypasses | **Traces Cross-File Call Graphs & Event-Loop State** using `gemini-3.7-flash` on Vertex AI |
| **Mean Time to Remediate (MTTR)** | **14–30 Days** of manual engineering patches | **~4.5 Minutes** (`cm fix` authors the minimal root-cause patch, re-runs the exploit to prove it is blocked, and opens an automated Pull Request) |
| **CI/CD Cloud Security (BoT Alignment)** | Long-lived service account keys stored in CI secrets | **100% Keyless OIDC Exchange** via GCP Workload Identity Federation (`id-token: write` $\to$ `github-actions/github-oidc`) |

---

## 2. Architecture & Workload Identity Federation (`codemender-wif-setup`)

```
GitHub Actions Push / Dispatch (mlenin/ktb-codemender-banking-demo)
   │
   ├── 1. Keyless OIDC Token Exchange (google-github-actions/auth@v2)
   │      ├── WIF Provider : projects/612463410164/locations/global/workloadIdentityPools/github-actions/providers/github-oidc
   │      ├── Service Acct : codemender-ci@lenin-ai-playground.iam.gserviceaccount.com
   │      └── Quota Project: lenin-ai-playground
   │
   ├── 2. Initialize CodeMender Sandbox (cm init | project_paths + vcs.type=git)
   │
   ├── 3. Deep Semantic Scan (cm find "src/services" -y --model gemini-3.7-flash)
   │
   ├── 4. Triage & Autonomous Exploit Verification (cm verify "$FID" -y --bypass-warning --model gemini-3.7-flash)
   │      └── Generates & executes real PoC exploit in .exploit/ -> Verifies True Positive!
   │
   ├── 5. Autonomous Remediation (cm fix "$FID" -y --bypass-warning --model gemini-3.7-flash)
   │      └── Patches vulnerable file, re-runs exploit to verify remediation, commits to codemender/auto-remediation
   │
   └── 6. Opens Pull Request + Uploads Visual HTML Report Artifact + Enforces CI/CD Security Gate
```

---

## 3. Repeatable Demo Guide (How to Replay Anytime for KTB)

### Option A: 1-Click Reset & Replay via GitHub Actions UI
1. Open **[Actions -> Reset & Replay KTB CodeMender Demo](https://github.com/mlenin/ktb-codemender-banking-demo/actions/workflows/reset-demo.yml)**.
2. Click **Run workflow** (with `trigger_codemender_scan = true`).
3. This automatically closes any previous remediation PRs, restores `src/services/` from the golden vulnerable baseline (`lab/baseline-services/`), and launches a fresh `CodeMender CI/CD Guardrail` run!

### Option B: 1-Command CLI Reset & Replay
```bash
gh workflow run reset-demo.yml -R mlenin/ktb-codemender-banking-demo -f trigger_codemender_scan=true
```
