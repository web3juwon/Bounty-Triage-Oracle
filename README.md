# BountyTriageOracle: Automated Vulnerability Assessment & Security Oracle

`BountyTriageOracle` is an Intelligent Contract designed for GenLayer that automates bug bounty assessments and vulnerability severity triaging for Web3 protocols.

## 🚀 Key Features
- **Robust URL Sanitization:** Automatically cleans raw GitHub URL inputs by removing markdown brackets, quotes, backticks, or trailing characters.
- **Full Dual-Metric Consensus Verification:** Validators independently verify and reach consensus on **both** the security severity tier (`CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, or `INVALID`) and the corresponding reward multiplier to eliminate independent leader bias.
- **Immutable Audit Trail:** Stores structured severity scores, verified reward percentages, and AI auditor reasoning directly on-chain.

---

##  Testing in GenLayer Studio

### 1. Submit Vulnerability
Call `submit_vulnerability` with a valid GitHub PR link and description:
- **github_url:** `https://github.com/ethereum/solidity/pull/14500`
- **description:** `Potential reentrancy vulnerability in withdrawal logic allowing double-spending.`

### 2. Evaluate Vulnerability
Call `evaluate_vulnerability` with:
- **report_id:** `0`

### 3. Check Results
Call `get_report` with **report_id: `0`** to view the finalized consensus severity, verified reward multiplier, and AI reasoning.
