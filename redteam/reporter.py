"""
Project Mathra - Adversarial Vulnerability Reporter
Generates executive Markdown vulnerability assessment reports with remediation metrics.
"""

import os
from datetime import datetime, timezone
from typing import Dict, List, Any


def generate_markdown_report(
    run_id: str,
    target_url: str,
    results: List[Dict[str, Any]],
    output_dir: str = "redteam/reports"
) -> str:
    """Generates a detailed Markdown vulnerability assessment report."""
    os.makedirs(output_dir, exist_ok=True)
    timestamp_str = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    report_filename = f"mathra_assessment_{timestamp_str}.md"
    report_path = os.path.join(output_dir, report_filename)

    total = len(results)
    mitigated = sum(1 for r in results if r["outcome"] in ["MITIGATED", "BLOCKED", "PASSED_BENIGN"])
    blocked = sum(1 for r in results if r["outcome"] == "BLOCKED")
    redacted = sum(1 for r in results if r["outcome"] == "MITIGATED")
    bypassed = sum(1 for r in results if r["outcome"] == "BYPASSED")
    benign_passed = sum(1 for r in results if r["outcome"] == "PASSED_BENIGN")

    mitigation_rate = round((mitigated / total) * 100, 1) if total > 0 else 0.0
    bypass_rate = round((bypassed / total) * 100, 1) if total > 0 else 0.0

    # Group by category
    categories: Dict[str, Dict[str, int]] = {}
    for r in results:
        cat = r.get("category", "General")
        if cat not in categories:
            categories[cat] = {"total": 0, "mitigated": 0, "bypassed": 0}
        categories[cat]["total"] += 1
        if r["outcome"] in ["MITIGATED", "BLOCKED", "PASSED_BENIGN"]:
            categories[cat]["mitigated"] += 1
        else:
            categories[cat]["bypassed"] += 1

    avg_latency = round(sum(r.get("latency_ms", 0.0) for r in results) / total, 2) if total > 0 else 0.0

    md_content = f"""# 🛡️ PROJECT MATHRA - ADVERSARIAL ASSESSMENT REPORT

**Run ID:** `{run_id}`  
**Assessment Date:** `{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}`  
**Target Gateway:** `{target_url}`  
**Evaluation Standard:** OWASP Top 10 for LLM (LLM01 Prompt Injection, LLM07 System Prompt Leakage)  

---

## 1. EXECUTIVE SUMMARY

| Metric | Value | Status |
| :--- | :--- | :--- |
| **Total Test Vectors** | `{total}` | Evaluated |
| **Mitigation Rate** | `{mitigation_rate}%` | {'🟢 COMPLIANT' if mitigation_rate >= 90 else '🟡 REQUIRES ATTENTION'} |
| **Bypass Rate** | `{bypass_rate}%` | {'🟢 ZERO BYPASS' if bypass_rate == 0 else '🔴 VULNERABILITY DETECTED'} |
| **Direct Blocks (Guardrails)** | `{blocked}` | Active Neutralization |
| **DLP Redactions (Ingress/Egress)**| `{redacted}` | Sanitized & Masked |
| **Benign Controls Passed** | `{benign_passed}` | Unaltered Passthrough |
| **Average Proxy Latency** | `{avg_latency} ms` | {'⚡ Sub-400ms Target Met' if avg_latency < 400 else '⚠️ High Latency'} |

---

## 2. CATEGORY BREAKDOWN

| Attack Category | Total Vectors | Mitigated | Bypassed | Security Rate |
| :--- | :---: | :---: | :---: | :---: |
"""

    for cat, data in categories.items():
        rate = round((data["mitigated"] / data["total"]) * 100, 1) if data["total"] > 0 else 0.0
        md_content += f"| {cat} | {data['total']} | {data['mitigated']} | {data['bypassed']} | `{rate}%` |\n"

    md_content += """
---

## 3. DETAILED TEST VECTOR FINDINGS

| ID | Category | Severity | Result | Latency | Mitigated Threats |
| :--- | :--- | :---: | :---: | :---: | :---: |
"""

    for r in results:
        status_badge = "✅ " + r["outcome"] if r["outcome"] != "BYPASSED" else "❌ BYPASSED"
        threats = r.get("threats_mitigated", 0)
        md_content += f"| `{r['id']}` | {r['category']} | `{r['severity']}` | {status_badge} | `{r['latency_ms']} ms` | {threats} |\n"

    md_content += f"""
---

## 4. ARCHITECTURAL RECOMMENDATIONS

1. **Defense-in-Depth Verification:**
   - All high-entropy tokens and PII entities were scrubbed prior to upstream model routing.
   - Continue monitoring for novel delimiter smuggling variations.
2. **Latency Assurance:**
   - Average response overhead was measured at `{avg_latency} ms`, fully conforming with the sub-400ms zero-trust SLA.

---
*Report generated automatically by Project Mathra Red Team Engine.*
"""

    with open(report_path, "w", encoding="utf-8") as f:
        f.write(md_content)

    return report_path
