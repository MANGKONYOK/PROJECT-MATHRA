# 🛡️ PROJECT MATHRA (AI-SPM & RED-TEAMING GATEWAY)

[![Python](https://img.shields.io/badge/Python-3.12%2B-blue.svg)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115%2B-009688.svg)](https://fastapi.tiangolo.com/)
[![Streamlit](https://img.shields.io/badge/Streamlit-1.40%2B-FF4B4B.svg)](https://streamlit.io/)
[![Zero-Trust](https://img.shields.io/badge/Zero--Trust-Enforced-00FF66.svg)]()
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

**Project Mathra** is an enterprise-grade **AI Security Posture Management (AI-SPM)**, Zero-Trust DLP reverse proxy, automated adversarial evaluation engine, and Shadow AI network monitoring suite.

Designed with DevSecOps best practices, Project Mathra provides deep visibility, real-time data redaction, input/output guardrails, and automated attack validation for modern LLM applications.

---

## 🏛️ SYSTEM ARCHITECTURE & 4 CORE PILLARS

```text
[ Client Application / User Query ]
               │
               ▼
┌─────────────────────────────────────────────────────────────┐
│ 1. THE GUARDIAN (FastAPI Reverse Proxy Gateway)             │
│   ├─ CWE-209 Sanitized Error Handling                       │
│   ├─ Ingress DLP: Microsoft Presidio PII/PHI Redactor       │
│   │   └─ High-Speed Regex Resilient Fallback Engine         │
│   ├─ Secret Scanner: TruffleHog AWS/GitHub/OpenAI/DB Tokens │
│   ├─ Guardrails: OWASP LLM01 Prompt Injection & Jailbreaks │
│   └─ Hybrid Router: LiteLLM to OpenAI / Ollama + Echo Mode  │
└─────────────────────────────────────────────────────────────┘
               │  (Sanitized Request)
               ▼
┌───────────────────────────────┐
│   Upstream LLM Provider       │
│ (gpt-4o-mini / local llama3)  │
└───────────────────────────────┘
               │  (Model Output)
               ▼
┌─────────────────────────────────────────────────────────────┐
│ Egress DLP Filter: System Prompt & Secret Leakage Check     │
└─────────────────────────────────────────────────────────────┘
               │  (Sanitized Output + Security Headers)
               ▼
    [ Secure Client Response ]
```

1. **The Guardian (Blue Team Proxy):**
   - Asynchronous reverse proxy gateway built on FastAPI.
   - **Ingress DLP:** PII/PHI redaction via Microsoft Presidio Analyzer/Anonymizer with automated high-speed regex fallback.
   - **Secret Scanner:** TruffleHog-inspired regex pattern matcher for AWS keys, GitHub PATs, OpenAI keys, Bearer tokens, and DB connection URIs.
   - **Input Guardrails:** Neutralizes prompt injections, DAN/roleplay escapes, and system prompt exfiltration.
   - **Hybrid Router:** LiteLLM dynamic routing to cloud (`gpt-4o-mini`) or local Ollama (`llama3`), featuring offline simulation/echo mode.

2. **The Auto-Pentester (Red Team Engine):**
   - Automated adversarial validation suite testing the Guardian proxy against 50+ curated attack vectors.
   - Dual-Mode execution: standalone CLI with `argparse` for CI/CD pipelines, and interactive UI in Streamlit.
   - Concurrency control via `asyncio.Semaphore(10)` to prevent connection drops.
   - Generates executive Markdown assessment reports (`redteam/reports/`).

3. **Overwatch (Shadow AI Monitor):**
   - Network-level TLS/HTTPS traffic interception using `mitmproxy` add-on scripts.
   - Intercepts unauthorized third-party GenAI calls (`api.openai.com`, `claude.ai`, `chatgpt.com`, Notion AI, Slack completions) without accessing client filesystems.
   - Enforces 403 Zero-Trust block pages and persists telemetry into the threat store.

4. **SOC Command Center:**
   - Pure-Python dashboard using Streamlit with an Obsidian dark monospace theme (`.streamlit/config.toml`).
   - Real-time threat metrics, live audit feeds, interactive security sandbox, and Red Team test runner.

---

## 📂 REPOSITORY STRUCTURE

```text
Project-Mathra/
├── .streamlit/
│   └── config.toml               # Glitch-Tech / Obsidian Dark Monospace Theme
├── backend/
│   ├── main.py                   # FastAPI Proxy Gateway & Middlewares
│   ├── core/
│   │   ├── config.py             # Pydantic Settings v2 & Env Loader
│   │   ├── logging.py            # CWE-209 Sanitized Enterprise Logging
│   │   ├── security.py           # Pydantic v2 Data Contracts & Schemas
│   │   └── database.py           # Async SQLAlchemy Threat Store (SQLite/Postgres)
│   ├── dlp/
│   │   ├── secret_scanner.py     # TruffleHog / Regex Secret Masker
│   │   ├── presidio_engine.py    # Presidio PII Engine + Resilient Fallback
│   │   └── guardrail_engine.py   # Adversarial Injection & Jailbreak Detector
│   └── router/
│       └── hybrid_router.py      # LiteLLM Proxy + Simulation Fallback
├── redteam/
│   ├── payloads/
│   │   └── injection_dataset.json# 50+ Curated Adversarial Attack Payloads
│   ├── pentest_runner.py         # Async Attack Runner (CLI + UI, Semaphore-10)
│   └── reporter.py               # Markdown Vulnerability Report Generator
├── overwatch/
│   └── proxy_addon.py            # mitmproxy Network Interception Script
├── tests/
│   ├── test_dlp.py               # Unit tests: Secret Scanner & Presidio
│   ├── test_proxy.py             # Integration tests: Reverse Proxy & Headers
│   └── test_overwatch.py         # Unit tests: Shadow AI domain matching
├── app.py                        # Streamlit SOC Command Center Dashboard
├── Dockerfile                    # Production unprivileged multi-stage container
├── docker-compose.yml            # Multi-service orchestration
├── requirements.txt              # Pinned production dependencies
├── .env.example                  # Environment configuration template
└── README.md                     # Documentation
```

---

## 🚀 QUICKSTART GUIDE

### 1. Installation & Environment Setup

```bash
# Clone repository
git clone https://github.com/your-org/Project-Mathra.git
cd Project-Mathra

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment settings
cp .env.example .env
```

### 2. Launch The Guardian Proxy Gateway

```bash
python -m uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload
```
*Healthcheck:* [http://localhost:8000/health](http://localhost:8000/health)  
*Swagger Documentation:* [http://localhost:8000/docs](http://localhost:8000/docs)

### 3. Launch SOC Command Center (Streamlit)

```bash
streamlit run app.py
```
Access the dashboard at [http://localhost:8501](http://localhost:8501).

---

## 🎯 RUNNING THE AUTO-PENTESTER (RED TEAM)

### CLI Mode (CI/CD Pipelines)

```bash
python redteam/pentest_runner.py \
  --target http://localhost:8000/v1/chat/completions \
  --concurrency 10 \
  --dataset redteam/payloads/injection_dataset.json \
  --output-dir redteam/reports
```

### UI Mode
Open the **SOC Command Center** (`app.py`), navigate to **🎯 Red Team Console**, set concurrency, and click **⚡ Launch Adversarial Pentest Suite** to observe real-time progress and view generated assessment reports.

---

## 👁️ RUNNING OVERWATCH (SHADOW AI MONITOR)

```bash
mitmproxy -s overwatch/proxy_addon.py -p 8080
```
Configure your client environment:
```bash
export HTTP_PROXY=http://localhost:8080
export HTTPS_PROXY=http://localhost:8080
```
Any unauthorized outbound requests to `api.openai.com`, `claude.ai`, or SaaS completion routes will be blocked with a 403 Zero-Trust notice and logged to `backend/data/mathra_events.db`.

---

## 🧪 TESTING & VERIFICATION

Run the comprehensive unit and integration test suite:

```bash
pytest tests/ -v
```

Output highlights:
```text
tests/test_dlp.py::test_secret_scanner_aws_key PASSED
tests/test_dlp.py::test_secret_scanner_github_token PASSED
tests/test_dlp.py::test_secret_scanner_openai_key PASSED
tests/test_dlp.py::test_presidio_email_and_phone PASSED
tests/test_dlp.py::test_guardrail_prompt_injection PASSED
tests/test_dlp.py::test_guardrail_jailbreak_dan PASSED
tests/test_proxy.py::test_chat_completions_headers_and_sanitization PASSED
tests/test_proxy.py::test_chat_completions_blocks_injection PASSED
tests/test_overwatch.py::test_overwatch_domain_matching PASSED
==================== 17 passed in 1.45s ====================
```

---

## 🔒 SECURITY & COMPLIANCE FEATURES

- **CWE-209 Mitigation:** Raw stack traces, library internals, or environment values are never leaked in API responses. Every error generates a sanitized client payload and a traceable `X-Mathra-Incident-ID` correlation token logged securely server-side.
- **Telemetry Response Headers:**
  - `X-Mathra-Processing-Time-MS`: Real-time inspection latency.
  - `X-Mathra-Threats-Mitigated`: Entity redaction and neutralization counter.
  - `X-Mathra-Incident-ID`: Unique incident identifier.
- **Strict Pydantic v2 Typing:** No untyped dictionaries; full type safety and request/response schema validation.
- **Non-Streaming Phase 1 Assurance:** Forces `stream=False` during evaluation to guarantee 100% complete egress DLP inspection on LLM outputs before returning data to clients.

---

## 📄 LICENSE

Distributed under the MIT License. See [LICENSE](LICENSE) for details.