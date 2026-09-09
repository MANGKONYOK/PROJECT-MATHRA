"""
Project Mathra - Overwatch (Shadow AI Network Interceptor)
mitmproxy Add-on to detect and block unauthorized outbound GenAI calls
at the network level without accessing client filesystems.
"""

import json
import logging
import os
import sqlite3
from datetime import datetime, timezone

# Categorized Comprehensive GenAI & IDE Agent Watchlist
TARGET_GENAI_DOMAINS = [
    # --- Frontier & Open LLM Cloud APIs ---
    "api.openai.com", "chatgpt.com", "oaistatic.com",
    "api.anthropic.com", "claude.ai",
    "gemini.google.com", "generativelanguage.googleapis.com", "aistudio.google.com",
    "api.deepseek.com", "chat.deepseek.com", "deepseek.com",
    "chatglm.cn", "open.bigmodel.cn", "api.zhipuai.cn",
    "api.mistral.ai", "chat.mistral.ai",
    "api.groq.com",
    "api.perplexity.ai", "perplexity.ai",
    "api.cohere.ai",
    "api.together.xyz",
    "openrouter.ai",
    "api.moonshot.cn", "kimi.moonshot.cn",
    "dashscope.aliyuncs.com",

    # --- IDE AI Agents & Coding Assistants ---
    "cursor.sh", "api.cursor.sh", "api2.cursor.sh", "repo42.cursor.sh",
    "api.githubcopilot.com", "copilot-proxy.githubusercontent.com", "copilot-telemetry.githubusercontent.com",
    "api.codeium.com", "server.codeium.com",
    "api.tabnine.com",
    "api.app-intelligence.jetbrains.com",
    "api.supermaven.com",
    "replit.com/api/v0/ai",

    # --- Enterprise SaaS Embedded AI Endpoints ---
    "notion.so/api/v3/getCompletion",
    "slack.com/api/chat.postMessage",
    "copilot.microsoft.com", "substrate.office.com",
    "canva.com/api/ai",
    "zoom.us/api/v2/ai"
]

DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "backend", "data", "mathra_events.db")


class OverwatchInterceptor:
    """mitmproxy add-on intercepting unauthorized outbound LLM traffic."""

    def __init__(self, db_path: str = DEFAULT_DB_PATH, block_mode: bool = True):
        self.db_path = db_path
        self.block_mode = block_mode
        # Sort by length descending to match most specific subdomains first
        self.watchlist = sorted(TARGET_GENAI_DOMAINS, key=len, reverse=True)
        self._ensure_db()

    def _ensure_db(self):
        """Ensures the SQLite database and threat_events table exist."""
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    incident_id TEXT NOT NULL,
                    timestamp TIMESTAMP NOT NULL,
                    user_id TEXT NOT NULL,
                    source_ip TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    details_sanitized TEXT NOT NULL,
                    latency_ms REAL NOT NULL
                )
            """)
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"[OVERWATCH] Database setup error: {e}")

    def _log_shadow_ai(self, source_ip: str, target: str, action: str, details: str):
        """Logs detected Shadow AI activity to the persistent store."""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            incident_id = f"MATHRA-SHADOW-{datetime.now(timezone.utc).strftime('%H%M%S')}"
            now_iso = datetime.now(timezone.utc).isoformat()
            cursor.execute("""
                INSERT INTO threat_events (
                    incident_id, timestamp, user_id, source_ip, event_type,
                    severity, action_taken, details_sanitized, latency_ms
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                incident_id,
                now_iso,
                "shadow-ai-client",
                source_ip,
                "SHADOW_AI_INTERCEPTED",
                "HIGH",
                action,
                details,
                0.0
            ))
            conn.commit()
            conn.close()
        except Exception as e:
            logging.error(f"[OVERWATCH] Failed to log shadow AI: {e}")

    def matches_target(self, host: str, path: str) -> str | None:
        """Checks if request matches the Shadow AI watchlist."""
        full_url = f"{host}{path}"
        for domain in self.watchlist:
            if domain in full_url or domain in host:
                return domain
        return None

    def request(self, flow):
        """mitmproxy event hook called for every intercepted HTTP/HTTPS request."""
        host = flow.request.pretty_host
        path = flow.request.path
        matched_target = self.matches_target(host, path)

        if matched_target:
            client_ip = flow.client_conn.peername[0] if flow.client_conn and flow.client_conn.peername else "127.0.0.1"
            action = "BLOCKED" if self.block_mode else "ALERTED"
            details = f"Unauthorized AI endpoint intercepted: {matched_target} via {host}{path[:40]}"

            self._log_shadow_ai(client_ip, matched_target, action, details)

            if self.block_mode:
                # Issue enterprise Zero-Trust 403 block page
                response_html = f"""<!DOCTYPE html>
<html>
<head>
    <title>403 - Enterprise AI Policy Block</title>
    <style>
        body {{ background-color: #0D1117; color: #E6EDF3; font-family: monospace; padding: 40px; }}
        .box {{ border: 2px solid #FF4444; border-radius: 8px; padding: 24px; max-width: 600px; margin: 0 auto; }}
        h1 {{ color: #FF4444; margin-top: 0; }}
        code {{ background: #161B22; color: #00FF66; padding: 4px 8px; border-radius: 4px; }}
    </style>
</head>
<body>
    <div class="box">
        <h1>🛡️ PROJECT MATHRA OVERWATCH - ACCESS DENIED</h1>
        <p>Your attempt to connect to unauthorized GenAI endpoint <code>{matched_target}</code> has been intercepted.</p>
        <p><strong>Reason:</strong> Enterprise Zero-Trust Data Loss Prevention Policy Violation.</p>
        <p>Please route your queries through the approved internal Guardian Proxy gateway.</p>
        <hr style="border-color: #30363D;">
        <p><small>Incident logged for Enterprise SOC Review.</small></p>
    </div>
</body>
</html>"""
                from mitmproxy import http
                flow.response = http.Response.make(
                    403,
                    response_html.encode("utf-8"),
                    {"Content-Type": "text/html", "X-Mathra-Overwatch": "BLOCKED"}
                )


# mitmproxy addon entrypoint
addons = [OverwatchInterceptor()]
