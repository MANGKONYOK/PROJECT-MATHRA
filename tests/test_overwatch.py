"""
Project Mathra - Tests for Overwatch (Shadow AI Network Interceptor)
Validates domain matching, SaaS endpoint detection, and event telemetry persistence.
"""

import os
import sqlite3
import pytest
from overwatch.proxy_addon import OverwatchInterceptor, TARGET_GENAI_DOMAINS


def test_overwatch_domain_matching():
    interceptor = OverwatchInterceptor()

    # Matches - Frontier & Open LLMs
    assert interceptor.matches_target("api.openai.com", "/v1/chat/completions") == "api.openai.com"
    assert interceptor.matches_target("claude.ai", "/login") == "claude.ai"
    assert interceptor.matches_target("gemini.google.com", "/app") == "gemini.google.com"
    assert interceptor.matches_target("api.deepseek.com", "/v1/chat/completions") == "api.deepseek.com"
    assert interceptor.matches_target("open.bigmodel.cn", "/api/paas/v4/chat/completions") == "open.bigmodel.cn"

    # Matches - IDE AI Agents
    assert interceptor.matches_target("api.cursor.sh", "/v1") == "api.cursor.sh"
    assert interceptor.matches_target("api.githubcopilot.com", "/chat/completions") == "api.githubcopilot.com"
    assert interceptor.matches_target("api.codeium.com", "/exa.language_server_pb.LanguageServerService/GetCompletions") == "api.codeium.com"

    # Matches - SaaS
    assert interceptor.matches_target("notion.so", "/api/v3/getCompletion") == "notion.so/api/v3/getCompletion"
    assert interceptor.matches_target("slack.com", "/api/chat.postMessage") == "slack.com/api/chat.postMessage"

    # Non-matches
    assert interceptor.matches_target("github.com", "/torvalds/linux") is None
    assert interceptor.matches_target("wikipedia.org", "/wiki/Main_Page") is None


def test_overwatch_logs_to_db(tmp_path):
    test_db = str(tmp_path / "test_overwatch.db")
    interceptor = OverwatchInterceptor(db_path=test_db, block_mode=True)

    interceptor._log_shadow_ai(
        source_ip="192.168.1.42",
        target="api.openai.com",
        action="BLOCKED",
        details="Unauthorized GenAI call intercepted"
    )

    conn = sqlite3.connect(test_db)
    cursor = conn.cursor()
    cursor.execute("SELECT incident_id, event_type, action_taken, details_sanitized FROM threat_events")
    rows = cursor.fetchall()
    conn.close()

    assert len(rows) == 1
    assert "MATHRA-SHADOW" in rows[0][0]
    assert rows[0][1] == "SHADOW_AI_INTERCEPTED"
    assert rows[0][2] == "BLOCKED"
    assert "Unauthorized GenAI" in rows[0][3]
