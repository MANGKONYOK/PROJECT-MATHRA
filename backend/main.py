"""
Project Mathra - FastAPI Security Proxy Gateway
Enterprise AI-SPM Ingress/Egress DLP, Guardrails, and LiteLLM Reverse Proxy.
Enforces CWE-209 Sanitized Error Handling, sub-400ms non-blocking async pipeline,
and attaches standard security telemetry headers to every response.
"""

import time
from contextlib import asynccontextmanager
from typing import Dict, Any

from fastapi import FastAPI, Request, Response, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.core.config import get_settings
from backend.core.database import init_db, log_threat_event, get_threat_metrics, get_recent_events
from backend.core.logging import logger, generate_incident_id
from backend.core.security import (
    ChatCompletionRequest,
    ChatCompletionResponse,
    ChatMessage,
    ScanRequest,
    SecurityScanResult,
    SecurityIncidentResponse,
    GuardrailAssessment,
)
from backend.dlp.secret_scanner import secret_scanner
from backend.dlp.presidio_engine import presidio_engine
from backend.dlp.guardrail_engine import guardrail_engine
from backend.router.hybrid_router import hybrid_router


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifecycle events: initialize database and warm up DLP components."""
    logger.info("Initializing Project Mathra Security Gateway...")
    await init_db()
    logger.info("Gateway Online. Ready to intercept and inspect AI traffic.")
    yield
    logger.info("Shutting down Project Mathra Gateway.")


settings = get_settings()

app = FastAPI(
    title="Project Mathra - AI-SPM & Red-Teaming Gateway",
    description="Enterprise Zero-Trust DLP reverse proxy and AI Security Posture Management platform.",
    version="1.0.0",
    lifespan=lifespan,
)

# Enable CORS for Streamlit SOC dashboard communication
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# CWE-209 Mitigation: Global Unhandled Exception Handler
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    incident_id = generate_incident_id()
    # Log detailed internal stack trace server-side with correlation ID
    logger.error(
        f"CRITICAL PROCESS FAILURE - Incident: {incident_id} - Path: {request.url.path} - Exception: {str(exc)}",
        exc_info=True,
    )
    # Return completely sanitized message to caller (never leak internal details)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={
            "error": "MATHRA GUARDIAN: Internal Security Processing Error.",
            "incident_id": incident_id,
            "message": "The incident has been isolated and logged for enterprise SOC review.",
        },
        headers={
            "X-Mathra-Incident-ID": incident_id,
            "X-Mathra-Processing-Time-MS": "0.0",
            "X-Mathra-Threats-Mitigated": "0",
        },
    )


@app.get("/health")
async def health_check() -> Dict[str, Any]:
    """Health check endpoint exposing engine status and operational mode."""
    return {
        "status": "online",
        "service": "Project Mathra Gateway",
        "version": "1.0.0",
        "dlp_engine_mode": presidio_engine.mode,
        "simulation_mode": settings.simulation_mode,
        "database": "connected",
    }


@app.post("/v1/security/scan", response_model=SecurityScanResult)
async def scan_payload(payload: ScanRequest) -> SecurityScanResult:
    """Direct DLP and guardrail scanning endpoint without model routing."""
    start_time = time.perf_counter()
    incident_id = generate_incident_id()

    # Step 1: Secret scanning
    masked_text, secrets = secret_scanner.mask(payload.text)

    # Step 2: PII/PHI anonymization
    sanitized_text, pii_matches = presidio_engine.anonymize(masked_text)

    # Step 3: Guardrail evaluation
    guardrail_res = guardrail_engine.evaluate(sanitized_text)

    threats_count = len(secrets) + len(pii_matches)
    if not guardrail_res.is_safe:
        threats_count += 1

    proc_time_ms = round((time.perf_counter() - start_time) * 1000, 2)

    status_str = "blocked" if not guardrail_res.is_safe else ("sanitized" if threats_count > 0 else "clean")

    # Record telemetry
    if threats_count > 0:
        await log_threat_event(
            incident_id=incident_id,
            event_type="SCAN_MITIGATION" if guardrail_res.is_safe else "PROMPT_INJECTION_SCAN",
            severity="HIGH" if not guardrail_res.is_safe else "MEDIUM",
            action_taken="BLOCKED" if not guardrail_res.is_safe else "REDACTED",
            details_sanitized=f"Secrets: {len(secrets)}, PII: {len(pii_matches)}, Guardrail: {guardrail_res.threat_type}",
            latency_ms=proc_time_ms,
            user_id=payload.user_id,
        )

    return SecurityScanResult(
        status=status_str,
        sanitized_text=sanitized_text,
        threats_mitigated=threats_count,
        pii_entities=pii_matches,
        secrets_found=secrets,
        guardrail=guardrail_res,
        processing_time_ms=proc_time_ms,
    )


@app.post("/v1/chat/completions", response_model=ChatCompletionResponse)
async def chat_completions(chat_req: ChatCompletionRequest, response: Response):
    """
    OpenAI-compatible reverse proxy endpoint.
    Performs Ingress DLP, Secret Masking, Guardrail Evaluation, Model Routing, and Egress DLP.
    """
    start_time = time.perf_counter()
    incident_id = generate_incident_id()

    sanitized_messages = []
    total_secrets = []
    total_pii = []
    worst_guardrail = GuardrailAssessment(is_safe=True, threat_score=0.0)

    # Ingress Inspection on all messages
    for msg in chat_req.messages:
        # Step 1: Secret Masking
        masked_content, secrets = secret_scanner.mask(msg.content)
        total_secrets.extend(secrets)

        # Step 2: Presidio PII Anonymization
        clean_content, pii = presidio_engine.anonymize(masked_content)
        total_pii.extend(pii)

        # Step 3: Guardrail Injection Scan
        g_eval = guardrail_engine.evaluate(clean_content)
        if g_eval.threat_score > worst_guardrail.threat_score:
            worst_guardrail = g_eval

        sanitized_messages.append(ChatMessage(role=msg.role, content=clean_content))

    threats_count = len(total_secrets) + len(total_pii)

    # Check for adversarial attack block
    if not worst_guardrail.is_safe:
        proc_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
        await log_threat_event(
            incident_id=incident_id,
            event_type=worst_guardrail.threat_type or "PROMPT_INJECTION",
            severity="CRITICAL",
            action_taken="BLOCKED",
            details_sanitized=f"Blocked adversarial payload: {worst_guardrail.reason}",
            latency_ms=proc_time_ms,
            user_id=chat_req.user_id,
        )

        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"MATHRA GUARDIAN: Request blocked by AI-SPM Guardrails ({worst_guardrail.reason}).",
            headers={
                "X-Mathra-Incident-ID": incident_id,
                "X-Mathra-Processing-Time-MS": str(proc_time_ms),
                "X-Mathra-Threats-Mitigated": str(threats_count + 1),
            },
        )

    # Log DLP redactions if secrets or PII were found
    if threats_count > 0:
        await log_threat_event(
            incident_id=incident_id,
            event_type="INGRESS_DLP_REDACTION",
            severity="HIGH" if total_secrets else "MEDIUM",
            action_taken="REDACTED",
            details_sanitized=f"Neutralized {len(total_secrets)} secrets and {len(total_pii)} PII entities.",
            latency_ms=0.0,
            user_id=chat_req.user_id,
        )

    # Construct security summary
    initial_summary = SecurityScanResult(
        status="sanitized" if threats_count > 0 else "clean",
        sanitized_text=sanitized_messages[-1].content if sanitized_messages else "",
        threats_mitigated=threats_count,
        pii_entities=total_pii,
        secrets_found=total_secrets,
        guardrail=worst_guardrail,
        processing_time_ms=0.0,
    )

    # Model Routing & Egress Defense
    completion_response = await hybrid_router.route_and_generate(
        sanitized_messages=sanitized_messages,
        requested_model=chat_req.model,
        security_summary=initial_summary,
    )

    total_proc_time_ms = round((time.perf_counter() - start_time) * 1000, 2)
    completion_response.security_summary.processing_time_ms = total_proc_time_ms

    # Attach Telemetry Headers to Response
    response.headers["X-Mathra-Processing-Time-MS"] = str(total_proc_time_ms)
    response.headers["X-Mathra-Threats-Mitigated"] = str(completion_response.security_summary.threats_mitigated)
    response.headers["X-Mathra-Incident-ID"] = incident_id

    return completion_response


# Backward-compatible MVP endpoint
@app.post("/chat")
async def legacy_chat(request: Request, response: Response):
    """Backward compatibility endpoint for existing MVP clients."""
    try:
        data = await request.json()
        prompt = data.get("prompt", "")
        user_id = data.get("user_id", "anonymous")
    except Exception:
        raise HTTPException(status_code=400, detail="MATHRA GUARDIAN: Invalid JSON payload.")

    chat_req = ChatCompletionRequest(
        messages=[ChatMessage(role="user", content=prompt)],
        user_id=user_id,
        stream=False,
    )
    resp = await chat_completions(chat_req, response)
    return {
        "status": "success",
        "original_prompt_length": len(prompt),
        "redacted_prompt": resp.security_summary.sanitized_text,
        "llm_response": resp.choices[0].message.content,
        "threats_mitigated": resp.security_summary.threats_mitigated,
        "incident_id": response.headers.get("X-Mathra-Incident-ID", ""),
    }


@app.get("/v1/metrics")
async def get_metrics():
    """Returns aggregated threat metrics for SOC observability."""
    return await get_threat_metrics()


@app.get("/v1/events")
async def get_events(limit: int = 50):
    """Returns recent threat events for the SOC audit stream."""
    return await get_recent_events(limit=limit)
