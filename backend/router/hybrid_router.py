"""
PROJECT MATHRA - LiteLLM Hybrid Router and Egress Defense
Handles universal model routing to API-based model and Local model,
with simulation/echo fallback mode for offline testing and egress sanitization.
"""

import time                                   # Used for timestamping
import uuid                                   # Used for generating unique IDs
from typing import List                       # Used for type hinting
from backend.core.config import get_settings  # Used for getting configuration
from backend.core.logging import logger       # Used for logging
from backend.core.security import (
    ChatMessage,                              # Used for type hinting
    ChatCompletionChoice,                     # Used for type hinting
    ChatCompletionChoiceMessage,              # Used for type hinting
    ChatCompletionResponse,                   # Used for type hinting
    SecurityScanResult,                       # Used for type hinting
)
from backend.dlp.secret_scanner import secret_scanner    # Used for secret scanning
from backend.dlp.presidio_engine import presidio_engine  # Used for PII anonymization

class HybridRouter:
    """Orchestrates upstream LLM routing, egress inspection, and simulation fallbacks."""

    def __init__(self):
        self.settings = get_settings()

    async def route_and_generate(
        self,
        sanitized_messages: List[ChatMessage],
        requested_model: str | None,
        security_summary: SecurityScanResult,
    ) -> ChatCompletionResponse:
        """Routes sanitized messages to the appropriate LLM provider and applies egress DLP."""
        model_name = requested_model or self.settings.default_model

        # Check simulation mode or missing credentials
        is_simulation = (
            self.settings.simulation_mode
            or not self.settings.openai_api_key
            or self.settings.openai_api_key.startswith("sk-demo")
        )

        response_text = ""
        created_ts = int(time.time())
        completion_id = f"chatcmpl-{uuid.uuid4().hex[:12]}"

        if is_simulation:
            # High-fidelity simulated LLM response for local testing and red-teaming validation
            last_user_msg = next((m.content for m in reversed(sanitized_messages) if m.role == "user"), "")
            response_text = (
                f"[MATHRA-SECURE-LLM-SIMULATOR]: Received sanitized payload: '{last_user_msg}'. "
                f"Model targeted: {model_name}. Zero-Trust policies enforced."
            )
        else:
            # Route via LiteLLM
            try:
                import litellm
                # Format messages for LiteLLM
                formatted_msgs = [{"role": m.role, "content": m.content} for m in sanitized_messages]

                # Normalize and map multi-provider model names for LiteLLM
                target_model = model_name
                lower_model = model_name.lower()
                if "deepseek" in lower_model and not target_model.startswith("deepseek/"):
                    target_model = f"deepseek/{model_name}"
                elif "gemini" in lower_model and not target_model.startswith("gemini/"):
                    target_model = f"gemini/{model_name}"
                elif ("glm" in lower_model or "zhipu" in lower_model) and not target_model.startswith("zhipu/"):
                    target_model = f"zhipu/{model_name}"
                elif "mistral" in lower_model and not target_model.startswith("mistral/"):
                    target_model = f"mistral/{model_name}"
                elif "groq" in lower_model and not target_model.startswith("groq/"):
                    target_model = f"groq/{model_name}"
                elif "llama" in lower_model and not target_model.startswith("ollama/"):
                    target_model = f"ollama/{model_name}"

                # Always force stream=False for Phase 1 egress inspection
                raw_response = await litellm.acompletion(
                    model=target_model,
                    messages=formatted_msgs,
                    stream=False,
                    api_base=self.settings.ollama_base_url if "ollama" in target_model else None,
                )
                response_text = raw_response.choices[0].message.content or ""
            except Exception as e:
                logger.error(f"LiteLLM upstream invocation failure: {e}", exc_info=True)
                # Fallback to simulation mode on network/provider error
                response_text = (
                    f"[MATHRA-FAILSAFE-RESPONSE]: Upstream model '{model_name}' temporarily unavailable. "
                    "Sanitized input processed successfully."
                )

        # Apply Egress DLP Inspection (verify outgoing content doesn't leak secrets or PII)
        egress_sanitized, egress_secrets = secret_scanner.mask(response_text)
        egress_sanitized, egress_pii = presidio_engine.anonymize(egress_sanitized)

        # Update security metadata with egress mitigation counts
        total_mitigated = security_summary.threats_mitigated + len(egress_secrets) + len(egress_pii)
        security_summary.threats_mitigated = total_mitigated

        choice = ChatCompletionChoice(
            index=0,
            message=ChatCompletionChoiceMessage(role="assistant", content=egress_sanitized),
            finish_reason="stop",
        )

        return ChatCompletionResponse(
            id=completion_id,
            object="chat.completion",
            created=created_ts,
            model=model_name,
            choices=[choice],
            security_summary=security_summary,
        )


# Global instance
hybrid_router = HybridRouter()