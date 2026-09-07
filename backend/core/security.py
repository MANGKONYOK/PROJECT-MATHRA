"""
PROJECT MATHRA - Pydantic v2 Schemas and Data Contracts
Strictly typed data contracts for requests, responses, scan results and error handling.
"""

from typing import List, Optional
from pydantic import BaseModel, Field, field_validator

class ChatMessage(BaseModel): # this code is used to store all messages in conversation 
    role: str = Field(..., description="Role of the message author (system, user, assistant)")
    content: str = Field(..., description="Contents of the message")

class ChatCompletionRequest(BaseModel): # this code is used to store all messages in conversation 
    messages: List[ChatMessage] = Field(..., min_length=1, description="List of messages in conversation")
    model: Optional[str] = Field(default=None, description="Requested model (defaults to proxy default)")
    user_id: str = Field(default="anonymous", description="End-user identifier for rate-limiting and audit")
    temperature: float = Field(default=0.7, ge=0.0, le=2.0, description="Sampling temperature")
    stream: bool = Field(default=False, description="Streaming mode. Phase 1 forces non-streaming for egress DLP")

    @field_validator("stream")
    @classmethod
    def force_non_streaming_in_phase1(cls, v: bool) -> bool:
        if v is True:
            # Phase 1 architectural rule: force stream=False to ensure full egress verification
            return False
        return v

# this code is used to scan text for PII entities and secrets 
class ScanRequest(BaseModel):
    text: str = Field(..., min_length=1, description="Raw text payload to analyze and sanitize")
    user_id: str = Field(default="anonymous", description="User or application source ID")

#  this code is used to store PII entities and secrets 
class DlpEntityMatch(BaseModel):
    entity_type: str = Field(..., description="Category of PII/PHI (e.g. EMAIL_ADDRESS, PHONE_NUMBER, SSN)")
    start: int = Field(..., description="Start character index")
    end: int = Field(..., description="End character index")
    score: float = Field(..., ge=0.0, le=1.0, description="Confidence score")
    text_snippet: Optional[str] = Field(default=None, description="Masked snippet of detected entity")

# this code is used to store secrets found in the text
class SecretMatch(BaseModel):
    secret_type: str = Field(..., description="Type of secret found (AWS_KEY, GITHUB_TOKEN, OPENAI_KEY)")
    match_snippet: str = Field(..., description="Masked representation of the discovered credential")

# this code is used to evaluate adversarial threat
class GuardrailAssessment(BaseModel):
    is_safe: bool = Field(default=True, description="Whether prompt passes guardrail security policy")
    threat_score: float = Field(default=0.0, ge=0.0, le=1.0, description="Normalized adversarial threat score")
    threat_type: Optional[str] = Field(default=None, description="Identified threat class (e.g. JAILBREAK, PROMPT_INJECTION)")
    reason: Optional[str] = Field(default=None, description="Explanatory classification message")

# this code is used to store security scan result
class SecurityScanResult(BaseModel):
    status: str = Field(default="sanitized", description="Status: sanitized, blocked, or clean")
    sanitized_text: str = Field(..., description="Redacted prompt ready for upstream LLM")
    threats_mitigated: int = Field(default=0, description="Total count of PII entities and secrets neutralized")
    pii_entities: List[DlpEntityMatch] = Field(default_factory=list, description="Detected PII entities")
    secrets_found: List[SecretMatch] = Field(default_factory=list, description="Detected high-entropy secrets")
    guardrail: GuardrailAssessment = Field(default_factory=GuardrailAssessment, description="Adversarial evaluation")
    processing_time_ms: float = Field(default=0.0, description="Processing latency in milliseconds")

# this code is used to store chat completion response
class ChatCompletionChoiceMessage(BaseModel):
    role: str = "assistant"
    content: str

# this code is used to store chat completion response
class ChatCompletionChoice(BaseModel):
    index: int = 0
    message: ChatCompletionChoiceMessage
    finish_reason: str = "stop"

# this code is used to store chat completion response
class ChatCompletionResponse(BaseModel):
    id: str = Field(..., description="Unique completion ID")
    object: str = "chat.completion"
    created: int = Field(..., description="Unix timestamp of response")
    model: str = Field(..., description="Model used to generate response")
    choices: List[ChatCompletionChoice] = Field(..., description="List of completion choices")
    security_summary: SecurityScanResult = Field(..., description="Security & DLP metadata summary")

# this code is used to store security incident response
class SecurityIncidentResponse(BaseModel):
    error: str = Field(..., description="Sanitized client-facing error message")
    incident_id: str = Field(..., description="Unique correlation ID for SOC log tracing")
    timestamp: str = Field(..., description="ISO 8601 UTC timestamp of occurrence")