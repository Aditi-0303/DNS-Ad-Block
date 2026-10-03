from datetime import datetime
from typing import Literal, Optional
from pydantic import BaseModel, ConfigDict, Field


class AnalyzeRequest(BaseModel):
    domain: str = Field(..., min_length=1, max_length=255)


class AnalyzeResponse(BaseModel):
    domain: str
    prediction: str
    score: float
    explanation: str

    # Existing ML
    ml_probability: float
    ml_decision: str
    ml_threshold: float

    # New domain-only ML
    domain_only_ml_probability: float
    domain_only_ml_decision: str
    domain_only_ml_threshold: float
    domain_only_ml_suspicious: bool

    # SHAP
    shap_summary: str

    entropy: float
    digit_count: int
    domain_length: int
    tld: str


class PiHoleEvent(BaseModel):
    """Normalized DNS event from a Pi-hole adapter or a saved Pi-hole export."""

    domain: str = Field(..., min_length=1, max_length=255)
    blocked: bool
    client_ip: Optional[str] = Field(default=None, max_length=64)
    query_type: str = Field(default="A", max_length=16)
    matched_rule: Optional[str] = Field(default=None, max_length=255)
    list_source: Optional[str] = Field(default=None, max_length=255)
    request_count: int = Field(default=1, ge=1, le=1_000_000)
    occurred_at: Optional[datetime] = None


class EvidenceItem(BaseModel):
    label: str
    detail: str
    weight: float = Field(ge=0, le=1)


class ExplanationRead(BaseModel):
    category: str
    block_reason: str
    matched_rule: Optional[str]
    list_source: Optional[str]
    evidence: list[EvidenceItem]
    false_positive_score: float
    false_positive_risk: Literal["low", "medium", "high"]
    impact_summary: str

class SHAPItem(BaseModel):
    feature: str
    value: float
    shap_value: float
    impact: Literal["malicious", "benign"]
    reason: str
class PiHoleEventResponse(BaseModel):
    id: int
    domain: str
    blocked: bool
    prediction: str
    ml_probability: float
    ml_decision: str
    ml_threshold: float
    shap_summary: list[SHAPItem]
    domain_only_ml_probability: Optional[float] = None
    domain_only_ml_decision: Optional[str] = None
    domain_only_ml_threshold: Optional[float] = None
    domain_only_ml_suspicious: Optional[bool] = None
    explanation: ExplanationRead


class PiHoleSyncResponse(BaseModel):
    imported: int
    skipped: int
    inspected: int
    message: str


class DNSLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    domain: str
    tld: str
    prediction: str
    score: float
    entropy: float
    digit_count: int
    domain_length: int
    explanation: str
    shap_summary: str
    domain_only_ml_probability: Optional[float] = None
    domain_only_ml_decision: Optional[str] = None
    domain_only_ml_threshold: Optional[float] = None
    domain_only_ml_suspicious: Optional[bool] = None
    source: str
    source_event_id: Optional[str]
    client_ip: Optional[str]
    query_type: Optional[str]
    is_blocked: bool
    category: str
    block_reason: str
    matched_rule: Optional[str]
    list_source: Optional[str]
    evidence: str
    false_positive_score: float
    false_positive_risk: str
    impact_summary: str
    request_count: int
    created_at: datetime

