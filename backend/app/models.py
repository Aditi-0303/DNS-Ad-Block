from datetime import datetime
from sqlalchemy import Boolean, Column, DateTime, Float, Integer, String, Text
from app.db import Base


class DNSLog(Base):
    __tablename__ = "dns_logs"

    id = Column(Integer, primary_key=True, index=True)
    domain = Column(String(255), index=True, nullable=False)
    tld = Column(String(32), nullable=False)
    prediction = Column(String(16), nullable=False)
    score = Column(Float, nullable=False)
    entropy = Column(Float, nullable=False)
    digit_count = Column(Integer, nullable=False)
    domain_length = Column(Integer, nullable=False)
    explanation = Column(String(255), nullable=False)
    shap_summary = Column(Text, nullable=False)
    source = Column(String(64), default="manual", nullable=False)
    source_event_id = Column(String(160), index=True, nullable=True)
    client_ip = Column(String(64), nullable=True)
    query_type = Column(String(16), default="A", nullable=True)
    # Pi-hole is the source of truth for this decision.  These fields retain
    # the evidence needed to explain a block rather than inferring it from a
    # domain name alone.
    is_blocked = Column(Boolean, default=False, nullable=False)
    category = Column(String(32), default="unknown", nullable=False)
    block_reason = Column(Text, default="No matching Pi-hole rule reported", nullable=False)
    matched_rule = Column(String(255), nullable=True)
    list_source = Column(String(255), nullable=True)
    evidence = Column(Text, default="[]", nullable=False)
    false_positive_score = Column(Float, default=0.0, nullable=False)
    false_positive_risk = Column(String(16), default="low", nullable=False)
    impact_summary = Column(Text, default="", nullable=False)
    request_count = Column(Integer, default=1, nullable=False)
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
