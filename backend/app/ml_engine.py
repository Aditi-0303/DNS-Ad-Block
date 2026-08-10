"""Transparent enrichment for Pi-hole events.

Pi-hole decides whether a DNS query is blocked.  This module never changes
that decision; it translates Pi-hole's rule evidence into a user-facing
explanation and a clearly-labelled false-positive assessment.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass


@dataclass(frozen=True)
class CategoryRule:
    category: str
    terms: tuple[str, ...]
    description: str


CATEGORY_RULES = (
    CategoryRule("advertising", ("adserver", "ads", "doubleclick", "adnxs", "banner"), "serves or measures advertising"),
    CategoryRule("tracking", ("analytics", "track", "telemetry", "metrics", "pixel"), "collects cross-site or product usage data"),
    CategoryRule("malware", ("malware", "phish", "exploit", "botnet"), "matches a security-related indicator"),
    CategoryRule("telemetry", ("sentry", "crash", "diagnostic", "beacon"), "sends application diagnostics or telemetry"),
)

# Blocking these can affect an application's sign-in, payments, media, or
# essential delivery path.  The score is advisory, never an automatic allow.
SERVICE_TERMS = ("accounts.google", "microsoftonline", "icloud", "cloudfront", "amazonaws", "stripe", "youtube")


class DomainAnalyzer:
    """Backward-compatible manual analyser plus Pi-hole explanation builder."""

    def _calculate_entropy(self, value: str) -> float:
        if not value:
            return 0.0
        length = float(len(value))
        return -sum((count / length) * math.log(count / length, 2) for count in (value.count(char) for char in set(value)))

    def _category(self, domain: str, matched_rule: str | None, list_source: str | None) -> tuple[str, str | None]:
        searchable = " ".join(filter(None, (domain, matched_rule, list_source))).lower()
        for rule in CATEGORY_RULES:
            matched_term = next((term for term in rule.terms if term in searchable), None)
            if matched_term:
                return rule.category, rule.description
        return "unknown", None

    def explain_pihole_event(
        self,
        *,
        domain: str,
        blocked: bool,
        matched_rule: str | None,
        list_source: str | None,
        request_count: int,
    ) -> dict:
        category, category_detail = self._category(domain, matched_rule, list_source)
        evidence: list[dict] = []
        if blocked:
            evidence.append({"label": "Pi-hole decision", "detail": "Pi-hole returned this query as blocked.", "weight": 1.0})
            if matched_rule:
                evidence.append({"label": "Matched rule", "detail": f"The query matched `{matched_rule}`.", "weight": 0.95})
            if list_source:
                evidence.append({"label": "Block source", "detail": f"The rule came from {list_source}.", "weight": 0.9})
            if category_detail:
                evidence.append({"label": "Category evidence", "detail": f"The domain/rule contains a {category} indicator and likely {category_detail}.", "weight": 0.65})
        else:
            evidence.append({"label": "Pi-hole decision", "detail": "Pi-hole allowed this query; no blocking rule was reported.", "weight": 1.0})

        service_match = next((term for term in SERVICE_TERMS if term in domain.lower()), None)
        score = 0.0
        if blocked and not matched_rule:
            score += 0.35
        if service_match:
            score += 0.45
            evidence.append({"label": "Compatibility signal", "detail": f"`{service_match}` can be part of an application or delivery service, so review before keeping it blocked.", "weight": 0.45})
        if category == "unknown":
            score += 0.20
        if request_count > 100:
            score += 0.10
        score = round(min(score, 1.0), 2)
        risk = "high" if score >= 0.65 else "medium" if score >= 0.35 else "low"

        if not blocked:
            block_reason = "Allowed by Pi-hole; no matching block rule was supplied."
        elif matched_rule and list_source:
            block_reason = f"Blocked because Pi-hole matched `{matched_rule}` from {list_source}."
        elif matched_rule:
            block_reason = f"Blocked because Pi-hole matched `{matched_rule}`."
        elif list_source:
            block_reason = f"Blocked by a Pi-hole rule from {list_source}; the exact rule was not supplied."
        else:
            block_reason = "Blocked by Pi-hole; import the matched rule and list source for a fuller explanation."

        activity = f"This domain was requested {request_count} time{'s' if request_count != 1 else ''}."
        impact_summary = (
            f"Allowing it may restore {category} traffic. {activity}"
            if blocked else f"No block impact. {activity}"
        )
        return {
            "category": category,
            "block_reason": block_reason,
            "matched_rule": matched_rule,
            "list_source": list_source,
            "evidence": evidence,
            "false_positive_score": score,
            "false_positive_risk": risk,
            "impact_summary": impact_summary,
        }

    def analyze(self, domain: str) -> dict:
        """Retained for the original manual `/analyze` demo endpoint.

        The result is explicitly a domain-risk heuristic, not a Pi-hole block
        explanation.  Pi-hole events should use ``explain_pihole_event``.
        """
        normalized = domain.strip().lower()
        tld = normalized.rsplit(".", 1)[-1] if "." in normalized else ""
        entropy = self._calculate_entropy(normalized)
        digit_count = sum(char.isdigit() for char in normalized)
        explanation = self.explain_pihole_event(
            domain=normalized, blocked=False, matched_rule=None, list_source=None, request_count=1
        )
        return {
            "domain": normalized, "tld": tld, "prediction": "safe", "score": 0.0,
            "entropy": round(entropy, 3), "digit_count": digit_count, "domain_length": len(normalized),
            "explanation": "Manual domain lookup; Pi-hole did not provide a blocking decision.",
            "shap_summary": json.dumps(explanation["evidence"]),
        }
