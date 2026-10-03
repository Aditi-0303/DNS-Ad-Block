
"""Transparent enrichment for Pi-hole events.

Pi-hole decides whether a DNS query is blocked. This module never changes
that decision. It provides user-facing explanations and supplementary
machine-learning analysis.
"""

from __future__ import annotations

import json
import math
from dataclasses import dataclass

from app.ml_classifier import DomainMLClassifier
from app.domain_only_classifier import DomainOnlyMLClassifier
from app.shap_explainer import DomainSHAPExplainer


@dataclass(frozen=True)
class CategoryRule:
    category: str
    terms: tuple[str, ...]
    description: str


CATEGORY_RULES = (
    CategoryRule(
        "advertising",
        (
            "adserver",
            "ads",
            "doubleclick",
            "adnxs",
            "banner",
        ),
        "serves or measures advertising",
    ),
    CategoryRule(
        "tracking",
        (
            "analytics",
            "track",
            "telemetry",
            "metrics",
            "pixel",
        ),
        "collects cross-site or product usage data",
    ),
    CategoryRule(
        "malware",
        (
            "malware",
            "phish",
            "exploit",
            "botnet",
        ),
        "matches a security-related indicator",
    ),
    CategoryRule(
        "telemetry",
        (
            "sentry",
            "crash",
            "diagnostic",
            "beacon",
        ),
        "sends application diagnostics or telemetry",
    ),
)


# These domains/services can be important for application functionality.
# This score is advisory and never changes the Pi-hole decision.
SERVICE_TERMS = (
    "accounts.google",
    "microsoftonline",
    "icloud",
    "cloudfront",
    "amazonaws",
    "stripe",
    "youtube",
)


class DomainAnalyzer:
    """Domain analyser plus Pi-hole explanation builder."""

    def __init__(self) -> None:

        # Existing ML model.
        # This remains unchanged.
        self.ml_classifier = DomainMLClassifier()

        # New domain-only ML model.
        self.domain_only_classifier = (
            DomainOnlyMLClassifier()
        )

        # Existing SHAP explainer.
        self.shap_explainer = (
            DomainSHAPExplainer()
        )

    # =========================================================
    # Existing ML model
    # =========================================================

    def predict_with_ml(
        self,
        domain: str,
    ) -> dict:
        """Run the existing ML classifier."""

        return self.ml_classifier.predict(
            domain
        )

    # =========================================================
    # New domain-only ML model
    # =========================================================

    def predict_with_domain_only_ml(
        self,
        domain: str,
    ) -> dict:
        """Run the new domain-only ML classifier."""

        return self.domain_only_classifier.predict(
            domain
        )

    # =========================================================
    # Existing SHAP
    # =========================================================

    def explain_with_shap(
        self,
        domain: str,
    ) -> dict:
        """Explain the existing ML model using SHAP."""

        return self.shap_explainer.explain(
            domain
        )

    # =========================================================
    # Utility methods
    # =========================================================

    def _calculate_entropy(
        self,
        value: str,
    ) -> float:

        if not value:
            return 0.0

        length = float(len(value))

        return -sum(
            (count / length)
            * math.log(
                count / length,
                2,
            )
            for count in (
                value.count(char)
                for char in set(value)
            )
        )

    def _category(
        self,
        domain: str,
        matched_rule: str | None,
        list_source: str | None,
    ) -> tuple[str, str | None]:

        searchable = " ".join(
            filter(
                None,
                (
                    domain,
                    matched_rule,
                    list_source,
                ),
            )
        ).lower()

        for rule in CATEGORY_RULES:

            matched_term = next(
                (
                    term
                    for term in rule.terms
                    if term in searchable
                ),
                None,
            )

            if matched_term:

                return (
                    rule.category,
                    rule.description,
                )

        return "unknown", None

    # =========================================================
    # Pi-hole explanation
    # =========================================================

    def explain_pihole_event(
        self,
        *,
        domain: str,
        blocked: bool,
        matched_rule: str | None,
        list_source: str | None,
        request_count: int,
    ) -> dict:

        category, category_detail = (
            self._category(
                domain,
                matched_rule,
                list_source,
            )
        )

        evidence: list[dict] = []

        if blocked:

            evidence.append(
                {
                    "label": "Pi-hole decision",
                    "detail": (
                        "Pi-hole returned this "
                        "query as blocked."
                    ),
                    "weight": 1.0,
                }
            )

            if matched_rule:

                evidence.append(
                    {
                        "label": "Matched rule",
                        "detail": (
                            f"The query matched "
                            f"`{matched_rule}`."
                        ),
                        "weight": 0.95,
                    }
                )

            if list_source:

                evidence.append(
                    {
                        "label": "Block source",
                        "detail": (
                            f"The rule came from "
                            f"{list_source}."
                        ),
                        "weight": 0.9,
                    }
                )

            if category_detail:

                evidence.append(
                    {
                        "label": "Category evidence",
                        "detail": (
                            f"The domain/rule contains "
                            f"a {category} indicator and "
                            f"likely {category_detail}."
                        ),
                        "weight": 0.65,
                    }
                )

        else:

            evidence.append(
                {
                    "label": "Pi-hole decision",
                    "detail": (
                        "Pi-hole allowed this query; "
                        "no blocking rule was reported."
                    ),
                    "weight": 1.0,
                }
            )

        service_match = next(
            (
                term
                for term in SERVICE_TERMS
                if term in domain.lower()
            ),
            None,
        )

        score = 0.0

        if blocked and not matched_rule:
            score += 0.35

        if service_match:

            score += 0.45

            evidence.append(
                {
                    "label": "Compatibility signal",
                    "detail": (
                        f"`{service_match}` can be part "
                        "of an application or delivery "
                        "service, so review before keeping "
                        "it blocked."
                    ),
                    "weight": 0.45,
                }
            )

        if category == "unknown":
            score += 0.20

        if request_count > 100:
            score += 0.10

        score = round(
            min(score, 1.0),
            2,
        )

        risk = (
            "high"
            if score >= 0.65
            else "medium"
            if score >= 0.35
            else "low"
        )

        if not blocked:

            block_reason = (
                "Allowed by Pi-hole; no matching "
                "block rule was supplied."
            )

        elif matched_rule and list_source:

            block_reason = (
                f"Blocked because Pi-hole matched "
                f"`{matched_rule}` from "
                f"{list_source}."
            )

        elif matched_rule:

            block_reason = (
                f"Blocked because Pi-hole matched "
                f"`{matched_rule}`."
            )

        elif list_source:

            block_reason = (
                f"Blocked by a Pi-hole rule from "
                f"{list_source}; the exact rule "
                "was not supplied."
            )

        else:

            block_reason = (
                "Blocked by Pi-hole; import the "
                "matched rule and list source for "
                "a fuller explanation."
            )

        activity = (
            f"This domain was requested "
            f"{request_count} time"
            f"{'s' if request_count != 1 else ''}."
        )

        impact_summary = (
            f"Allowing it may restore "
            f"{category} traffic. {activity}"
            if blocked
            else
            f"No block impact. {activity}"
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

    # =========================================================
    # Main analysis
    # =========================================================

    def analyze(
        self,
        domain: str,
    ) -> dict:
        """Analyze a domain without overriding Pi-hole."""

        normalized = (
            domain
            .strip()
            .lower()
            .rstrip(".")
        )

        tld = (
            normalized.rsplit(".", 1)[-1]
            if "." in normalized
            else ""
        )

        entropy = self._calculate_entropy(
            normalized
        )

        digit_count = sum(
            char.isdigit()
            for char in normalized
        )

        # -----------------------------------------------------
        # Existing ML model
        # -----------------------------------------------------

        ml_result = self.predict_with_ml(
            normalized
        )

        # -----------------------------------------------------
        # New domain-only ML model
        # -----------------------------------------------------

        domain_only_result = (
            self.predict_with_domain_only_ml(
                normalized
            )
        )

        # -----------------------------------------------------
        # Existing SHAP explanation
        # -----------------------------------------------------

        shap_result = self.explain_with_shap(
            normalized
        )

        # -----------------------------------------------------
        # Pi-hole explanation
        # -----------------------------------------------------

        pihole_explanation = (
            self.explain_pihole_event(
                domain=normalized,
                blocked=False,
                matched_rule=None,
                list_source=None,
                request_count=1,
            )
        )

        # -----------------------------------------------------
        # Domain-only ML interpretation
        # -----------------------------------------------------

        domain_only_decision = (
            "SUSPICIOUS"
            if domain_only_result[
                "is_suspicious"
            ]
            else "LOW_RISK"
        )

        # -----------------------------------------------------
        # Return combined analysis
        # -----------------------------------------------------

        return {

            # =================================================
            # Basic domain information
            # =================================================

            "domain": normalized,

            "tld": tld,

            "entropy": round(
                entropy,
                3,
            ),

            "digit_count": digit_count,

            "domain_length": len(
                normalized
            ),

            # =================================================
            # Existing ML model
            # =================================================

            "prediction": (
                "malicious"
                if ml_result[
                    "is_malicious"
                ]
                else "safe"
            ),

            "ml_probability": (
                ml_result[
                    "probability"
                ]
            ),

            "ml_decision": (
                ml_result[
                    "decision"
                ]
            ),

            "ml_threshold": (
                ml_result[
                    "threshold"
                ]
            ),

            "score": round(
                ml_result[
                    "probability"
                ] * 100,
                2,
            ),

            "explanation": (
                "ML classifier detected a "
                "high-confidence malicious domain."
                if ml_result[
                    "is_malicious"
                ]
                else
                "ML classifier did not detect "
                "sufficient evidence of malicious "
                "activity."
            ),

            # =================================================
            # New domain-only ML model
            # =================================================

            "domain_only_ml_probability": (
                domain_only_result[
                    "probability"
                ]
            ),

            "domain_only_ml_decision": (
                domain_only_decision
            ),

            "domain_only_ml_threshold": (
                domain_only_result[
                    "threshold"
                ]
            ),

            "domain_only_ml_suspicious": (
                domain_only_result[
                    "is_suspicious"
                ]
            ),

            # =================================================
            # SHAP
            # =================================================

            "shap_summary": json.dumps(
                shap_result[
                    "features"
                ]
            ),

            # =================================================
            # Pi-hole explanation
            # =================================================

            "pihole_explanation": (
                pihole_explanation
            ),
        }

    