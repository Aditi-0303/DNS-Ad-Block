"""SHAP explanations for the domain-only ML classifier."""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd
import shap

from app.feature_extraction import extract_features


class DomainSHAPExplainer:
    """Generate SHAP explanations for the domain-only ML model."""

    def __init__(self) -> None:

        model_path = (
            Path(__file__).resolve().parent.parent
            / "ml"
            / "domain_only_model.joblib"
        )

        if not model_path.exists():
            raise FileNotFoundError(
                f"Domain-only ML model not found: {model_path}"
            )

        package = joblib.load(model_path)

        self.model = package["model"]
        self.feature_names = package["feature_names"]

        self.explainer = shap.TreeExplainer(
            self.model
        )

    def _human_readable_reason(
        self,
        feature: str,
        value: float,
        shap_value: float,
    ) -> str:

        direction = (
            "increased the malicious prediction"
            if shap_value > 0
            else "pushed the prediction toward benign"
        )

        strength = abs(shap_value)

        if strength >= 1.0:
            intensity = "strongly"
        elif strength >= 0.1:
            intensity = "moderately"
        else:
            intensity = "slightly"

        explanations = {
            "Length": (
                f"The domain length ({value:g}) "
                f"{intensity} {direction}."
            ),
            "Entropy": (
                f"The domain entropy ({value:.3f}) "
                f"{intensity} {direction}."
            ),
            "DigitRatio": (
                f"The digit ratio ({value:.3f}) "
                f"{intensity} {direction}."
            ),
            "HyphenCount": (
                f"The number of hyphens ({value:g}) "
                f"{intensity} {direction}."
            ),
            "VowelRatio": (
                f"The vowel ratio ({value:.3f}) "
                f"{intensity} {direction}."
            ),
            "ConsonantRatio": (
                f"The consonant ratio ({value:.3f}) "
                f"{intensity} {direction}."
            ),
            "LongestConsecutiveConsonants": (
                f"The longest consecutive consonant "
                f"sequence ({value:g}) {intensity} "
                f"{direction}."
            ),
            "NgramSuspicionScore": (
                f"The suspicious n-gram score "
                f"({value:.3f}) {intensity} {direction}."
            ),
            "SubdomainCount": (
                f"The number of subdomains ({value:g}) "
                f"{intensity} {direction}."
            ),
            "TldRiskScore": (
                f"The TLD risk score ({value:.3f}) "
                f"{intensity} {direction}."
            ),
        }

        return explanations.get(
            feature,
            f"{feature} {intensity} {direction}.",
        )

    def explain(
        self,
        domain: str,
    ) -> dict:
        """Return SHAP feature contributions."""

        normalized_domain = (
            domain
            .strip()
            .lower()
            .rstrip(".")
        )

        features = extract_features(
            normalized_domain
        )

        feature_vector = pd.DataFrame(
            [
                [
                    getattr(
                        features,
                        name,
                    )
                    for name in self.feature_names
                ]
            ],
            columns=self.feature_names,
        )

        shap_values = self.explainer.shap_values(
            feature_vector
        )

        values = shap_values[0]

        contributions = []

        for (
            name,
            value,
            feature_value,
        ) in zip(
            self.feature_names,
            values,
            feature_vector.iloc[0].tolist(),
        ):

            contributions.append(
                {
                    "feature": name,
                    "value": round(
                        float(feature_value),
                        6,
                    ),
                    "shap_value": round(
                        float(value),
                        6,
                    ),
                    "impact": (
                        "malicious"
                        if value > 0
                        else "benign"
                    ),
                    "reason": self._human_readable_reason(
                        name,
                        float(feature_value),
                        float(value),
                    ),
                }
            )

        contributions.sort(
            key=lambda item: abs(
                item["shap_value"]
            ),
            reverse=True,
        )

        expected_value = self.explainer.expected_value

        if hasattr(
            expected_value,
            "__len__",
        ):
            expected_value = expected_value[0]

        return {
            "domain": normalized_domain,
            "base_value": round(
                float(expected_value),
                6,
            ),
            "features": contributions,
        }


if __name__ == "__main__":

    explainer = DomainSHAPExplainer()

    for domain in (
        "google.com",
        "ahva.binglide.info",
    ):

        result = explainer.explain(
            domain
        )

        print("\nDomain:", domain)
        print("Base value:", result["base_value"])

        for feature in result["features"][:5]:
            print(
                feature["feature"],
                "=>",
                feature["shap_value"],
                "|",
                feature["impact"],
            )