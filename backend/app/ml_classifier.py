"""Machine-learning domain classifier for XAI-PiBlock.

This module loads the trained domain classification model and provides
malicious-domain predictions independently of Pi-hole's own decision.
"""

from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd

from app.feature_extraction import extract_features


class DomainMLClassifier:
    """Loads and runs the trained malicious-domain classifier."""

    def __init__(self) -> None:
        model_path = (
            Path(__file__).resolve().parent.parent
            / "ml"
            / "domain_model.joblib"
        )

        if not model_path.exists():
            raise FileNotFoundError(
                f"ML model not found: {model_path}"
            )

        package = joblib.load(model_path)

        self.model = package["model"]
        self.feature_names = package["feature_names"]
        self.block_threshold = float(
            package.get("block_threshold", 0.90)
        )

    def predict(self, domain: str) -> dict:
        """Predict whether a domain is malicious."""

        normalized_domain = domain.strip().lower().rstrip(".")

        features = extract_features(normalized_domain)

        feature_vector = pd.DataFrame(
            [
                [
                    getattr(features, name)
                    for name in self.feature_names
                ]
            ],
            columns=self.feature_names,
        )

        probability = float(
            self.model.predict_proba(feature_vector)[0][1]
        )

        is_malicious = probability >= self.block_threshold

        return {
            "domain": normalized_domain,
            "probability": round(probability, 4),
            "is_malicious": is_malicious,
            "decision": "BLOCK" if is_malicious else "ALLOW",
            "threshold": self.block_threshold,
        }


# ---------------------------------------------------------
# Manual test
# ---------------------------------------------------------

if __name__ == "__main__":

    classifier = DomainMLClassifier()

    test_domains = [
        "google.com",
        "xkq7vbzwqmpz.tk",
        "151.235.31.133",
    ]

    print("=" * 60)
    print("DOMAIN ML CLASSIFIER TEST")
    print("=" * 60)

    for domain in test_domains:
        result = classifier.predict(domain)

        print(f"\nDomain      : {result['domain']}")
        print(f"Probability : {result['probability']}")
        print(f"Malicious   : {result['is_malicious']}")
        print(f"Decision    : {result['decision']}")