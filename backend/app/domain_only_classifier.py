from __future__ import annotations

from pathlib import Path

import joblib
import pandas as pd

from app.feature_extraction import extract_features


class DomainOnlyMLClassifier:
    """Runs the domain-only ML model as an additional analysis layer."""

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

        self.feature_names = package[
            "feature_names"
        ]

        self.block_threshold = float(
            package.get(
                "block_threshold",
                0.90,
            )
        )

    def predict(
        self,
        domain: str,
    ) -> dict:

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

        probability = float(
            self.model.predict_proba(
                feature_vector
            )[0][1]
        )

        is_suspicious = (
            probability
            >= self.block_threshold
        )

        return {
            "domain": normalized_domain,
            "probability": round(
                probability,
                4,
            ),
            "is_suspicious": is_suspicious,
            "decision": (
                "BLOCK"
                if is_suspicious
                else "ALLOW"
            ),
            "threshold": (
                self.block_threshold
            ),
        }


if __name__ == "__main__":

    classifier = DomainOnlyMLClassifier()

    test_domains = [
        "google.com",
        "ahva.binglide.info",
        "hal-cert.net",
    ]

    print("=" * 70)
    print("DOMAIN-ONLY ML CLASSIFIER TEST")
    print("=" * 70)

    for domain in test_domains:

        result = classifier.predict(
            domain
        )

        print(
            f"\nDomain      : "
            f"{result['domain']}"
        )

        print(
            f"Probability : "
            f"{result['probability']}"
        )

        print(
            f"Suspicious  : "
            f"{result['is_suspicious']}"
        )

        print(
            f"Decision    : "
            f"{result['decision']}"
        )