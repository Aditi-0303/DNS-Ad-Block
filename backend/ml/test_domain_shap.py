from pathlib import Path

import joblib
import pandas as pd
import shap

from app.feature_extraction import extract_feature_dict


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "domain_only_model.joblib"


# ---------------------------------------------------------
# Load model
# ---------------------------------------------------------

package = joblib.load(MODEL_PATH)

model = package["model"]
feature_names = package["feature_names"]


explainer = shap.TreeExplainer(model)


# ---------------------------------------------------------
# Test domains
# ---------------------------------------------------------

test_domains = [
    "google.com",
    "ahva.binglide.info",
    "hal-cert.net",
]


# ---------------------------------------------------------
# SHAP test
# ---------------------------------------------------------

print("=" * 70)
print("XAI-PiBlock Domain-Only SHAP Test")
print("=" * 70)


for domain in test_domains:

    feature_dict = extract_feature_dict(domain)

    feature_vector = pd.DataFrame(
        [
            [
                feature_dict[name]
                for name in feature_names
            ]
        ],
        columns=feature_names,
    )

    probability = model.predict_proba(
        feature_vector
    )[0][1]

    shap_values = explainer.shap_values(
        feature_vector
    )

    values = shap_values[0]

    print("\n" + "-" * 70)
    print(f"Domain      : {domain}")
    print(f"Probability : {probability:.4f}")

    print("\nFeature contributions:")

    contributions = []

    for name, feature_value, shap_value in zip(
        feature_names,
        feature_vector.iloc[0].tolist(),
        values,
    ):
        contributions.append(
            (
                name,
                feature_value,
                float(shap_value),
            )
        )

    contributions.sort(
        key=lambda x: abs(x[2]),
        reverse=True,
    )

    for name, feature_value, shap_value in contributions:

        impact = (
            "MALICIOUS"
            if shap_value > 0
            else "BENIGN"
        )

        print(
            f"{name:<35} "
            f"value={feature_value:<10.4f} "
            f"SHAP={shap_value:<10.4f} "
            f"{impact}"
        )