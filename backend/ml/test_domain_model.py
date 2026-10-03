from pathlib import Path
import sys

import joblib
import pandas as pd

from app.feature_extraction import extract_feature_dict


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "domain_only_model.joblib"


# ---------------------------------------------------------
# Load model
# ---------------------------------------------------------

package = joblib.load(MODEL_PATH)

model = package["model"]
feature_names = package["feature_names"]
threshold = package["block_threshold"]


print("=" * 70)
print("XAI-PiBlock Domain-Only Model Test")
print("=" * 70)

print(f"\nModel threshold: {threshold}")


# ---------------------------------------------------------
# Test domains
# ---------------------------------------------------------

if len(sys.argv) > 1:

    # Test domain supplied from command line
    test_domains = sys.argv[1:]

else:

    # Default sanity-test domains
    test_domains = [
        "google.com",
        "youtube.com",
        "microsoft.com",
        "github.com",
        "wikipedia.org",

        "29514ffac60ab312eadf1d09fe4c361e.com",
        "ahva.binglide.info",
        "4d7255ca9b2659623.tempsite.link",
        "afcu-0nline-scn5-2g4.pages.dev",
        "aev8fk.detmir.top",
    ]


# ---------------------------------------------------------
# Prediction
# ---------------------------------------------------------

print("\nResults:")
print("-" * 70)

for domain in test_domains:

    domain = domain.strip().lower()

    feature_dict = extract_feature_dict(domain)

    X = pd.DataFrame(
        [[feature_dict[name] for name in feature_names]],
        columns=feature_names,
    )

    probability = model.predict_proba(X)[0][1]

    if probability >= threshold:
        decision = "BLOCK"
    else:
        decision = "ALLOW"

    print(
        f"{domain:<50} "
        f"Probability: {probability:.4f} "
        f"Decision: {decision}"
    )