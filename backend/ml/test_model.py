from pathlib import Path
import sys

import joblib
import pandas as pd

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.feature_extraction import extract_features


BASE_DIR = Path(__file__).resolve().parent

MODEL_PATH = BASE_DIR / "domain_model.joblib"
DATASET_PATH = BASE_DIR / "training_features.csv"


# ---------------------------------------------------------
# Load model
# ---------------------------------------------------------

package = joblib.load(MODEL_PATH)

model = package["model"]
feature_names = package["feature_names"]
block_threshold = package["block_threshold"]


# ---------------------------------------------------------
# Prediction function
# ---------------------------------------------------------

def predict_domain(domain: str):
    features = extract_features(domain)

    feature_vector = pd.DataFrame(
        [[getattr(features, name) for name in feature_names]],
        columns=feature_names,
    )

    probability = float(
        model.predict_proba(feature_vector)[0][1]
    )

    malicious = probability >= block_threshold

    return {
        "domain": domain,
        "probability": probability,
        "malicious": malicious,
        "decision": "BLOCK" if malicious else "ALLOW",
    }


# ---------------------------------------------------------
# Load dataset
# ---------------------------------------------------------

df = pd.read_csv(DATASET_PATH)


# ---------------------------------------------------------
# Select known malicious domains
# ---------------------------------------------------------

malicious_domains = (
    df[df["Label"] == 1]["Domain"]
    .drop_duplicates()
    .sample(
        n=10,
        random_state=42
    )
    .tolist()
)


# ---------------------------------------------------------
# Select known benign domains
# ---------------------------------------------------------

benign_domains = (
    df[df["Label"] == 0]["Domain"]
    .drop_duplicates()
    .sample(
        n=10,
        random_state=42
    )
    .tolist()
)


# ---------------------------------------------------------
# Test malicious domains
# ---------------------------------------------------------

print("=" * 70)
print("XAI-PiBlock ML MODEL VALIDATION")
print("=" * 70)

print("\nKNOWN MALICIOUS DOMAINS")
print("-" * 70)

malicious_correct = 0

for domain in malicious_domains:

    result = predict_domain(domain)

    if result["malicious"]:
        malicious_correct += 1

    print(
        f"{domain:<40} "
        f"Probability: {result['probability']:.4f}   "
        f"Decision: {result['decision']}"
    )


# ---------------------------------------------------------
# Test benign domains
# ---------------------------------------------------------

print("\nKNOWN BENIGN DOMAINS")
print("-" * 70)

benign_correct = 0

for domain in benign_domains:

    result = predict_domain(domain)

    if not result["malicious"]:
        benign_correct += 1

    print(
        f"{domain:<40} "
        f"Probability: {result['probability']:.4f}   "
        f"Decision: {result['decision']}"
    )


# ---------------------------------------------------------
# Summary
# ---------------------------------------------------------

print("\n" + "=" * 70)
print("TEST SUMMARY")
print("=" * 70)

print(
    f"\nMalicious blocked: "
    f"{malicious_correct}/{len(malicious_domains)}"
)

print(
    f"Benign allowed:    "
    f"{benign_correct}/{len(benign_domains)}"
)

print(
    f"\nBlocking threshold: "
    f"{block_threshold:.2f}"
)

print("=" * 70)