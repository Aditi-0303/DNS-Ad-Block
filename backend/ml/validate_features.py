from pathlib import Path
import sys

import pandas as pd


# Allow importing from backend/app
BACKEND_DIR = Path(__file__).resolve().parent.parent

if str(BACKEND_DIR) not in sys.path:
    sys.path.insert(0, str(BACKEND_DIR))


from app.feature_extraction import (
    extract_feature_dict,
    FEATURE_NAMES,
)


# ============================================================
# Configuration
# ============================================================

DATASET_PATH = Path(__file__).resolve().parent / "training_features.csv"

SAMPLE_SIZE = 20
TOLERANCE = 1e-5


# ============================================================
# Load dataset
# ============================================================

print("=" * 70)
print("XAI-PiBlock Feature Parity Test")
print("=" * 70)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Dataset rows: {len(df)}")


# ============================================================
# Select deterministic sample
# ============================================================

sample = df.sample(
    n=min(SAMPLE_SIZE, len(df)),
    random_state=42,
)


# ============================================================
# Compare features
# ============================================================

total_comparisons = 0
mismatches = []

print(
    f"\nComparing {len(sample)} randomly selected domains..."
)


for _, row in sample.iterrows():

    domain = str(row["Domain"])

    calculated = extract_feature_dict(domain)

    for feature_name in FEATURE_NAMES:

        expected = float(row[feature_name])
        actual = float(calculated[feature_name])

        total_comparisons += 1

        difference = abs(
            expected - actual
        )

        if difference > TOLERANCE:

            mismatches.append(
                {
                    "domain": domain,
                    "feature": feature_name,
                    "dataset_value": expected,
                    "python_value": actual,
                    "difference": difference,
                }
            )


# ============================================================
# Results
# ============================================================

print("\n" + "=" * 70)
print("RESULT")
print("=" * 70)

print(
    f"\nTotal feature comparisons: {total_comparisons}"
)

print(
    f"Mismatches: {len(mismatches)}"
)


if not mismatches:

    print("\n✅ FEATURE PARITY PASSED")

    print(
        "\nThe Python feature extractor matches "
        "the values stored in the training dataset."
    )

else:

    print("\n❌ FEATURE PARITY FAILED")

    print(
        "\nThe following differences were found:\n"
    )

    for mismatch in mismatches[:20]:

        print(
            f"Domain       : {mismatch['domain']}"
        )

        print(
            f"Feature      : {mismatch['feature']}"
        )

        print(
            f"Dataset      : {mismatch['dataset_value']}"
        )

        print(
            f"Python       : {mismatch['python_value']}"
        )

        print(
            f"Difference   : {mismatch['difference']}"
        )

        print("-" * 70)

    raise SystemExit(1)


print("\nFeature validation complete.")