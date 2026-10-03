from pathlib import Path

import pandas as pd

from app.feature_extraction import extract_features


BASE_DIR = Path(__file__).resolve().parent

INPUT_PATH = BASE_DIR / "domain_only_raw.csv"
OUTPUT_PATH = BASE_DIR / "domain_only_features.csv"


FEATURE_NAMES = [
    "Length",
    "SubdomainCount",
    "Entropy",
    "DigitRatio",
    "HyphenCount",
    "VowelRatio",
    "ConsonantRatio",
    "LongestConsecutiveConsonants",
    "NgramSuspicionScore",
    "TldRiskScore",
]


print("=" * 70)
print("XAI-PiBlock Domain Feature Builder")
print("=" * 70)

print("\nLoading raw dataset...")

df = pd.read_csv(INPUT_PATH)

print(f"Rows: {len(df)}")


rows = []

for index, row in df.iterrows():

    domain = row["Domain"]
    label = int(row["Label"])

    features = extract_features(domain)

    feature_row = {
        "Domain": domain,
        **features.to_dict(),
        "Label": label,
    }

    rows.append(feature_row)


feature_df = pd.DataFrame(rows)


# Ensure column order

feature_df = feature_df[
    [
        "Domain",
        *FEATURE_NAMES,
        "Label",
    ]
]


feature_df.to_csv(
    OUTPUT_PATH,
    index=False,
)


print("\n" + "=" * 70)
print("FEATURE DATASET CREATED")
print("=" * 70)

print(f"\nOutput: {OUTPUT_PATH}")
print(f"Rows: {len(feature_df)}")
print(f"Columns: {len(feature_df.columns)}")

print("\nLabel distribution:")
print(feature_df["Label"].value_counts().sort_index())

print("\nMissing values:")
print(feature_df.isna().sum())

print("\nFeature preview:")
print(
    feature_df.head(10).to_string(index=False)
)

print("\nFeature dataset creation complete.")