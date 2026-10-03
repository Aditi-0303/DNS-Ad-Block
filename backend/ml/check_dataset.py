import pandas as pd


DATASET_PATH = r".\ml\training_features.csv"

EXPECTED_FEATURES = [
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


print("=" * 60)
print("XAI-PiBlock Dataset Verification")
print("=" * 60)


# ------------------------------------------------------------
# Load dataset
# ------------------------------------------------------------

df = pd.read_csv(DATASET_PATH)


# ------------------------------------------------------------
# Basic information
# ------------------------------------------------------------

print("\nDataset shape:")
print(f"Rows    : {df.shape[0]}")
print(f"Columns : {df.shape[1]}")


# ------------------------------------------------------------
# Columns
# ------------------------------------------------------------

print("\nColumns found:")

for column in df.columns:
    print(f"  - {column}")


# ------------------------------------------------------------
# Check required columns
# ------------------------------------------------------------

required_columns = ["Domain"] + EXPECTED_FEATURES + ["Label"]

missing_columns = [
    column
    for column in required_columns
    if column not in df.columns
]

if missing_columns:
    print("\nERROR: Missing columns:")
    for column in missing_columns:
        print(f"  - {column}")

    raise SystemExit(1)

print("\nAll required columns are present.")


# ------------------------------------------------------------
# Label distribution
# ------------------------------------------------------------

print("\nLabel distribution:")

print(df["Label"].value_counts().sort_index())


# ------------------------------------------------------------
# Check labels
# ------------------------------------------------------------

unique_labels = set(df["Label"].dropna().unique())

print("\nUnique labels:")
print(unique_labels)

if not unique_labels.issubset({0, 1}):
    print("\nERROR: Label column must contain only 0 and 1.")
    raise SystemExit(1)

print("Labels are valid: 0 = benign, 1 = malicious.")


# ------------------------------------------------------------
# Missing values
# ------------------------------------------------------------

print("\nMissing values:")

missing_values = df[required_columns].isnull().sum()

print(missing_values)

if missing_values.sum() > 0:
    print("\nWARNING: Dataset contains missing values.")
else:
    print("No missing values found.")


# ------------------------------------------------------------
# Duplicate domains
# ------------------------------------------------------------

duplicate_domains = df["Domain"].duplicated().sum()

print("\nDuplicate domains:")
print(duplicate_domains)


# ------------------------------------------------------------
# Feature data types
# ------------------------------------------------------------

print("\nFeature data types:")

for feature in EXPECTED_FEATURES:
    print(f"{feature:35} {df[feature].dtype}")


# ------------------------------------------------------------
# Basic feature statistics
# ------------------------------------------------------------

print("\nFeature statistics:")

print(df[EXPECTED_FEATURES].describe().transpose())


# ------------------------------------------------------------
# Class percentages
# ------------------------------------------------------------

total = len(df)

benign_count = int((df["Label"] == 0).sum())
malicious_count = int((df["Label"] == 1).sum())

print("\nClass distribution:")

print(f"Total     : {total}")
print(f"Benign    : {benign_count}")
print(f"Malicious : {malicious_count}")

if total > 0:
    print(
        f"Malicious percentage: "
        f"{(malicious_count / total) * 100:.2f}%"
    )


# ------------------------------------------------------------
# Final result
# ------------------------------------------------------------

print("\n" + "=" * 60)
print("DATASET VERIFICATION COMPLETE")
print("=" * 60)