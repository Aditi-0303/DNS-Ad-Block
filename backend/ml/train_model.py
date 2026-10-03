from pathlib import Path
import json

import joblib
import pandas as pd

from sklearn.ensemble import GradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split


# ---------------------------------------------------------
# Paths
# ---------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "training_features.csv"
MODEL_PATH = BASE_DIR / "domain_model.joblib"
METRICS_PATH = BASE_DIR / "training_metrics.json"


# ---------------------------------------------------------
# Features
# ---------------------------------------------------------

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


# ---------------------------------------------------------
# Load dataset
# ---------------------------------------------------------

print("=" * 60)
print("XAI-PiBlock Domain ML Training")
print("=" * 60)

print("\nLoading dataset...")

df = pd.read_csv(DATASET_PATH)

print(f"Dataset: {DATASET_PATH}")
print(f"Rows: {len(df)}")
print(f"Columns: {len(df.columns)}")


# ---------------------------------------------------------
# Prepare X and y
# ---------------------------------------------------------

X = df[FEATURE_NAMES]
y = df["Label"].astype(int)

print("\nLabel distribution:")
print(y.value_counts().sort_index())

print("\nBenign:   ", int((y == 0).sum()))
print("Malicious:", int((y == 1).sum()))


# ---------------------------------------------------------
# Train/Test split
# ---------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)

print("\nTrain/Test split:")
print(f"Training samples: {len(X_train)}")
print(f"Testing samples:  {len(X_test)}")


# ---------------------------------------------------------
# Malicious class weighting
# ---------------------------------------------------------
# Matches the original C# project's intention:
# malicious examples receive 3x training weight.

sample_weights = y_train.map({
    0: 1.0,
    1: 3.0,
}).to_numpy()


# ---------------------------------------------------------
# Model
# ---------------------------------------------------------
# GradientBoostingClassifier is used as the Python
# equivalent boosted-tree baseline.
#
# NOTE:
# ML.NET FastTree and sklearn GradientBoosting are
# different implementations, so this is not expected
# to reproduce the C# model bit-for-bit.

print("\nCreating model...")

model = GradientBoostingClassifier(
    n_estimators=100,
    max_leaf_nodes=20,
    min_samples_leaf=10,
    random_state=42,
)


# ---------------------------------------------------------
# Train
# ---------------------------------------------------------

print("Training model...")

model.fit(
    X_train,
    y_train,
    sample_weight=sample_weights,
)

print("Training completed.")


# ---------------------------------------------------------
# Predictions
# ---------------------------------------------------------

y_pred = model.predict(X_test)

# Probability of malicious class
y_probability = model.predict_proba(X_test)[:, 1]


# ---------------------------------------------------------
# Metrics
# ---------------------------------------------------------

accuracy = accuracy_score(y_test, y_pred)

roc_auc = roc_auc_score(
    y_test,
    y_probability,
)

pr_auc = average_precision_score(
    y_test,
    y_probability,
)

precision = precision_score(
    y_test,
    y_pred,
    zero_division=0,
)

recall = recall_score(
    y_test,
    y_pred,
    zero_division=0,
)

f1 = f1_score(
    y_test,
    y_pred,
    zero_division=0,
)

cm = confusion_matrix(
    y_test,
    y_pred,
)

report = classification_report(
    y_test,
    y_pred,
    target_names=["Benign", "Malicious"],
    zero_division=0,
)


# ---------------------------------------------------------
# Display results
# ---------------------------------------------------------

print("\n" + "=" * 60)
print("MODEL RESULTS")
print("=" * 60)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")
print(f"PR-AUC   : {pr_auc:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")
print(report)


# ---------------------------------------------------------
# Save model
# ---------------------------------------------------------

model_package = {
    "model": model,
    "feature_names": FEATURE_NAMES,
    "block_threshold": 0.90,
    "malicious_weight": 3.0,
    "random_state": 42,
    "model_type": "GradientBoostingClassifier",
}

joblib.dump(
    model_package,
    MODEL_PATH,
)

print(f"\nModel saved to:")
print(MODEL_PATH)


# ---------------------------------------------------------
# Save metrics
# ---------------------------------------------------------

metrics = {
    "dataset_rows": int(len(df)),
    "benign_samples": int((y == 0).sum()),
    "malicious_samples": int((y == 1).sum()),
    "test_samples": int(len(X_test)),
    "accuracy": float(accuracy),
    "roc_auc": float(roc_auc),
    "pr_auc": float(pr_auc),
    "precision": float(precision),
    "recall": float(recall),
    "f1": float(f1),
    "confusion_matrix": cm.tolist(),
    "model_type": "GradientBoostingClassifier",
    "n_estimators": 100,
    "max_leaf_nodes": 20,
    "min_samples_leaf": 10,
    "malicious_weight": 3.0,
    "random_state": 42,
    "block_threshold": 0.90,
}

with open(
    METRICS_PATH,
    "w",
    encoding="utf-8",
) as f:
    json.dump(
        metrics,
        f,
        indent=4,
    )

print("\nMetrics saved to:")
print(METRICS_PATH)

print("\n" + "=" * 60)
print("✅ MODEL TRAINING COMPLETE")
print("=" * 60)