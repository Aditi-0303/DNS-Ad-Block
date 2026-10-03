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


BASE_DIR = Path(__file__).resolve().parent

DATASET_PATH = BASE_DIR / "domain_only_features.csv"
MODEL_PATH = BASE_DIR / "domain_only_model.joblib"
METRICS_PATH = BASE_DIR / "domain_only_metrics.json"


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
print("XAI-PiBlock Domain-Only ML Training")
print("=" * 70)


# ------------------------------------------------------------
# Load
# ------------------------------------------------------------

df = pd.read_csv(DATASET_PATH)

print("\nDataset:")
print(f"Rows: {len(df)}")
print(f"Benign: {(df.Label == 0).sum()}")
print(f"Malicious: {(df.Label == 1).sum()}")


# ------------------------------------------------------------
# Prepare
# ------------------------------------------------------------

X = df[FEATURE_NAMES]
y = df["Label"].astype(int)


# ------------------------------------------------------------
# Train/test split
# ------------------------------------------------------------

X_train, X_test, y_train, y_test = train_test_split(
    X,
    y,
    test_size=0.20,
    random_state=42,
    stratify=y,
)


print("\nSplit:")
print(f"Training: {len(X_train)}")
print(f"Testing : {len(X_test)}")


# ------------------------------------------------------------
# Model
# ------------------------------------------------------------

model = GradientBoostingClassifier(
    n_estimators=100,
    max_leaf_nodes=20,
    min_samples_leaf=10,
    random_state=42,
)


print("\nTraining...")

model.fit(
    X_train,
    y_train,
)

print("Training complete.")


# ------------------------------------------------------------
# Predictions
# ------------------------------------------------------------

y_probability = model.predict_proba(
    X_test
)[:, 1]


threshold = 0.60

y_pred = (
    y_probability >= threshold
).astype(int)


# ------------------------------------------------------------
# Metrics
# ------------------------------------------------------------

accuracy = accuracy_score(
    y_test,
    y_pred,
)

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


# ------------------------------------------------------------
# Results
# ------------------------------------------------------------

print("\n" + "=" * 70)
print("DOMAIN-ONLY MODEL RESULTS")
print("=" * 70)

print(f"\nAccuracy : {accuracy:.4f}")
print(f"ROC-AUC  : {roc_auc:.4f}")
print(f"PR-AUC   : {pr_auc:.4f}")
print(f"Precision: {precision:.4f}")
print(f"Recall   : {recall:.4f}")
print(f"F1 Score : {f1:.4f}")

print("\nConfusion Matrix:")
print(cm)

print("\nClassification Report:")

print(
    classification_report(
        y_test,
        y_pred,
        target_names=[
            "Benign",
            "Malicious",
        ],
        zero_division=0,
    )
)


# ------------------------------------------------------------
# Save model
# ------------------------------------------------------------

model_package = {
    "model": model,
    "feature_names": FEATURE_NAMES,
    "block_threshold": threshold,
    "random_state": 42,
    "model_type": "GradientBoostingClassifier",
    "training_type": "domain_only",
}


joblib.dump(
    model_package,
    MODEL_PATH,
)


print("\nModel saved:")
print(MODEL_PATH)


# ------------------------------------------------------------
# Save metrics
# ------------------------------------------------------------

metrics = {
    "dataset_rows": int(len(df)),
    "benign_samples": int(
        (y == 0).sum()
    ),
    "malicious_samples": int(
        (y == 1).sum()
    ),
    "test_samples": int(
        len(X_test)
    ),
    "accuracy": float(
        accuracy
    ),
    "roc_auc": float(
        roc_auc
    ),
    "pr_auc": float(
        pr_auc
    ),
    "precision": float(
        precision
    ),
    "recall": float(
        recall
    ),
    "f1": float(
        f1
    ),
    "confusion_matrix": cm.tolist(),
    "model_type": (
        "GradientBoostingClassifier"
    ),
    "n_estimators": 100,
    "max_leaf_nodes": 20,
    "min_samples_leaf": 10,
    "random_state": 42,
    "block_threshold": threshold,
    "training_type": "domain_only",
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


print("\nMetrics saved:")
print(METRICS_PATH)

print("\n" + "=" * 70)
print("DOMAIN-ONLY TRAINING COMPLETE")
print("=" * 70)