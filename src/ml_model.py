
from pathlib import Path

import joblib
import pandas as pd

from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.model_selection import train_test_split

FEATURES = [
    "failed_attempts",
    "unique_usernames",
    "events_per_minute",
    "success_after_failures",
]

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_FILE = PROJECT_ROOT / "data" / "ml_training_data.csv"
MODEL_DIR = PROJECT_ROOT / "models"
MODEL_FILE = MODEL_DIR / "threat_classifier.joblib"

def train_model():
    # Load training dataset
    data = pd.read_csv(DATA_FILE)

    required_columns = FEATURES + ["label"]
    missing = set(required_columns) - set(data.columns)

    if missing:
        raise ValueError(f"Missing columns: {sorted(missing)}")

    if data[required_columns].isnull().any().any():
        raise ValueError("Training data contains missing values.")

    if not set(data["label"].unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 (Normal) or 1 (Suspicious).")

    X = data[FEATURES]
    y = data["label"]

    if y.nunique() != 2 or y.value_counts().min() < 2:
        raise ValueError("At least two examples of each class are required.")

    # Split data into training and testing sets
    X_train, X_test, y_train, y_test = train_test_split(
        X,
        y,
        test_size=0.25,
        random_state=42,
        stratify=y,
    )

    # Create and train Random Forest model
    model = RandomForestClassifier(
        n_estimators=100,
        random_state=42,
        class_weight="balanced",
    )

    model.fit(X_train, y_train)

    # Evaluate model
    predictions = model.predict(X_test)

    print("\nModel Evaluation")
    print("----------------")
    print("Confusion Matrix:")
    print(confusion_matrix(y_test, predictions))

    print("\nClassification Report:")
    print(
        classification_report(
            y_test,
            predictions,
            target_names=["Normal", "Suspicious"],
            zero_division=0,
        )
    )

    # Save trained model and feature information
    MODEL_DIR.mkdir(parents=True, exist_ok=True)

    joblib.dump(
        {
            "model": model,
            "features": FEATURES,
        },
        MODEL_FILE,
    )

    print(f"\nModel saved successfully: {MODEL_FILE}")

if __name__ == "__main__":
    train_model()