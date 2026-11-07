
from pathlib import Path

import joblib
import pandas as pd

PROJECT_ROOT = Path(__file__).resolve().parent.parent
MODEL_FILE = PROJECT_ROOT / "models" / "threat_classifier.joblib"

def predict_activity(
    failed_attempts: int,
    unique_usernames: int,
    events_per_minute: int,
    success_after_failures: int,
) -> dict:

    # Check that the trained model exists
    if not MODEL_FILE.exists():
        raise FileNotFoundError(
            "Model not found. Run python src/ml_model.py first."
        )

    # Load the saved model
    saved_model = joblib.load(MODEL_FILE)
    model = saved_model["model"]
    features = saved_model["features"]

    # Prepare new activity for prediction
    activity = pd.DataFrame(
        [[
            failed_attempts,
            unique_usernames,
            events_per_minute,
            success_after_failures,
        ]],
        columns=features,
    )

    # Predict activity
    prediction = int(model.predict(activity)[0])

    if prediction == 1:
        result = "Suspicious"
        severity = "High"
    else:
        result = "Normal"
        severity = "Low"

    return {
        "prediction": result,
        "severity": severity,
    }

if __name__ == "__main__":

    # Example suspicious login activity
    result = predict_activity(
        failed_attempts=8,
        unique_usernames=3,
        events_per_minute=10,
        success_after_failures=0,
    )

    print("\nCyber Threat Detection Result")
    print("-----------------------------")
    print(f"Prediction: {result['prediction']}")
    print(f"Severity: {result['severity']}")