"""Evaluate a Random Forest on a held-out labeled dataset without saving a model."""

import argparse
import numpy as np
from pathlib import Path

import pandas as pd

FEATURES = [
    "failed_attempts",
    "unique_usernames",
    "events_per_minute",
    "success_after_failures",
]
LABEL = "label"
MIN_ROWS = 40


def load_labeled_data(path: Path) -> pd.DataFrame:
    data = pd.read_csv(path)
    required = FEATURES + [LABEL]
    missing = sorted(set(required) - set(data.columns))
    if missing:
        raise ValueError(f"Missing required columns: {', '.join(missing)}")
    if data[required].isnull().any().any():
        raise ValueError("Evaluation data contains missing feature or label values.")
    try:
        data[FEATURES] = data[FEATURES].apply(pd.to_numeric, errors="raise")
        labels = pd.to_numeric(data[LABEL], errors="raise")
    except (TypeError, ValueError) as error:
        raise ValueError("Features and labels must be numeric.") from error
    if not np.isfinite(data[FEATURES].to_numpy(dtype=float)).all():
        raise ValueError("Evaluation features must be finite numeric values.")
    if not set(labels.unique()).issubset({0, 1}):
        raise ValueError("Labels must be 0 (Normal) or 1 (Suspicious).")
    if labels.nunique() != 2 or labels.value_counts().min() < 2:
        raise ValueError("Evaluation data must contain at least two examples per class.")
    if len(data) < MIN_ROWS:
        raise ValueError(
            f"Only {len(data)} labeled rows are available; at least {MIN_ROWS} "
            "are required for this held-out evaluation. Collect more authorized, "
            "representative examples first."
        )
    data[LABEL] = labels.astype(int)
    return data


def evaluate(
    path: Path | None = None,
    seed: int = 42,
    train_path: Path | None = None,
    test_path: Path | None = None,
    negative_label_name: str = "Normal",
    positive_label_name: str = "Suspicious",
) -> None:
    if (train_path is None) != (test_path is None):
        raise ValueError("Provide both --train-data and --test-data for a time-separated evaluation.")
    if train_path is not None and path is not None:
        raise ValueError("Use either --data or the --train-data/--test-data pair, not both.")

    # Import only after validating the dataset. On locked-down Windows systems,
    # this keeps the useful data-quality error available even if a native DLL
    # needed by scikit-learn is blocked by application control.
    if train_path is not None:
        train_data = load_labeled_data(train_path)
        test_data = load_labeled_data(test_path)
        train_x, train_y = train_data[FEATURES], train_data[LABEL].astype(int)
        test_x, test_y = test_data[FEATURES], test_data[LABEL].astype(int)
        print(f"Training data: {train_path} ({len(train_data)} rows)")
        print(f"Held-out data: {test_path} ({len(test_data)} rows)")
    else:
        path = path or Path(__file__).resolve().parents[1] / "data" / "ml_training_data.csv"
        data = load_labeled_data(path)
        x = data[FEATURES]
        y = data[LABEL].astype(int)
        from sklearn.model_selection import train_test_split

        train_x, test_x, train_y, test_y = train_test_split(
            x, y, test_size=0.25, random_state=seed, stratify=y
        )
        test_data = data
        print(f"Dataset: {path}")
        print(f"Rows: {len(data)} (train={len(train_x)}, held-out={len(test_x)})")
        print(f"Label counts: {data[LABEL].value_counts().sort_index().to_dict()}")

    from sklearn.ensemble import RandomForestClassifier
    model = RandomForestClassifier(
        n_estimators=100, random_state=seed, class_weight="balanced"
    )
    model.fit(train_x, train_y)
    predicted = model.predict(test_x)

    report_evaluation(
        test_data, test_x, test_y, predicted,
        negative_label_name, positive_label_name,
    )


def evaluate_saved_model(
    path: Path,
    model_path: Path | None = None,
    negative_label_name: str = "Normal",
    positive_label_name: str = "Suspicious",
) -> None:
    """Measure the checked-in model artifact on a labeled held-out CSV."""
    data = load_labeled_data(path)
    model_path = model_path or Path(__file__).resolve().parents[1] / "models" / "threat_classifier.joblib"
    import joblib

    saved = joblib.load(model_path)
    if not isinstance(saved, dict) or "model" not in saved or "features" not in saved:
        raise ValueError("Saved model artifact must contain model and features entries.")
    if saved["features"] != FEATURES:
        raise ValueError(
            "Saved model feature list does not match the evaluation schema: "
            f"{saved['features']}"
        )

    test_x = data[FEATURES]
    test_y = data[LABEL].astype(int)
    predicted = saved["model"].predict(test_x)
    print(f"Saved model: {model_path}")
    print(f"Held-out data: {path} ({len(data)} rows)")
    report_evaluation(
        data, test_x, test_y, predicted,
        negative_label_name, positive_label_name,
    )


def report_evaluation(
    test_data: pd.DataFrame,
    test_x: pd.DataFrame,
    test_y: pd.Series,
    predicted,
    negative_label_name: str = "Normal",
    positive_label_name: str = "Suspicious",
) -> None:
    from sklearn.metrics import classification_report, confusion_matrix

    print("Confusion matrix (labels 0=Normal, 1=Suspicious):")
    print(confusion_matrix(test_y, predicted, labels=[0, 1]))
    print("Per-class precision, recall, F1, and support:")
    print(classification_report(
        test_y, predicted,
        labels=[0, 1],
        target_names=[negative_label_name, positive_label_name],
        zero_division=0,
    ))

    mistakes = test_data.loc[test_x.index, FEATURES].copy()
    mistakes["actual"] = test_y
    mistakes["predicted"] = predicted
    false_positives = mistakes[(mistakes.actual == 0) & (mistakes.predicted == 1)]
    false_negatives = mistakes[(mistakes.actual == 1) & (mistakes.predicted == 0)]
    for title, rows in [
        ("False-positive held-out rows", false_positives),
        ("False-negative held-out rows", false_negatives),
    ]:
        print(f"{title}: {len(rows)}")
        if not rows.empty:
            print(rows.head(20).to_string())
            if len(rows) > 20:
                print("(First 20 shown.)")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--data", type=Path, help="CSV to split randomly for a baseline evaluation")
    parser.add_argument("--train-data", type=Path, help="Fit CSV for an explicit temporal/source split")
    parser.add_argument("--test-data", type=Path, help="Held-out CSV for an explicit temporal/source split")
    parser.add_argument("--saved-model", action="store_true", help="Evaluate the existing saved model instead of fitting a new one")
    parser.add_argument("--model-path", type=Path, help="Saved model file used with --saved-model")
    parser.add_argument("--negative-label-name", default="Normal", help="Display name for label 0")
    parser.add_argument("--positive-label-name", default="Suspicious", help="Display name for label 1")
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()
    try:
        if args.saved_model:
            if args.train_data is not None:
                parser.error("--saved-model cannot be used with --train-data.")
            if args.data is not None and args.test_data is not None:
                parser.error("Use either --data or --test-data with --saved-model, not both.")
            evaluation_path = args.test_data or args.data
            if evaluation_path is None:
                parser.error("--saved-model requires an explicit --data or --test-data CSV.")
            evaluate_saved_model(
                evaluation_path,
                args.model_path,
                args.negative_label_name,
                args.positive_label_name,
            )
        elif args.model_path is not None:
            parser.error("--model-path requires --saved-model.")
        elif args.train_data is not None or args.test_data is not None:
            if args.train_data is None or args.test_data is None:
                parser.error("--train-data and --test-data must be provided together.")
            if args.data is not None:
                parser.error("Use either --data or the --train-data/--test-data pair, not both.")
            evaluate(
                seed=args.seed,
                train_path=args.train_data,
                test_path=args.test_data,
                negative_label_name=args.negative_label_name,
                positive_label_name=args.positive_label_name,
            )
        else:
            evaluate(
                args.data,
                seed=args.seed,
                negative_label_name=args.negative_label_name,
                positive_label_name=args.positive_label_name,
            )
    except (OSError, ValueError) as error:
        parser.error(str(error))


if __name__ == "__main__":
    main()
