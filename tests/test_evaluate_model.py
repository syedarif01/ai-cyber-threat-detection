"""Data checks for the non-destructive Random Forest evaluation command."""

import pandas as pd
import pytest

from src.evaluate_model import (
    FEATURES,
    MIN_ROWS,
    evaluate_saved_model,
    load_labeled_data,
)


class AlwaysNormalModel:
    def predict(self, features):
        return [0] * len(features)


def make_data(rows=MIN_ROWS):
    return pd.DataFrame({
        FEATURES[0]: [5] * rows,
        FEATURES[1]: [2] * rows,
        FEATURES[2]: [4] * rows,
        FEATURES[3]: [0] * rows,
        "label": [0, 1] * (rows // 2),
    })


def test_evaluation_requires_more_than_current_small_dataset(tmp_path):
    path = tmp_path / "small.csv"
    make_data(16).to_csv(path, index=False)
    with pytest.raises(ValueError, match="at least 40"):
        load_labeled_data(path)


def test_evaluation_rejects_missing_features(tmp_path):
    path = tmp_path / "missing.csv"
    make_data().drop(columns=[FEATURES[0]]).to_csv(path, index=False)
    with pytest.raises(ValueError, match="Missing required columns"):
        load_labeled_data(path)


def test_evaluation_rejects_missing_or_invalid_labels(tmp_path):
    path = tmp_path / "invalid.csv"
    data = make_data()
    data.loc[0, "label"] = 2
    data.to_csv(path, index=False)
    with pytest.raises(ValueError, match="Labels must be 0"):
        load_labeled_data(path)

    data = make_data().astype({FEATURES[0]: object})
    data.loc[0, FEATURES[0]] = "not-a-number"
    data.to_csv(path, index=False)
    with pytest.raises(ValueError, match="must be numeric"):
        load_labeled_data(path)

    data = make_data().astype({FEATURES[0]: float})
    data.loc[0, FEATURES[0]] = float("inf")
    data.to_csv(path, index=False)
    with pytest.raises(ValueError, match="must be finite"):
        load_labeled_data(path)


def test_evaluation_accepts_a_minimum_sized_balanced_dataset(tmp_path):
    path = tmp_path / "valid.csv"
    make_data().to_csv(path, index=False)
    loaded = load_labeled_data(path)
    assert len(loaded) == MIN_ROWS
    assert set(loaded.label.unique()) == {0, 1}


def test_saved_model_evaluation_reports_a_held_out_csv(tmp_path, capsys):
    import joblib

    data_path = tmp_path / "held-out.csv"
    model_path = tmp_path / "model.joblib"
    make_data().to_csv(data_path, index=False)
    joblib.dump({"model": AlwaysNormalModel(), "features": FEATURES}, model_path)

    evaluate_saved_model(data_path, model_path)

    output = capsys.readouterr().out
    assert "Saved model:" in output
    assert "Held-out data:" in output
    assert "False-negative held-out rows: 20" in output


def test_saved_model_evaluation_rejects_incompatible_features(tmp_path):
    import joblib

    data_path = tmp_path / "held-out.csv"
    model_path = tmp_path / "model.joblib"
    make_data().to_csv(data_path, index=False)
    joblib.dump({"model": AlwaysNormalModel(), "features": ["other_feature"]}, model_path)

    with pytest.raises(ValueError, match="feature list does not match"):
        evaluate_saved_model(data_path, model_path)
