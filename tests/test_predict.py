from src import predict


def test_predict_reports_native_model_load_failure(monkeypatch, tmp_path):
    model_file = tmp_path / "model.joblib"
    model_file.write_bytes(b"model-placeholder")
    monkeypatch.setattr(predict, "MODEL_FILE", model_file)

    def blocked_model_load(_path):
        raise ImportError("native extension blocked")

    monkeypatch.setattr(predict.joblib, "load", blocked_model_load)
    result = predict.predict_activity(5, 2, 5, 0)

    assert result == {
        "prediction": "Unavailable",
        "severity": "Unknown",
        "model_available": False,
    }
