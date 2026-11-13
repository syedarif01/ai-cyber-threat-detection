import pandas as pd

from scripts.prepare_lateral_movement_eval import FEATURES, prepare


def test_adapter_creates_time_separated_labeled_features(tmp_path):
    rows = []
    for start in ["2026-05-10", "2026-05-20"]:
        base_time = pd.Timestamp(f"{start} 12:00:00")
        for index in range(40):
            rows.append({
                "event_id": len(rows) + 1,
                "timestamp": (base_time + pd.Timedelta(seconds=index * 30)).isoformat(),
                "user_id": f"user-{index % 5}",
                "src_host": "host-a" if index < 20 else "host-b",
                "auth_result": "Failure" if index % 3 == 0 else "Success",
                "is_malicious": index % 2,
            })
    source = tmp_path / "benchmark.csv"
    train_path = tmp_path / "train.csv"
    test_path = tmp_path / "test.csv"
    pd.DataFrame(rows).to_csv(source, index=False)

    train_count, test_count = prepare(source, train_path, test_path)
    train = pd.read_csv(train_path)
    test = pd.read_csv(test_path)

    assert (train_count, test_count) == (40, 40)
    assert list(train.columns) == FEATURES + ["label"]
    assert train.label.value_counts().to_dict() == {0: 20, 1: 20}
    assert test.label.value_counts().to_dict() == {0: 20, 1: 20}
    assert train.loc[1, "success_after_failures"] == 1
    assert test.loc[1, "success_after_failures"] == 1
