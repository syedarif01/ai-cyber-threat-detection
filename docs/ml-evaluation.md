# ML evaluation and Smart App Control

## Current result

The project contains a Random Forest model artifact and an evaluation command. On 2026-11-13, the current Windows environment successfully imported `RandomForestClassifier` and loaded the saved artifact for a prediction (`model_available: true`). That confirms runtime compatibility only; it does not measure accuracy.

- `data/ml_training_data.csv` contains 16 labeled rows, with 8 rows in each class. The evaluation command requires at least 40 rows and deliberately rejects this file.
- The earlier scikit-learn import block is no longer reproducible in this environment. Keep Smart App Control enabled; recheck the import before evaluating if the environment changes.
- No precision, recall, F1-score, confusion matrix, false-positive count, or false-negative count is claimed for this project.

### Qualitative scenario smoke check

The saved artifact was run on five crafted feature vectors. It returned `Suspicious/High` for a single-source brute-force pattern `(8, 1, 10, 0)`, multi-account password-spray pattern `(8, 8, 10, 0)`, and success-after-failures pattern `(5, 1, 6, 1)`. It returned `Normal/Low` for low-volume failures `(4, 2, 3, 0)` and low-volume benign activity `(1, 1, 2, 0)`. These are inference smoke checks against a model trained on the same 16-row file, not independent labeled tests or performance metrics.

## Preserve Windows protection

Keep Smart App Control enabled. Microsoft's current FAQ says there is no per-app exception for a blocked application. If a future update blocks scikit-learn again, use a compatible build signed by a trusted publisher or a separate, approved evaluation environment. Do not turn off endpoint protection or copy untrusted replacement binaries into the Python environment. See [Microsoft's Smart App Control FAQ](https://support.microsoft.com/en-gb/windows/security/threat-malware-protection/smart-app-control-frequently-asked-questions?pubDate=20261001) and the [Smart App Control overview](https://learn.microsoft.com/en-us/windows/apps/develop/smart-app-control/overview).

## Evaluation data format

Prepare a CSV with at least 40 authorized, representative, labeled observations and these columns:

| Column | Meaning |
| --- | --- |
| `failed_attempts` | Count of failed login attempts in the observation window |
| `unique_usernames` | Number of distinct usernames attempted |
| `events_per_minute` | Authentication event rate |
| `success_after_failures` | Binary indicator for a successful login after failures |
| `label` | `0` for normal activity or `1` for suspicious activity |

Forty rows is only a guardrail in the script, not a claim that this sample size is sufficient for a reliable security model. Prefer a much larger dataset that reflects benign activity and several attack scenarios. Keep source and labels documented, remove identifying information where appropriate, and avoid uploading sensitive logs to an unapproved service.

## Public dataset review

The official [LANL Comprehensive, Multi-Source Cyber-Security Events dataset](https://lanl.ma.ic.ac.uk/data/cyber1/) includes authentication records and a separate red-team ground-truth file. Its authentication file is listed as 7.2 GB compressed, and the source contains approximately 1.65 billion events overall. Authentication rows contain source/destination accounts and computers, authentication/logon type, orientation, and success/failure; red-team rows identify compromised user/computer/time tuples. These are not the project's four precomputed features and per-row binary label. A documented feature and label adapter plus a compute-appropriate, time-separated evaluation would be required before using it. No LANL metrics are claimed, and no dataset copy is included in this repository.

### Synthetic lateral-movement benchmark

The author's [180,000-event synthetic enterprise authentication dataset](https://www.kaggle.com/datasets/codewithdaniel1/synthetic-enterprise-auth-logs) is described in the [source repository](https://github.com/codewithdaniel1/lateral-movement-detection/blob/main/docs/DATASET.md). The repository links to the current Kaggle owner slug. The source describes event labels for simulated lateral movement, a time split, and a CC BY 4.0 license. It is self-authored synthetic data, is attack-enriched, and has not been validated against real incidents. Its threat type differs from this project's repeated-failed-login focus, so any results must be called a synthetic lateral-movement benchmark and must not be presented as real-world accuracy.

**Access status checked 2026-11-13:** the earlier link used the obsolete `danielpeng1995` owner slug and showed “page not found.” The source repository currently links to the Kaggle URL above; the web reader resolves the page title but cannot inspect or download the file. To obtain it, open the link in a browser, sign in to Kaggle if prompted, use the page's Download control, extract the downloaded archive, and keep the CSV outside this repository. Never share a Kaggle token. The adapter maps each event to one-minute, per-source-host counts using the event and preceding context; it copies `is_malicious` only as the target. It excludes May 1–7 baseline events, fits on May 8–15, and holds out May 16–30, following the source description. Run:

```powershell
python scripts\prepare_lateral_movement_eval.py --input path\to\synthetic_auth_logs.csv
python -m src.evaluate_model --train-data data\phase3_train.csv --test-data data\phase3_test.csv
```

The generated feature CSVs are ignored by Git. Keep the source attribution with any reported result. A low or high score on this synthetic lateral-movement data does not validate detection of real brute-force activity.

## Run the held-out evaluation

From the project root, in an environment where the project's approved scikit-learn installation can load:

```powershell
.\.venv\Scripts\python.exe -m src.evaluate_model --data path\to\authorized_evaluation.csv
```

The command validates schema, numeric finite features, labels and minimum sample size. With `--data`, it uses a stratified 75/25 random split. With `--train-data` and `--test-data`, it fits on the first CSV and evaluates the untouched second CSV, which supports the time-separated benchmark above. Both modes train the configured Random Forest in memory without overwriting the saved model and print per-class precision, recall and F1, the confusion matrix, false-positive/false-negative counts, and up to 20 example rows for each error type.

This split is a baseline. For research-quality evaluation, preserve an untouched test set or split by time/source to reduce leakage, repeat across seeds, and review misclassified examples with a domain expert. Do not tune against the final test data.

## What to provide to continue

The saved model and Random Forest import currently work in the checked environment. The synthetic benchmark is not yet evaluated because its CSV is not included in the source repository and the downloadable file requires Kaggle access. Do not share Kaggle tokens, API keys, database passwords, or private authentication logs. For claims about model performance, use the linked synthetic benchmark with the documented caveats or provide a usable, authorized labeled dataset; for claims about real-world accuracy, that dataset must represent real activity and attacks.

