# CyberGuard AI — Threat Detection and Incident Response

CyberGuard analyzes authentication logs with rule-based and machine-learning detection, stores incidents in PostgreSQL, and provides a React dashboard for incident review and response-action simulation.

## Current features

- Detect repeated failed logins with an explainable rule, and use the Random Forest classifier when its native dependencies are available.
- Store security events and correlate repeated detections into incidents.
- Review, search, filter, acknowledge, investigate, resolve, and add analyst notes to incidents.
- Create response actions, approve or reject them, and simulate approved actions. Simulation does not change network settings.
- Review audit records for incident and response-action activity.
- View dashboard summaries and threat-severity charts.

## Requirements

- Python 3.10 or newer
- Node.js 20.19+ or 22.12+
- PostgreSQL

## Configure PostgreSQL

Create a PostgreSQL database, then create a project-root `.env` file with:

```dotenv
DB_HOST=localhost
DB_PORT=5432
DB_NAME=cyber_threat_db
DB_USER=your_postgres_user
DB_PASSWORD=your_postgres_password
CYBERGUARD_ANALYST_API_KEY=replace_with_a_long_random_secret
CYBERGUARD_VIEWER_API_KEY=replace_with_another_long_random_secret
CYBERGUARD_ANALYST_NAME=Your name
```

Keep `.env` local; it is excluded from Git. Create or update the application tables with:

```powershell
python -m src.init_db
```

## Run the backend

From the project root in PowerShell:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python -m src.init_db
uvicorn src.api:app --host 127.0.0.1 --reload
```

The API is available at `http://127.0.0.1:8000`; interactive API documentation is at `/docs`. Generate each key with `python -c "import secrets; print(secrets.token_urlsafe(48))"`. The analyst key can read and change incident data. The viewer key is read-only. If both keys are omitted, the API accepts loopback clients only and refuses remote clients.

## Run the frontend

In a second terminal:

```powershell
cd frontend
npm ci
npm run dev
```

Open the local Vite URL shown in the terminal (normally `http://localhost:5173`). The frontend expects the API at `http://127.0.0.1:8000`.

## Run detection

Detection reads `data/sample_logs.csv` and persists newly observed events and incidents:

```powershell
python -m src.detection_engine
```

The model is included at `models/threat_classifier.joblib`. To retrain it from `data/ml_training_data.csv`, run `python -m src.ml_model`.

To evaluate on a separate, larger labeled CSV without overwriting the saved model, use `python -m src.evaluate_model --data path\to\evaluation.csv`. The CSV must contain the four training features and a binary `label` column, with at least 40 labeled rows. For a time-separated evaluation, use `--train-data` and `--test-data`. The command reports per-class precision, recall, F1, a labeled confusion matrix, and false-positive/false-negative counts and examples. The current 16-row file is deliberately rejected as too small. The synthetic authentication benchmark is linked at its current Kaggle URL in [ML evaluation](docs/ml-evaluation.md); download and evaluate it there before making model performance claims.

If the operating system blocks a scikit-learn native extension, detection continues with the repeated-failed-login rule and the API/dashboard report that ML inference is unavailable. Keep Smart App Control enabled. Microsoft currently documents no per-app bypass; use a compatible, trusted and signed build if available, or run model evaluation in another approved environment. See [ML evaluation and Smart App Control](docs/ml-evaluation.md).

## Verify the project

From the project root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q
.\.venv\Scripts\python.exe -m compileall -q src tests scripts
.\.venv\Scripts\python.exe scripts\live_api_smoke.py
```

From `frontend`:

```powershell
npm run lint
npm run build
```

API workflow tests use in-memory SQLite and do not modify the configured PostgreSQL database. The live API smoke script starts FastAPI against disposable in-memory SQLite, uses temporary process-only API keys, exercises every route including create/approve/reject/simulate/notes/audit, and shuts its server down. It never calls real log detection or writes to PostgreSQL. The separate database connection can be checked with `python src/database.py`.

## Project documentation and presentation

- [Architecture, data flow, use cases, database ER diagram, API overview, and verification record](docs/architecture-and-testing.md)
- [ML evaluation instructions and current environment limitation](docs/ml-evaluation.md)
- [Solo demonstration plan and viva questions](docs/final-year-demo-and-viva.md)
- Final-year report: [CyberGuard_AI_Final_Year_Project_Report.docx](docs/deliverables/CyberGuard_AI_Final_Year_Project_Report.docx)
- Presentation: [CyberGuard_AI_Final_Year_Presentation.pptx](docs/deliverables/CyberGuard_AI_Final_Year_Presentation.pptx)

Fill in the student, registration, department, institution, supervisor, and date placeholders before submitting the report or presentation. The project is a capstone prototype. The available 16-row training file and current machine policy do not support a reliable model performance claim.
