from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware

from .detection_engine import run_detection
from .database import SessionLocal
from .database_service import get_alert_history


app = FastAPI(
    title="AI Cyber Threat Detection API",
    description=(
        "API for detecting suspicious login activity "
        "using rule-based and machine learning detection."
    ),
    version="1.0.0",
)


# Allow React frontend to communicate with FastAPI
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://localhost:5173",
        "http://127.0.0.1:5173",
    ],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.get("/")
def home():
    return {
        "message": "AI Cyber Threat Detection API is running!",
        "status": "online",
    }


@app.get("/health")
def health_check():
    return {
        "status": "healthy",
        "service": "Cyber Threat Detection API",
    }


@app.get("/detect")
def detect_threats():
    try:
        alerts = run_detection()

        return {
            "total_alerts": len(alerts),
            "alerts": alerts,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )


@app.get("/history")
def alert_history(
    limit: int = Query(default=100, ge=1, le=500)
):
    """Retrieve complete historical alerts from PostgreSQL."""

    db = SessionLocal()

    try:
        alerts = get_alert_history(db, limit)

        return {
            "total_alerts": len(alerts),
            "alerts": alerts,
        }

    except Exception as error:
        raise HTTPException(
            status_code=500,
            detail=str(error),
        )

    finally:
        db.close()