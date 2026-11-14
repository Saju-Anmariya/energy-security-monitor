"""
Energy Security Monitor - Phase 4: read-only REST API.

Run:  uvicorn api:app --app-dir src --reload
Docs: http://127.0.0.1:8000/docs
"""

from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query

import db

app = FastAPI(
    title="Energy Security Monitor API",
    description="Read-only access to security alerts (simulated data).",
    version="1.0.0",
)

Severity = Literal["critical", "high", "medium", "low"]
AlertType = Literal["brute_force", "password_spraying", "port_scan", "suspicious_admin_login"]


@app.middleware("http")
async def add_security_headers(request, call_next):
    """Safe default headers on every response (the kind of warning OWASP ZAP reports)."""
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Referrer-Policy"] = "no-referrer"
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/summary")
def get_summary():
    try:
        return db.summary()
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail=str(error))


@app.get("/alerts")
def list_alerts(
    severity: Optional[Severity] = None,
    alert_type: Optional[AlertType] = None,
    limit: int = Query(100, ge=1, le=1000),
):
    try:
        df = db.get_alerts(
            severity=[severity] if severity else None,
            alert_type=[alert_type] if alert_type else None,
            limit=limit,
        )
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail=str(error))
    return df.to_dict(orient="records")


@app.get("/alerts/{alert_id}")
def get_alert(alert_id: int):
    try:
        alert = db.get_alert(alert_id)
    except FileNotFoundError as error:
        raise HTTPException(status_code=503, detail=str(error))
    if alert is None:
        raise HTTPException(status_code=404, detail="Alert not found")
    return alert
