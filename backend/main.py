"""
San Carlos City Social Hygiene Clinic — Backend API
Runs on http://127.0.0.1:9000
Storage: SQLite (clinic.db, auto-created on first run)

Start:  python main.py
        OR uvicorn main:app --host 0.0.0.0 --port 9000 --reload
Docs:   http://127.0.0.1:9000/docs
"""

import sqlite3
import os
from contextlib import contextmanager
from datetime import datetime, timezone
from typing import Optional

import uvicorn
from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator

# ---------------------------------------------------------------------------
# App + CORS
# ---------------------------------------------------------------------------

app = FastAPI(
    title="San Carlos City Social Hygiene Clinic API",
    version="1.0.0",
    description="Anonymous scheduling, symptoms self-assessment, and dashboard.",
)

# Allow the static frontend (served from any origin in dev).
# In production narrow this to your actual domain, e.g. ["https://yourdomain.gov.ph"]
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)

# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

DB_PATH = os.path.join(os.path.dirname(__file__), "clinic.db")


@contextmanager
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")   # safe for concurrent reads
    conn.execute("PRAGMA foreign_keys=ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    with get_db() as conn:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS appointments (
                id               INTEGER PRIMARY KEY AUTOINCREMENT,
                code             TEXT UNIQUE NOT NULL,
                reason           TEXT NOT NULL,
                appointment_time TEXT NOT NULL,
                status           TEXT NOT NULL DEFAULT 'pending',
                created_at       TEXT NOT NULL DEFAULT (datetime('now','utc'))
            );

            CREATE TABLE IF NOT EXISTS assessments (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                score      INTEGER NOT NULL,
                risk_level TEXT NOT NULL,
                notes      TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT (datetime('now','utc'))
            );

            CREATE TABLE IF NOT EXISTS event_registrations (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                code       TEXT UNIQUE NOT NULL,
                name       TEXT NOT NULL,
                event      TEXT NOT NULL,
                contact    TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL DEFAULT (datetime('now','utc'))
            );
        """)


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class AppointmentIn(BaseModel):
    code: str
    reason: str
    time: str   # ISO-8601 string sent by the browser

    @field_validator("reason")
    @classmethod
    def reason_not_empty(cls, v: str) -> str:
        v = v.strip()
        if not v:
            raise ValueError("reason must not be empty")
        return v

    @field_validator("time")
    @classmethod
    def time_is_iso(cls, v: str) -> str:
        try:
            datetime.fromisoformat(v.replace("Z", "+00:00"))
        except ValueError:
            raise ValueError("time must be an ISO-8601 datetime string")
        return v


class AssessmentIn(BaseModel):
    score: int          # number of risk factors selected
    notes: str          # comma-separated factor labels

    @field_validator("score")
    @classmethod
    def score_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("score must be >= 0")
        return v


class EventRegistrationIn(BaseModel):
    code: str
    name: str
    event: str
    contact: Optional[str] = ""


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def classify_risk(score: int) -> str:
    if score == 0:
        return "none"
    if score <= 2:
        return "low"
    if score <= 4:
        return "medium"
    return "high"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Routes — appointments
# ---------------------------------------------------------------------------

@app.post("/api/appointments", status_code=status.HTTP_201_CREATED)
def create_appointment(data: AppointmentIn):
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO appointments (code, reason, appointment_time) VALUES (?, ?, ?)",
                (data.code, data.reason, data.time),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Duplicate appointment code — please try again.",
            )
    return {"success": True, "code": data.code}


@app.get("/api/appointments/upcoming")
def upcoming_appointments(limit: int = 10):
    """Public list of upcoming appointments (code + reason only — no PII)."""
    with get_db() as conn:
        rows = conn.execute(
            """
            SELECT code, reason, appointment_time, status
            FROM   appointments
            WHERE  appointment_time >= ?
              AND  status != 'cancelled'
            ORDER  BY appointment_time ASC
            LIMIT  ?
            """,
            (now_utc(), min(limit, 50)),
        ).fetchall()
    return {"appointments": [dict(r) for r in rows]}


# ---------------------------------------------------------------------------
# Routes — self-assessment
# ---------------------------------------------------------------------------

@app.post("/api/assessments", status_code=status.HTTP_201_CREATED)
def create_assessment(data: AssessmentIn):
    risk_level = classify_risk(data.score)
    with get_db() as conn:
        conn.execute(
            "INSERT INTO assessments (score, risk_level, notes) VALUES (?, ?, ?)",
            (data.score, risk_level, data.notes),
        )
    return {"success": True, "risk_level": risk_level}


# ---------------------------------------------------------------------------
# Routes — event registrations
# ---------------------------------------------------------------------------

@app.post("/api/event_registrations", status_code=status.HTTP_201_CREATED)
def create_event_registration(data: EventRegistrationIn):
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO event_registrations (code, name, event, contact) VALUES (?, ?, ?, ?)",
                (data.code, data.name or "Anonymous", data.event, data.contact or ""),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Duplicate registration code — please try again.",
            )
    return {"success": True, "code": data.code}


# ---------------------------------------------------------------------------
# Routes — dashboard
# ---------------------------------------------------------------------------

@app.get("/api/dashboard")
def get_dashboard():
    """Aggregated stats + next 5 upcoming appointments for the dashboard."""
    with get_db() as conn:
        now = now_utc()

        total_appts = conn.execute(
            "SELECT COUNT(*) FROM appointments"
        ).fetchone()[0]

        upcoming_count = conn.execute(
            "SELECT COUNT(*) FROM appointments WHERE appointment_time >= ? AND status != 'cancelled'",
            (now,),
        ).fetchone()[0]

        total_assessments = conn.execute(
            "SELECT COUNT(*) FROM assessments"
        ).fetchone()[0]

        risk_counts = {
            row["risk_level"]: row["n"]
            for row in conn.execute(
                "SELECT risk_level, COUNT(*) AS n FROM assessments GROUP BY risk_level"
            ).fetchall()
        }

        total_events = conn.execute(
            "SELECT COUNT(*) FROM event_registrations"
        ).fetchone()[0]

        upcoming_rows = conn.execute(
            """
            SELECT code, reason, appointment_time, status
            FROM   appointments
            WHERE  appointment_time >= ?
              AND  status != 'cancelled'
            ORDER  BY appointment_time ASC
            LIMIT  5
            """,
            (now,),
        ).fetchall()

    return {
        "stats": {
            "total_appointments":        total_appts,
            "upcoming_appointments":     upcoming_count,
            "total_assessments":         total_assessments,
            "risk_distribution":         risk_counts,
            "total_event_registrations": total_events,
        },
        "upcoming_appointments": [dict(r) for r in upcoming_rows],
    }


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.get("/health")
def health():
    return {"status": "ok", "time": now_utc()}


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

@app.on_event("startup")
def startup():
    init_db()


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 9000))
    uvicorn.run("main:app", host="0.0.0.0", port=port, reload=(port == 9000))
