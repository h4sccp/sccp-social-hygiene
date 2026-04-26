"""
San Carlos City Social Hygiene Clinic — Backend API
Storage: SQLite (clinic.db, auto-created on first run)

Environment variables (set in Render → Environment):
  HMAC_SECRET       — secret key for signing appointment codes (required in production)
  RECAPTCHA_SECRET  — Google reCAPTCHA v3 secret key (optional; skip verification if unset)
  ALLOWED_ORIGINS   — comma-separated allowed origins (defaults to GitHub Pages + localhost)

Start:  python main.py
        OR uvicorn main:app --host 0.0.0.0 --port 9000 --reload
Docs:   http://127.0.0.1:9000/docs
"""

import sqlite3
import os
import hmac as hmac_mod
import hashlib
import json as json_mod
import urllib.parse
import urllib.request
import smtplib
import threading
from contextlib import contextmanager
from datetime import datetime, timezone, timedelta
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from typing import Optional

import uvicorn
from fastapi import Depends, FastAPI, Header, HTTPException, Request, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, field_validator
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

# ---------------------------------------------------------------------------
# Config
# ---------------------------------------------------------------------------

HMAC_SECRET      = os.environ.get("HMAC_SECRET",     "dev-secret-change-in-production")
RECAPTCHA_SECRET = os.environ.get("RECAPTCHA_SECRET","")
CLINIC_EMAIL     = os.environ.get("CLINIC_EMAIL",    "chosccpsocialhygiene@gmail.com")
SMTP_PASSWORD    = os.environ.get("SMTP_PASSWORD",   "")
STAFF_PASSWORD   = os.environ.get("STAFF_PASSWORD",  "changeme")
ALLOWED_ORIGINS  = os.environ.get(
    "ALLOWED_ORIGINS",
    "https://h4sccp.github.io,http://127.0.0.1:5500,http://localhost:5500,http://127.0.0.1:9000",
).split(",")

# ---------------------------------------------------------------------------
# Rate limiter  (IP-aware, reads X-Forwarded-For from Render's proxy)
# ---------------------------------------------------------------------------

def _real_ip(request: Request) -> str:
    forwarded = request.headers.get("X-Forwarded-For", "")
    return forwarded.split(",")[0].strip() if forwarded else (request.client.host or "unknown")

limiter = Limiter(key_func=_real_ip)

# ---------------------------------------------------------------------------
# App
# ---------------------------------------------------------------------------

app = FastAPI(
    title="San Carlos City Social Hygiene Clinic API",
    version="2.0.0",
    description="Anonymous scheduling, symptoms self-assessment, and dashboard.",
)

app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

app.add_middleware(
    CORSMiddleware,
    allow_origins=ALLOWED_ORIGINS,
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
    conn.execute("PRAGMA journal_mode=WAL")
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
# HMAC-signed appointment codes
# ---------------------------------------------------------------------------

def make_code(appointment_iso: str) -> str:
    """Generate a signed code that embeds the appointment timestamp.

    Format: SCC-{unix_timestamp_hex}-{hmac_8chars}
    Example: SCC-682196D0-A3F2B891
    """
    dt     = datetime.fromisoformat(appointment_iso.replace("Z", "+00:00"))
    ts_hex = format(int(dt.timestamp()), "X")
    sig    = hmac_mod.new(
        HMAC_SECRET.encode(), ts_hex.encode(), hashlib.sha256
    ).hexdigest()[:8].upper()
    return f"SCC-{ts_hex}-{sig}"


def check_code(code: str) -> dict:
    """Verify a code's HMAC and return validity + expiry info."""
    parts = code.upper().strip().split("-")
    if len(parts) != 3 or parts[0] != "SCC":
        return {"valid": False}
    ts_hex, sig = parts[1], parts[2]
    try:
        expected = hmac_mod.new(
            HMAC_SECRET.encode(), ts_hex.encode(), hashlib.sha256
        ).hexdigest()[:8].upper()
    except Exception:
        return {"valid": False}
    if not hmac_mod.compare_digest(sig, expected):
        return {"valid": False}
    try:
        appt_ts = int(ts_hex, 16)
        appt_dt = datetime.fromtimestamp(appt_ts, tz=timezone.utc)
    except (ValueError, OverflowError):
        return {"valid": False}
    now = datetime.now(timezone.utc)
    return {
        "valid":            True,
        "expired":          now > appt_dt + timedelta(minutes=15),
        "appointment_time": appt_dt.isoformat(),
    }


# ---------------------------------------------------------------------------
# reCAPTCHA v3 verification
# ---------------------------------------------------------------------------

def verify_recaptcha(token: str) -> bool:
    """Returns True if the token is valid (or if reCAPTCHA is not configured)."""
    if not RECAPTCHA_SECRET or not token:
        return True
    try:
        data = urllib.parse.urlencode(
            {"secret": RECAPTCHA_SECRET, "response": token}
        ).encode()
        with urllib.request.urlopen(
            "https://www.google.com/recaptcha/api/siteverify", data, timeout=5
        ) as resp:
            result = json_mod.loads(resp.read())
        return bool(result.get("success")) and float(result.get("score", 0)) >= 0.5
    except Exception:
        return True  # don't block real users if Google is unreachable


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------

class AppointmentIn(BaseModel):
    reason:          str
    time:            str            # ISO-8601 string sent by the browser
    recaptcha_token: Optional[str] = None

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
    score: int
    notes: str

    @field_validator("score")
    @classmethod
    def score_non_negative(cls, v: int) -> int:
        if v < 0:
            raise ValueError("score must be >= 0")
        return v


class EventRegistrationIn(BaseModel):
    code:    str
    name:    str
    event:   str
    contact: Optional[str] = ""


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def classify_risk(score: int) -> str:
    if score == 0:   return "none"
    if score <= 2:   return "low"
    if score <= 4:   return "medium"
    return "high"


def now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Staff authentication — simple HMAC token valid for 1 hour
# ---------------------------------------------------------------------------

def _make_staff_token() -> str:
    hour = datetime.now(timezone.utc).strftime("%Y%m%d%H")
    return hmac_mod.new(HMAC_SECRET.encode(), f"staff:{hour}".encode(), hashlib.sha256).hexdigest()


def _verify_staff_token(token: str) -> bool:
    now = datetime.now(timezone.utc)
    for delta in range(2):  # accept current hour and previous hour
        hour     = (now - timedelta(hours=delta)).strftime("%Y%m%d%H")
        expected = hmac_mod.new(HMAC_SECRET.encode(), f"staff:{hour}".encode(), hashlib.sha256).hexdigest()
        if hmac_mod.compare_digest(token or "", expected):
            return True
    return False


def require_staff(x_staff_token: str = Header(default="")):
    if not _verify_staff_token(x_staff_token):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Staff authentication required.")


# ---------------------------------------------------------------------------
# Email notification (sent to clinic inbox — patient stays anonymous)
# ---------------------------------------------------------------------------

def _send_email_sync(code: str, reason: str, appointment_iso: str) -> None:
    if not SMTP_PASSWORD:
        return
    try:
        dt  = datetime.fromisoformat(appointment_iso.replace("Z", "+00:00"))
        day = dt.strftime("%A, %B %d, %Y")
        tm  = dt.strftime("%I:%M %p")

        msg = MIMEMultipart("alternative")
        msg["Subject"] = f"New Anonymous Appointment — {day} at {tm}"
        msg["From"]    = CLINIC_EMAIL
        msg["To"]      = CLINIC_EMAIL

        text = (
            f"New anonymous appointment booked.\n\n"
            f"Code   : {code}\n"
            f"Date   : {day}\n"
            f"Time   : {tm}\n"
            f"Reason : {reason}\n\n"
            f"Patient is anonymous. No personal information was collected.\n"
            f"Verify this code at the Dashboard when the patient arrives."
        )
        html = f"""
        <div style="font-family:sans-serif;max-width:480px;margin:0 auto;border:1px solid #e5e7eb;border-radius:8px;overflow:hidden;">
          <div style="background:#dc2626;padding:1rem 1.5rem;">
            <h2 style="color:#fff;margin:0;font-size:1.1rem;">San Carlos City Social Hygiene Clinic</h2>
            <p style="color:#fecaca;margin:4px 0 0;font-size:.85rem;">New Anonymous Appointment</p>
          </div>
          <div style="padding:1.5rem;">
            <p style="margin:0 0 1rem;color:#374151;">A new appointment has been booked. The patient is <strong>fully anonymous</strong> — no personal information was collected.</p>
            <table style="width:100%;border-collapse:collapse;font-size:.9rem;">
              <tr><td style="padding:6px 12px;background:#f9fafb;font-weight:600;color:#6b7280;width:80px;">Code</td>
                  <td style="padding:6px 12px;font-family:monospace;font-size:1rem;color:#dc2626;letter-spacing:2px;"><strong>{code}</strong></td></tr>
              <tr><td style="padding:6px 12px;background:#f9fafb;font-weight:600;color:#6b7280;">Date</td>
                  <td style="padding:6px 12px;">{day}</td></tr>
              <tr><td style="padding:6px 12px;background:#f9fafb;font-weight:600;color:#6b7280;">Time</td>
                  <td style="padding:6px 12px;">{tm}</td></tr>
              <tr><td style="padding:6px 12px;background:#f9fafb;font-weight:600;color:#6b7280;">Reason</td>
                  <td style="padding:6px 12px;">{reason}</td></tr>
            </table>
            <p style="margin:1.25rem 0 0;font-size:.8rem;color:#9ca3af;">Verify this code in the Dashboard when the patient arrives, then mark as Attended or No-show.</p>
          </div>
        </div>"""

        msg.attach(MIMEText(text, "plain"))
        msg.attach(MIMEText(html,  "html"))

        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(CLINIC_EMAIL, SMTP_PASSWORD)
            server.sendmail(CLINIC_EMAIL, CLINIC_EMAIL, msg.as_string())
    except Exception:
        pass  # never block a booking because email failed


def send_appointment_email(code: str, reason: str, appointment_iso: str) -> None:
    threading.Thread(
        target=_send_email_sync,
        args=(code, reason, appointment_iso),
        daemon=True,
    ).start()


# ---------------------------------------------------------------------------
# Routes — appointments
# ---------------------------------------------------------------------------

@app.post("/api/appointments", status_code=status.HTTP_201_CREATED)
@limiter.limit("3/day")
def create_appointment(request: Request, data: AppointmentIn):
    if not verify_recaptcha(data.recaptcha_token or ""):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Bot check failed. Please try again.",
        )
    code = make_code(data.time)
    with get_db() as conn:
        try:
            conn.execute(
                "INSERT INTO appointments (code, reason, appointment_time) VALUES (?, ?, ?)",
                (code, data.reason, data.time),
            )
        except sqlite3.IntegrityError:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Duplicate appointment — please try again.",
            )
    send_appointment_email(code, data.reason, data.time)
    return {"success": True, "code": code}


@app.post("/api/staff/token")
@limiter.limit("10/hour")
def staff_login(request: Request, body: dict):
    """Returns a 1-hour staff token if the password is correct."""
    if not hmac_mod.compare_digest(body.get("password", ""), STAFF_PASSWORD):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Incorrect password.")
    return {"token": _make_staff_token()}


@app.post("/api/appointments/{code}/status")
def update_appointment_status(code: str, body: dict, _: None = Depends(require_staff)):
    """Staff endpoint: mark appointment as attended or no-show."""
    new_status = (body.get("status") or "").strip().lower()
    if new_status not in ("attended", "no-show", "pending", "cancelled"):
        raise HTTPException(status_code=400, detail="Invalid status value.")
    with get_db() as conn:
        updated = conn.execute(
            "UPDATE appointments SET status = ? WHERE code = ?",
            (new_status, code.upper()),
        ).rowcount
    if not updated:
        raise HTTPException(status_code=404, detail="Appointment not found.")
    return {"success": True, "code": code.upper(), "status": new_status}


@app.get("/api/appointments/upcoming")
def upcoming_appointments(limit: int = 10):
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


@app.get("/api/verify/{code}")
def verify_appointment_code(code: str, _: None = Depends(require_staff)):
    """Staff endpoint: verify that a patient's code is genuine and not expired."""
    result = check_code(code)
    if not result["valid"]:
        return {"valid": False, "message": "Invalid code. This was not issued by the clinic."}

    with get_db() as conn:
        row = conn.execute(
            "SELECT reason, appointment_time, status FROM appointments WHERE code = ?",
            (code.upper(),),
        ).fetchone()

    if not row:
        return {"valid": False, "message": "Code not found in records."}

    if row["status"] == "cancelled":
        return {"valid": False, "message": "This appointment was cancelled."}

    if result["expired"]:
        return {
            "valid":            True,
            "expired":          True,
            "reason":           row["reason"],
            "appointment_time": row["appointment_time"],
            "status":           row["status"],
            "message":          "Code is valid but expired (more than 15 minutes past appointment time).",
        }

    return {
        "valid":            True,
        "expired":          False,
        "reason":           row["reason"],
        "appointment_time": row["appointment_time"],
        "status":           row["status"],
        "message":          "Valid appointment code.",
    }


# ---------------------------------------------------------------------------
# Routes — self-assessment
# ---------------------------------------------------------------------------

@app.post("/api/assessments", status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")
def create_assessment(request: Request, data: AssessmentIn):
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
def get_dashboard(_: None = Depends(require_staff)):
    with get_db() as conn:
        now = now_utc()

        total_appts    = conn.execute("SELECT COUNT(*) FROM appointments").fetchone()[0]
        upcoming_count = conn.execute(
            "SELECT COUNT(*) FROM appointments WHERE appointment_time >= ? AND status != 'cancelled'",
            (now,),
        ).fetchone()[0]
        total_assess   = conn.execute("SELECT COUNT(*) FROM assessments").fetchone()[0]
        risk_counts    = {
            row["risk_level"]: row["n"]
            for row in conn.execute(
                "SELECT risk_level, COUNT(*) AS n FROM assessments GROUP BY risk_level"
            ).fetchall()
        }
        total_events   = conn.execute("SELECT COUNT(*) FROM event_registrations").fetchone()[0]
        upcoming_rows  = conn.execute(
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
            "total_assessments":         total_assess,
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
