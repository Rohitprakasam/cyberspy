"""
CyberSpy Backend — Main FastAPI Application

All API routes, WebSocket handlers, and application lifecycle events.
"""

import os
import uuid
import hashlib
import json
import traceback
from datetime import datetime
from contextlib import asynccontextmanager
from typing import Optional

from fastapi import FastAPI, UploadFile, File, Form, Depends, HTTPException, status, WebSocket
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from config import settings
from database import init_db, get_db
from auth import create_device_token, verify_device_token
from ai_engine import analyze_logs_with_llm, generate_forensic_report
from dispatch import dispatch_to_authority, determine_dispatch_target
from models import (
    DeviceRecord, CaseRecord,
    DeviceRegisterRequest, DeviceRegisterResponse,
    EvidenceSubmitResponse, CaseStatusResponse,
    ThreatSnapshot, CaseStatus, ForensicReport,
    AuthorityDispatchResult,
)


# ============================================================
#  APP LIFECYCLE
# ============================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    await init_db()
    os.makedirs(settings.EVIDENCE_UPLOAD_DIR, exist_ok=True)
    print("CyberSpy Backend v1.0.0 started")
    print(f"LLM Provider: {settings.LLM_PROVIDER}")
    yield
    # Shutdown logic
    print("CyberSpy Backend shutting down")


app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description=(
        "CyberSpy Backend API — Real-time mobile hack detection, "
        "AI-powered forensic analysis, and direct cyber authority reporting."
    ),
    lifespan=lifespan,
)

# CORS — allow Android app and dev tools
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# ============================================================
#  HEALTH CHECK
# ============================================================

@app.get("/", tags=["Health"])
async def root():
    return {
        "service": settings.APP_NAME,
        "version": settings.APP_VERSION,
        "status": "operational",
        "timestamp": datetime.utcnow().isoformat(),
    }


@app.get("/health", tags=["Health"])
async def health_check():
    return {"status": "healthy", "llm_provider": settings.LLM_PROVIDER}


# ============================================================
#  DEVICE AUTHENTICATION
# ============================================================

@app.post(
    "/api/v1/auth/device-register",
    response_model=DeviceRegisterResponse,
    tags=["Authentication"],
    summary="Register a device and receive a JWT token",
)
async def register_device(
    request: DeviceRegisterRequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Register a new device or re-authenticate an existing one.
    Returns a JWT token for all subsequent API calls.
    """
    # Check if device already registered
    result = await db.execute(
        select(DeviceRecord).where(DeviceRecord.device_id == request.device_id)
    )
    existing = result.scalar_one_or_none()

    if existing:
        existing.last_seen = datetime.utcnow()
        existing.device_fingerprint = request.device_fingerprint
    else:
        device = DeviceRecord(
            device_id=request.device_id,
            device_fingerprint=request.device_fingerprint,
            device_model=request.device_model,
            android_version=request.android_version,
        )
        db.add(device)

    await db.flush()

    token = create_device_token(request.device_id)
    return DeviceRegisterResponse(
        access_token=token,
        device_id=request.device_id,
        expires_in_hours=settings.JWT_EXPIRY_HOURS,
    )


# ============================================================
#  EVIDENCE SUBMISSION
# ============================================================

@app.post(
    "/api/v1/evidence/submit",
    response_model=EvidenceSubmitResponse,
    tags=["Evidence"],
    summary="Submit an encrypted evidence package for analysis",
)
async def submit_evidence(
    evidence_file: UploadFile = File(..., description="Encrypted .cyberspy evidence package"),
    device_logs: str = Form(default="", description="Raw device logs (JSON text) for AI analysis"),
    victim_state: str = Form(default="KA", description="2-letter Indian state code"),
    device_id: str = Depends(verify_device_token),
    db: AsyncSession = Depends(get_db),
):
    print(f"DEBUG: submit_evidence called by {device_id}")
    try:
        # --- Step 1: Save & hash the evidence file ---
        case_id = f"CS-{uuid.uuid4().hex[:8].upper()}"
        file_path = os.path.join(settings.EVIDENCE_UPLOAD_DIR, f"{case_id}.cyberspy")

        content = await evidence_file.read()
        evidence_hash = hashlib.sha256(content).hexdigest()

        with open(file_path, "wb") as f:
            f.write(content)

        # --- Step 2: AI Analysis ---
        log_text = device_logs if device_logs else "No raw logs provided — using evidence metadata"
        snapshot = await analyze_logs_with_llm(log_text)

        # --- Step 3: Generate Forensic Report ---
        report = generate_forensic_report(case_id, snapshot)

        # --- Step 4: Dispatch to Authority ---
        dispatch_result = await dispatch_to_authority(
            case_id, snapshot, evidence_hash, victim_state
        )

        # --- Step 5: Save case to DB ---
        try:
            logs_data = json.loads(device_logs) if device_logs else {}
        except:
            logs_data = {"error": "Malformed JSON logs"}

        case = CaseRecord(
            case_id=case_id,
            device_id=device_id,
            status=CaseStatus.DISPATCHED.value,
            threat_level=snapshot.threat_level.value,
            attack_type=snapshot.attack_type.value,
            summary=snapshot.summary,
            iocs=[ioc.model_dump() for ioc in snapshot.iocs],
            device_logs=logs_data,
            evidence_hash=evidence_hash,
            authority_crn=dispatch_result.authority_crn,
            dispatched_to=dispatch_result.dispatched_to,
            report_path=file_path,
        )
        db.add(case)
        await db.flush()

        return EvidenceSubmitResponse(
            case_id=case_id,
            status=CaseStatus.DISPATCHED,
            evidence_hash=evidence_hash,
            message=(
                f"Evidence received and analyzed. Threat level: {snapshot.threat_level.value}. "
                f"Dispatched to {dispatch_result.dispatched_to}. "
                f"Authority CRN: {dispatch_result.authority_crn}"
            ),
        )
    except Exception as e:
        import traceback
        with open("error_log.txt", "a") as f:
            f.write(f"\n--- ERROR {datetime.now()} ---\n{traceback.format_exc()}\n")
        raise HTTPException(status_code=500, detail=str(e))


# ============================================================
#  CASE STATUS
# ============================================================

@app.get(
    "/api/v1/case/{case_id}/status",
    response_model=CaseStatusResponse,
    tags=["Cases"],
    summary="Check the status of a submitted case",
)
async def get_case_status(
    case_id: str,
    device_id: str = Depends(verify_device_token),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CaseRecord).where(
            CaseRecord.case_id == case_id,
            CaseRecord.device_id == device_id,
        )
    )
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    return CaseStatusResponse(
        case_id=case.case_id,
        status=CaseStatus(case.status),
        threat_level=case.threat_level,
        summary=case.summary,
        authority_crn=case.authority_crn,
        dispatched_to=case.dispatched_to,
        created_at=case.created_at,
        updated_at=case.updated_at,
    )


# ============================================================
#  ADMIN DASHBOARD LISTING
# ============================================================

@app.get(
    "/api/v1/admin/cases",
    response_model=list[CaseStatusResponse],
    tags=["Admin"],
    summary="Get all cases for the admin dashboard",
)
async def get_all_cases(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(CaseRecord).order_by(CaseRecord.created_at.desc()))
    cases = result.scalars().all()
    
    return [
        CaseStatusResponse(
            case_id=c.case_id,
            status=CaseStatus(c.status),
            threat_level=c.threat_level,
            summary=c.summary,
            iocs=c.iocs,
            device_logs=c.device_logs,
            attack_type=c.attack_type,
            evidence_hash=c.evidence_hash,
            authority_crn=c.authority_crn,
            dispatched_to=c.dispatched_to,
            created_at=c.created_at,
            updated_at=c.updated_at,
        ) for c in cases
    ]

# ============================================================
#  WEB DASHBOARD UI UI
# ============================================================

from fastapi.responses import HTMLResponse

@app.get("/dashboard", response_class=HTMLResponse, tags=["Admin"])
async def dashboard_ui():
    """Serves the main admin dashboard HTML file."""
    try:
        with open("dashboard.html", "r", encoding="utf-8") as f:
            return f.read()
    except FileNotFoundError:
        return "<h1 style='color:red;'>dashboard.html not found!</h1>"

# ============================================================
#  FORENSIC REPORT RETRIEVAL
# ============================================================

@app.get(
    "/api/v1/case/{case_id}/report",
    response_model=ForensicReport,
    tags=["Cases"],
    summary="Retrieve the AI-generated forensic report",
)
async def get_case_report(
    case_id: str,
    device_id: str = Depends(verify_device_token),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(CaseRecord).where(
            CaseRecord.case_id == case_id,
            CaseRecord.device_id == device_id,
        )
    )
    case = result.scalar_one_or_none()

    if not case:
        raise HTTPException(status_code=404, detail="Case not found")

    # Re-generate report from stored data
    from models import IOC, ThreatLevel, AttackType

    snapshot = ThreatSnapshot(
        threat_level=ThreatLevel(case.threat_level),
        summary=case.summary or "",
        iocs=[IOC(**ioc) for ioc in (case.iocs or [])],
        attack_type=AttackType(case.attack_type) if case.attack_type else AttackType.UNKNOWN,
        confidence=0.9,
    )
    report = generate_forensic_report(case_id, snapshot)
    return report


# ============================================================
#  ANALYSIS-ONLY ENDPOINT (for on-device LLM fallback)
# ============================================================

@app.post(
    "/api/v1/analyze",
    response_model=ThreatSnapshot,
    tags=["Analysis"],
    summary="Analyze device logs without full evidence submission",
)
async def analyze_logs(
    logs: str = Form(..., description="Raw device logs in JSON format"),
    device_id: str = Depends(verify_device_token),
):
    """
    Quick analysis endpoint: sends logs to AI and returns threat snapshot.
    Used when on-device LLM is unavailable or for second-opinion analysis.
    """
    snapshot = await analyze_logs_with_llm(logs)
    return snapshot


# ============================================================
#  AUTHORITY ROUTING PREVIEW
# ============================================================

@app.post(
    "/api/v1/dispatch/preview",
    tags=["Dispatch"],
    summary="Preview which authorities a case would be routed to",
)
async def preview_dispatch(
    snapshot: ThreatSnapshot,
    victim_state: str = "KA",
    device_id: str = Depends(verify_device_token),
):
    """Preview the dispatch routing without actually sending."""
    routing = determine_dispatch_target(snapshot, victim_state)
    return routing


# ============================================================
#  WEBSOCKET — REAL-TIME CASE UPDATES
# ============================================================

@app.websocket("/ws/v1/case/{case_id}/updates")
async def case_updates_ws(websocket: WebSocket, case_id: str):
    """
    WebSocket endpoint for real-time case status updates.
    The Android app connects here after submitting evidence.
    """
    await websocket.accept()
    try:
        # Send initial status
        await websocket.send_json({
            "case_id": case_id,
            "event": "connected",
            "message": "Connected to case update stream",
            "timestamp": datetime.utcnow().isoformat(),
        })

        # In production, this would listen to a Redis pub/sub channel
        # For now, keep connection alive and send periodic heartbeats
        import asyncio
        while True:
            await asyncio.sleep(30)
            await websocket.send_json({
                "case_id": case_id,
                "event": "heartbeat",
                "timestamp": datetime.utcnow().isoformat(),
            })
    except Exception:
        pass  # Client disconnected


# ============================================================
#  ENTRY POINT
# ============================================================

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
