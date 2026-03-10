"""CyberSpy Database Models & Pydantic Schemas"""

from datetime import datetime
from typing import Optional, List
from enum import Enum
from pydantic import BaseModel, Field
from sqlalchemy import Column, String, Integer, Float, DateTime, Text, Boolean, JSON
from sqlalchemy.orm import declarative_base

Base = declarative_base()


# ============================================================
#  ENUMS
# ============================================================

class ThreatLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"
    CRITICAL = "CRITICAL"


class CaseStatus(str, Enum):
    RECEIVED = "RECEIVED"
    ANALYZING = "ANALYZING"
    REPORT_GENERATED = "REPORT_GENERATED"
    DISPATCHED = "DISPATCHED"
    ACCEPTED_BY_AUTHORITY = "ACCEPTED_BY_AUTHORITY"
    UNDER_INVESTIGATION = "UNDER_INVESTIGATION"
    CLOSED = "CLOSED"


class AttackType(str, Enum):
    SPYWARE = "spyware"
    DATA_EXFILTRATION = "data_exfiltration"
    ROOT_EXPLOIT = "root_exploit"
    RANSOMWARE = "ransomware"
    PHISHING = "phishing"
    SIM_SWAP = "sim_swap"
    CREDENTIAL_THEFT = "credential_theft"
    C2_COMMUNICATION = "c2_communication"
    UNKNOWN = "unknown"


# ============================================================
#  DATABASE MODELS (SQLAlchemy)
# ============================================================

class DeviceRecord(Base):
    __tablename__ = "devices"

    id = Column(Integer, primary_key=True, autoincrement=True)
    device_id = Column(String(64), unique=True, nullable=False, index=True)
    device_fingerprint = Column(String(256), nullable=False)
    device_model = Column(String(128))
    android_version = Column(String(16))
    registered_at = Column(DateTime, default=datetime.utcnow)
    last_seen = Column(DateTime, default=datetime.utcnow)
    is_active = Column(Boolean, default=True)


class CaseRecord(Base):
    __tablename__ = "cases"

    id = Column(Integer, primary_key=True, autoincrement=True)
    case_id = Column(String(32), unique=True, nullable=False, index=True)
    device_id = Column(String(64), nullable=False, index=True)
    status = Column(String(32), default=CaseStatus.RECEIVED.value)
    threat_level = Column(String(16))
    attack_type = Column(String(64))
    summary = Column(Text)
    iocs = Column(JSON)  # list of IOC dicts
    device_logs = Column(JSON)  # raw captured logs
    evidence_hash = Column(String(64))  # SHA-256 of evidence package
    ipfs_cid = Column(String(128))  # IPFS content identifier
    authority_crn = Column(String(64))  # Case Reference Number from authority
    dispatched_to = Column(String(128))  # which authority
    report_path = Column(String(256))
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============================================================
#  PYDANTIC SCHEMAS (Request / Response)
# ============================================================

# --- Device Auth ---

class DeviceRegisterRequest(BaseModel):
    device_id: str = Field(..., description="Unique device identifier")
    device_fingerprint: str = Field(..., description="Hardware fingerprint hash")
    device_model: str = Field(default="Unknown")
    android_version: str = Field(default="Unknown")


class DeviceRegisterResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    device_id: str
    expires_in_hours: int


# --- IOC (Indicator of Compromise) ---

class IOC(BaseModel):
    type: str = Field(..., description="ip | domain | hash | app")
    value: str = Field(..., description="The IOC value")
    note: str = Field(default="", description="Additional context")


# --- Threat Snapshot (from on-device LLM or cloud analysis) ---

class ThreatSnapshot(BaseModel):
    threat_level: ThreatLevel
    summary: str = Field(..., description="Plain-English threat summary")
    iocs: List[IOC] = Field(default_factory=list)
    attack_type: AttackType = AttackType.UNKNOWN
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)


# --- Evidence Submission ---

class EvidenceSubmitResponse(BaseModel):
    case_id: str
    status: CaseStatus
    evidence_hash: str
    message: str


# --- Case Status ---

class CaseStatusResponse(BaseModel):
    case_id: str
    status: CaseStatus
    threat_level: Optional[ThreatLevel] = None
    summary: Optional[str] = None
    iocs: Optional[List[dict]] = None
    device_logs: Optional[dict] = None
    attack_type: Optional[str] = None
    evidence_hash: Optional[str] = None
    authority_crn: Optional[str] = None
    dispatched_to: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


# --- Forensic Report ---

class ForensicReport(BaseModel):
    case_id: str
    generated_at: datetime
    threat_level: ThreatLevel
    executive_summary: str
    detailed_analysis: str
    iocs: List[IOC]
    attack_type: AttackType
    attack_timeline: List[str]
    evidence_integrity: str  # SHA-256 verification status
    recommendations: List[str]
    legal_notice: str


# --- Authority Dispatch ---

class AuthorityDispatchResult(BaseModel):
    case_id: str
    dispatched_to: str
    authority_crn: str
    dispatched_at: datetime
    status: str
