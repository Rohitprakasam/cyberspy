"""CyberSpy Authority Dispatch Engine

Routes forensic reports to the appropriate law enforcement authority
based on threat type, IOC geography, and severity.
"""

import uuid
from datetime import datetime
from typing import Optional
from models import ThreatSnapshot, AttackType, AuthorityDispatchResult, ThreatLevel
from config import settings


# ============================================================
#  AUTHORITY ROUTING LOGIC
# ============================================================

# Indian state cyber cell endpoints (simulated for hackathon)
STATE_CYBER_CELLS = {
    "KA": {"name": "Karnataka Cyber Crime Cell", "endpoint": "/ka/submit"},
    "MH": {"name": "Maharashtra Cyber Cell", "endpoint": "/mh/submit"},
    "DL": {"name": "Delhi Cyber Cell", "endpoint": "/dl/submit"},
    "TN": {"name": "Tamil Nadu Cyber Cell", "endpoint": "/tn/submit"},
    "UP": {"name": "Uttar Pradesh Cyber Cell", "endpoint": "/up/submit"},
    "WB": {"name": "West Bengal Cyber Cell", "endpoint": "/wb/submit"},
    "GJ": {"name": "Gujarat Cyber Cell", "endpoint": "/gj/submit"},
    "RJ": {"name": "Rajasthan Cyber Cell", "endpoint": "/rj/submit"},
    "AP": {"name": "Andhra Pradesh Cyber Cell", "endpoint": "/ap/submit"},
    "TS": {"name": "Telangana Cyber Cell", "endpoint": "/ts/submit"},
    "KL": {"name": "Kerala Cyber Cell", "endpoint": "/kl/submit"},
    "PB": {"name": "Punjab Cyber Cell", "endpoint": "/pb/submit"},
}


def determine_dispatch_target(
    snapshot: ThreatSnapshot, victim_state: str = "KA"
) -> dict:
    """
    Determine which authority to dispatch to based on:
    1. IOC geography (foreign IPs → Interpol)
    2. Threat type (financial → priority + 1930 helpline)
    3. Severity (CRITICAL → CERT-In alert)
    4. Victim's state → State Cyber Cell
    """
    targets = []

    # Always dispatch to the victim's state cyber cell
    state_info = STATE_CYBER_CELLS.get(
        victim_state.upper(), STATE_CYBER_CELLS["KA"]
    )
    targets.append({
        "authority": state_info["name"],
        "type": "STATE_CYBER_CELL",
        "priority": "PRIMARY",
    })

    # MHA National Portal (always for HIGH/CRITICAL)
    if snapshot.threat_level in (ThreatLevel.HIGH, ThreatLevel.CRITICAL):
        targets.append({
            "authority": "MHA National Cybercrime Portal (cybercrime.gov.in)",
            "type": "MHA_NATIONAL",
            "priority": "PRIMARY",
        })

    # Check for foreign IPs → Interpol/FBI
    has_foreign_ip = any(
        ioc.type == "ip" and _is_foreign_ip(ioc.value) for ioc in snapshot.iocs
    )
    if has_foreign_ip:
        targets.append({
            "authority": "Interpol Cybercrime Directorate (I-24/7)",
            "type": "INTERPOL",
            "priority": "SECONDARY",
        })

    # Financial fraud → 1930 helpline alert
    if snapshot.attack_type in (
        AttackType.CREDENTIAL_THEFT,
        AttackType.PHISHING,
        AttackType.SIM_SWAP,
    ):
        targets.append({
            "authority": "National Cyber Crime Helpline 1930",
            "type": "HELPLINE_1930",
            "priority": "URGENT",
        })

    # Critical infrastructure → CERT-In
    if snapshot.threat_level == ThreatLevel.CRITICAL:
        targets.append({
            "authority": "CERT-In (cert-in.org.in)",
            "type": "CERT_IN",
            "priority": "ALERT",
        })

    return {
        "primary_target": targets[0]["authority"],
        "all_targets": targets,
        "dispatch_count": len(targets),
    }


def _is_foreign_ip(ip: str) -> bool:
    """
    Simple heuristic: if IP doesn't start with common Indian ISP ranges,
    consider it foreign. In production, use a GeoIP database.
    """
    indian_prefixes = (
        "49.", "59.", "103.", "106.", "112.", "115.", "117.",
        "122.", "124.", "125.", "14.", "27.", "43.", "61.",
    )
    return not ip.startswith(indian_prefixes)


async def dispatch_to_authority(
    case_id: str,
    snapshot: ThreatSnapshot,
    evidence_hash: str,
    victim_state: str = "KA",
) -> AuthorityDispatchResult:
    """
    Dispatch the forensic report to the determined authority.
    In production, this makes real API calls. For hackathon, simulated.
    """
    routing = determine_dispatch_target(snapshot, victim_state)
    primary = routing["primary_target"]

    # Generate a Case Reference Number (CRN)
    crn = _generate_crn(victim_state, case_id)

    if settings.DISPATCH_ENABLED:
        # Production: make actual API call to cyber cell
        # await _call_authority_api(primary, case_id, evidence_hash)
        pass

    return AuthorityDispatchResult(
        case_id=case_id,
        dispatched_to=primary,
        authority_crn=crn,
        dispatched_at=datetime.utcnow(),
        status=f"Dispatched to {routing['dispatch_count']} authorities",
    )


def _generate_crn(state_code: str, case_id: str) -> str:
    """Generate a Case Reference Number matching Indian police format."""
    year = datetime.utcnow().year
    seq = uuid.uuid4().hex[:6].upper()
    return f"CC/{state_code.upper()}/{year}/{seq}"
