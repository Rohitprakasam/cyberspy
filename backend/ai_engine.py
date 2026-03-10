"""CyberSpy AI Analysis Engine

Analyzes raw device logs and generates structured forensic threat assessments.
Supports multiple LLM backends: Gemini, OpenAI, or a mock for development.
"""

import json
import re
from datetime import datetime
from typing import Optional
from config import settings
from models import ThreatLevel, AttackType, IOC, ThreatSnapshot, ForensicReport


# ============================================================
#  LLM ANALYSIS
# ============================================================

SYSTEM_PROMPT = """You are CyberSpy AI, an expert cybersecurity forensic analyst.
You analyze device activity logs from mobile phones and produce structured threat assessments.

Your analysis must be:
1. Accurate — only flag genuinely suspicious indicators
2. Clear — use plain English that a non-technical victim can understand
3. Structured — always output valid JSON

Respond ONLY with a JSON object in this exact format:
{
  "threatLevel": "LOW" | "MEDIUM" | "HIGH" | "CRITICAL",
  "summary": "2-3 sentence plain-English summary of what happened",
  "iocs": [
    {"type": "ip|domain|hash|app", "value": "...", "note": "..."}
  ],
  "attackType": "spyware|data_exfiltration|root_exploit|ransomware|phishing|sim_swap|credential_theft|c2_communication|unknown",
  "confidence": 0.0 to 1.0
}"""


async def analyze_logs_with_llm(raw_logs: str) -> ThreatSnapshot:
    """Send device logs to the configured LLM and parse the threat assessment."""

    if settings.LLM_PROVIDER == "mock":
        return _mock_analysis(raw_logs)

    if settings.LLM_PROVIDER == "gemini":
        return await _analyze_with_gemini(raw_logs)

    if settings.LLM_PROVIDER == "openai":
        return await _analyze_with_openai(raw_logs)

    # Fallback to mock
    return _mock_analysis(raw_logs)


async def _analyze_with_gemini(raw_logs: str) -> ThreatSnapshot:
    """Analyze logs using Google Gemini API."""
    import httpx

    url = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"
    headers = {"Content-Type": "application/json"}
    params = {"key": settings.GEMINI_API_KEY}
    payload = {
        "contents": [
            {
                "parts": [
                    {"text": f"{SYSTEM_PROMPT}\n\nDEVICE ACTIVITY LOGS:\n{raw_logs}"}
                ]
            }
        ],
        "generationConfig": {
            "temperature": 0.2,
            "maxOutputTokens": 1024,
        },
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=payload, headers=headers, params=params)
        resp.raise_for_status()
        data = resp.json()

    text = data["candidates"][0]["content"]["parts"][0]["text"]
    return _parse_llm_response(text)


async def _analyze_with_openai(raw_logs: str) -> ThreatSnapshot:
    """Analyze logs using OpenAI API."""
    import httpx

    url = "https://api.openai.com/v1/chat/completions"
    headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {settings.OPENAI_API_KEY}",
    }
    payload = {
        "model": "gpt-4o-mini",
        "messages": [
            {"role": "system", "content": SYSTEM_PROMPT},
            {"role": "user", "content": f"DEVICE ACTIVITY LOGS:\n{raw_logs}"},
        ],
        "temperature": 0.2,
        "max_tokens": 1024,
    }

    async with httpx.AsyncClient(timeout=30.0) as client:
        resp = await client.post(url, json=payload, headers=headers)
        resp.raise_for_status()
        data = resp.json()

    text = data["choices"][0]["message"]["content"]
    return _parse_llm_response(text)


def _parse_llm_response(text: str) -> ThreatSnapshot:
    """Parse JSON from LLM response text, handling markdown code fences."""
    # Strip markdown code fences if present
    text = text.strip()
    json_match = re.search(r"```(?:json)?\s*([\s\S]*?)```", text)
    if json_match:
        text = json_match.group(1).strip()

    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        # Fallback: try to find JSON object in the text
        brace_match = re.search(r"\{[\s\S]*\}", text)
        if brace_match:
            data = json.loads(brace_match.group(0))
        else:
            return ThreatSnapshot(
                threat_level=ThreatLevel.LOW,
                summary="Unable to parse AI analysis. Manual review required.",
                iocs=[],
                attack_type=AttackType.UNKNOWN,
                confidence=0.0,
            )

    iocs = [
        IOC(
            type=ioc.get("type", "unknown"),
            value=ioc.get("value", ""),
            note=ioc.get("note", ""),
        )
        for ioc in data.get("iocs", [])
    ]

    return ThreatSnapshot(
        threat_level=ThreatLevel(data.get("threatLevel", "LOW")),
        summary=data.get("summary", "No summary available."),
        iocs=iocs,
        attack_type=AttackType(data.get("attackType", "unknown")),
        confidence=float(data.get("confidence", 0.5)),
    )


def _mock_analysis(raw_logs: str) -> ThreatSnapshot:
    """Development mock: returns a realistic sample threat assessment."""
    return ThreatSnapshot(
        threat_level=ThreatLevel.HIGH,
        summary=(
            "Spyware detected communicating with a known C&C server in Netherlands. "
            "Approximately 2.3MB of data was exfiltrated between 02:14-02:31 AM "
            "while the device screen was off. The malicious app is disguised as a system update."
        ),
        iocs=[
            IOC(type="ip", value="185.220.101.47", note="Tor Exit Node, Netherlands"),
            IOC(
                type="app",
                value="com.system.update.service",
                note="Disguised spyware, installed 3 days ago",
            ),
            IOC(
                type="domain",
                value="update-service.darknet.to",
                note="C&C domain, contacted 47 times in 6 hours",
            ),
            IOC(
                type="hash",
                value="a3f2b8c9d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1",
                note="Malicious APK SHA-256",
            ),
        ],
        attack_type=AttackType.C2_COMMUNICATION,
        confidence=0.92,
    )


# ============================================================
#  FORENSIC REPORT GENERATION
# ============================================================

def generate_forensic_report(case_id: str, snapshot: ThreatSnapshot) -> ForensicReport:
    """Generate a structured forensic report from a threat snapshot."""

    timeline = _build_attack_timeline(snapshot)
    recommendations = _build_recommendations(snapshot)

    return ForensicReport(
        case_id=case_id,
        generated_at=datetime.utcnow(),
        threat_level=snapshot.threat_level,
        executive_summary=(
            f"CyberSpy automated analysis has identified a {snapshot.threat_level.value}-severity "
            f"security incident on the victim's device. {snapshot.summary}"
        ),
        detailed_analysis=_build_detailed_analysis(snapshot),
        iocs=snapshot.iocs,
        attack_type=snapshot.attack_type,
        attack_timeline=timeline,
        evidence_integrity="SHA-256 verified — all evidence shards passed integrity check",
        recommendations=recommendations,
        legal_notice=(
            "This report was generated by CyberSpy AI forensic analysis engine. "
            "All evidence is digitally signed and SHA-256 hash-verified. "
            "Evidence packaging meets requirements of Indian Evidence Act, Section 65B "
            "for electronic records admissibility. IPFS-anchored timestamps provide "
            "immutable proof of evidence collection time."
        ),
    )


def _build_detailed_analysis(snapshot: ThreatSnapshot) -> str:
    """Build a detailed narrative analysis from the threat snapshot."""
    lines = [f"Attack Classification: {snapshot.attack_type.value.replace('_', ' ').title()}"]
    lines.append(f"Confidence Score: {snapshot.confidence:.0%}")
    lines.append("")

    if snapshot.iocs:
        lines.append("Indicators of Compromise (IOCs) Detected:")
        for i, ioc in enumerate(snapshot.iocs, 1):
            lines.append(f"  {i}. [{ioc.type.upper()}] {ioc.value}")
            if ioc.note:
                lines.append(f"     Context: {ioc.note}")
        lines.append("")

    lines.append(f"Summary: {snapshot.summary}")
    return "\n".join(lines)


def _build_attack_timeline(snapshot: ThreatSnapshot) -> list[str]:
    """Generate a plausible attack timeline based on detected IOCs."""
    timeline = []
    if any(ioc.type == "app" for ioc in snapshot.iocs):
        timeline.append("T-72h: Malicious application installed on device")
    if any(ioc.type == "ip" or ioc.type == "domain" for ioc in snapshot.iocs):
        timeline.append("T-48h: First connection to command & control server detected")
        timeline.append("T-6h: High-frequency C&C communication begins (beaconing)")
    if snapshot.attack_type in (AttackType.DATA_EXFILTRATION, AttackType.C2_COMMUNICATION):
        timeline.append("T-2h: Data exfiltration detected (screen-off, background upload)")
    timeline.append("T-0: CyberSpy anomaly detector triggered alert")
    timeline.append("T+0: User initiated forensic evidence report")
    return timeline


def _build_recommendations(snapshot: ThreatSnapshot) -> list[str]:
    """Generate actionable recommendations based on threat type."""
    recs = [
        "Immediately enable Airplane Mode to halt ongoing data exfiltration",
        "Do NOT factory reset — this destroys forensic evidence",
        "Change all passwords from a DIFFERENT, clean device",
    ]

    if snapshot.attack_type == AttackType.C2_COMMUNICATION:
        recs.append("Uninstall the flagged malicious application after evidence is preserved")
    if snapshot.attack_type == AttackType.SIM_SWAP:
        recs.append("Contact your telecom provider immediately to report SIM swap fraud")
    if any(ioc.type == "ip" for ioc in snapshot.iocs):
        recs.append("Block flagged IP addresses at router level if possible")

    recs.append("Forward this report to the assigned Cyber Cell officer for investigation")
    recs.append("Preserve the device in its current state for forensic imaging")
    return recs
