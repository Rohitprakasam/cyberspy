# CyberSpy 🛡️

CyberSpy is a comprehensive cyber-threat forensic system designed for real-time mobile hack detection and AI-powered evidence analysis. It consists of a stealthy Android application and a robust FastAPI backend.

## Features

- **Real-Time Monitoring**: The Android app silently monitors 5 critical data streams: network traffic, app usage, system logs, running processes, and device state.
- **On-Device Threat Detection**: Basic anomaly scoring and Indicator of Compromise (IOC) extraction happens directly on the device.
- **Secure Evidence Packaging**: Data is encrypted using AES-256 and sharded before transmission to ensure forensic integrity.
- **AI-Powered Forensic Analysis**: The backend uses Large Language Models (LLMs) like Google Gemini to analyze raw device logs and generate structured forensic reports.
- **Admin Command Center**: A sleek, cyberpunk-themed web dashboard for authorities to view incoming cases, threat levels, expanding IOC details, and raw device activity streams.
- **Automated Dispatch**: The backend features a routing engine to dispatch critical reports to appropriate authorities (e.g., State Cyber Cells, CERT-In, or Interpol).

## Project Structure

- `android/`: The Android client application (Kotlin).
- `backend/`: The FastAPI backend server (Python).
- `setup.md`: Detailed setup and installation instructions.

## Quick Start

Please refer to `setup.md` for detailed instructions on how to run both the backend server and build the Android application.

## Mission

To provide a resilient, automated pipeline for detecting mobile compromises and generating court-admissible forensic evidence.
