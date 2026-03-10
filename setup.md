# CyberSpy Setup Guide 🛠️

This guide covers the setup and deployment of both the CyberSpy Backend and the Android App.

---

## 🚀 1. Backend Setup (FastAPI)

The backend is built with Python 3.10+ and FastAPI.

### Prerequisites

- Python 3.10 or higher
- Redis (Optional, for caching/rate-limiting)

### Installation

1. Navigate to the backend directory:
   ```bash
   cd backend
   ```
2. (Optional but recommended) Create a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install the required dependencies:
   ```bash
   pip install -r requirements.txt
   ```
4. Configure Environment Variables:
   - Create a `.env` file in the `backend/` directory.
   - Add the following keys (replace placeholders with real values):
     ```env
     GEMINI_API_KEY=your_gemini_api_key_here
     SECRET_KEY=a_long_random_secure_string_for_jwt
     DATABASE_URL=sqlite+aiosqlite:///./cyberspy_v3.db
     LLM_PROVIDER=gemini  # Or "mock" for testing without an API key
     ```

### Running the Server

Start the FastAPI server using Uvicorn:

```bash
python -m uvicorn main:app --host 0.0.0.0 --port 8000 --reload
```

### Accessing the Dashboard

Open your web browser and navigate to:
`http://localhost:8000/dashboard`

---

## 📱 2. Android App Setup (Kotlin & Jetpack Compose)

The Android app requires Android Studio and Gradle.

### Prerequisites

- Android Studio Ladybug (or newer)
- JDK 17+ (JDK 24 is handled via Gradle toolchains if configured)
- Android SDK API 34+

### Building and Running

1. Open Android Studio.
2. Select **File > Open** and choose the `android/` directory.
3. Allow Gradle to sync and download dependencies.
4. **Configure Backend IP**:
   - The app needs to know where the backend is hosted.
   - By default, it looks for `http://10.0.2.2:8000` (for emulators).
   - If running on a real device, open the app, go to Settings (gear icon), and enter your computer's local network IP address (e.g., `http://192.168.1.5:8000`).
5. Connect your Android device via USB or start an Emulator.
6. Click the **Run** (Play) button in Android Studio.

### Demo Flow

1. Open the CyberSpy app on your device.
2. Click the **"REPORT"** button. The app will capture real-time logs and send them to the backend.
3. Check the web dashboard (`http://localhost:8000/dashboard`) to see the new case appear instantly. Click the case to expand and view the AI-generated forensic analysis and raw logs!
