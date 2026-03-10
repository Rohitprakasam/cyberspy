"""CyberSpy Backend Configuration"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    # --- App ---
    APP_NAME: str = "CyberSpy Backend"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = True

    # --- Security ---
    SECRET_KEY: str = "cyberspy-dev-secret-change-in-production"
    JWT_ALGORITHM: str = "HS256"
    JWT_EXPIRY_HOURS: int = 720  # 30 days for device tokens

    # --- Database ---
    DATABASE_URL: str = "sqlite+aiosqlite:///./cyberspy.db"

    # --- Redis ---
    REDIS_URL: str = "redis://localhost:6379/0"

    # --- AI / LLM ---
    LLM_PROVIDER: str = "gemini"  # "openai" | "gemini" | "mock"
    GEMINI_API_KEY: Optional[str] = "AIzaSyBfwJCkaCTd2qBYHv41XtAMrwLdQwMT3zw"
    OPENAI_API_KEY: Optional[str] = None

    # --- IPFS ---
    IPFS_API_URL: str = "http://localhost:5001"
    IPFS_ENABLED: bool = False  # disabled by default for dev

    # --- Authority Dispatch ---
    CYBER_CELL_API_URL: str = "https://api.cybercrime.gov.in/v1"
    CYBER_CELL_API_KEY: Optional[str] = None
    DISPATCH_ENABLED: bool = False  # disabled by default for dev

    # --- Evidence Storage ---
    EVIDENCE_UPLOAD_DIR: str = "./evidence_packages"
    MAX_EVIDENCE_SIZE_MB: int = 100

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"


settings = Settings()
