"""Environment-driven configuration for MandateGuard.

`load_dotenv()` is called explicitly at import time (per build spec) rather than
relying on a cached settings singleton, so a restart always re-reads .env.
"""
from __future__ import annotations

import os
from enum import Enum
from pathlib import Path

from dotenv import load_dotenv

PROJECT_ROOT = Path(__file__).resolve().parent

load_dotenv(PROJECT_ROOT / ".env", override=True)


class Mode(str, Enum):
    """Which trust posture the whole system runs under."""

    VULNERABLE = "vulnerable"
    GUARDED = "guarded"


class Settings:
    """Plain env-backed settings. Re-read on construction, never cached globally."""

    def __init__(self) -> None:
        self.mode: Mode = Mode(os.environ.get("MODE", "guarded").strip().lower())

        self.razorpay_key_id: str = os.environ.get("RAZORPAY_KEY_ID", "").strip()
        self.razorpay_key_secret: str = os.environ.get("RAZORPAY_KEY_SECRET", "").strip()

        self.llm_api_key: str = os.environ.get("LLM_API_KEY", "").strip()
        self.llm_base_url: str = os.environ.get("LLM_BASE_URL", "https://api.openai.com/v1").strip()
        self.llm_model: str = os.environ.get("LLM_MODEL", "gpt-4o-mini").strip()
        self.llm_temperature: float = float(os.environ.get("LLM_TEMPERATURE", "0"))
        self.llm_seed: int = int(os.environ.get("LLM_SEED", "1337"))

        self.db_path: str = os.environ.get("DB_PATH", "mandateguard.db").strip()

    # --- capability probes -------------------------------------------------
    @property
    def razorpay_live(self) -> bool:
        """True when real test-mode Razorpay credentials are configured.

        We deliberately require the rzp_test_ prefix: this project must never
        run against live keys.
        """
        return bool(
            self.razorpay_key_id
            and self.razorpay_key_secret
            and self.razorpay_key_id.startswith("rzp_test_")
        )

    @property
    def llm_live(self) -> bool:
        """True when an OpenAI-compatible LLM endpoint is configured."""
        return bool(self.llm_api_key)

    def describe(self) -> dict:
        return {
            "mode": self.mode.value,
            "razorpay": "live-test-mode" if self.razorpay_live else "simulated",
            "llm": f"live:{self.llm_model}" if self.llm_live else "deterministic-stub",
        }


def get_settings() -> Settings:
    """Build a fresh Settings object. Cheap; intentionally not memoised."""
    return Settings()
