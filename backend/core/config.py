import os
from typing import List
from dotenv import load_dotenv

load_dotenv()

def str_to_bool(val: str, default: bool = False) -> bool:
    if not val:
        return default
    return val.strip().lower() in ("true", "1", "yes")

def parse_csv_origins(val: str, default: List[str]) -> List[str]:
    if not val:
        return default
    return [o.strip() for o in val.split(",") if o.strip()]


MODEL_HIGH_CONFIDENCE_THRESHOLD: float = float(
    os.getenv("MODEL_HIGH_CONFIDENCE_THRESHOLD", "0.85")
)

MALICIOUS_OVERRIDE_THRESHOLD: float = float(
    os.getenv("MALICIOUS_OVERRIDE_THRESHOLD", "0.70")
)

SUSPICIOUS_OVERRIDE_THRESHOLD: float = float(
    os.getenv("SUSPICIOUS_OVERRIDE_THRESHOLD", "0.55")
)

ENABLE_RULE_BASED_FALLBACK: bool = str_to_bool(
    os.getenv("ENABLE_RULE_BASED_FALLBACK", "true")
)

ALLOWED_ORIGINS: List[str] = parse_csv_origins(
    os.getenv("ALLOWED_ORIGINS"),
    default=["http://localhost:3000", "http://localhost:5173", "http://localhost:8000"],
)

HF_MODEL_ID: str = os.getenv("HF_MODEL_ID", "OMCHOKSI108/TheKavach")

MAX_TEXT_INPUT_LENGTH: int = int(os.getenv("MAX_TEXT_INPUT_LENGTH", "5000"))
