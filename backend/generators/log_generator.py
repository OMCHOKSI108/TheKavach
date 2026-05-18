import random
import uuid
from datetime import datetime, timedelta
from typing import List, Dict, Any
from .data_loader import data_loader

INTERNAL_IP_POOL = [f"192.168.1.{i}" for i in range(1, 255)]
EXTERNAL_IP_POOL = [
    f"{random.randint(50,220)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
    for _ in range(500)
]

PROTOCOLS = ["TCP", "UDP", "HTTP", "HTTPS", "FTP", "SSH", "ICMP", "DNS"]
ACTIONS = ["allowed", "blocked"]
THREAT_LABELS = ["benign", "suspicious", "malicious"]
THREAT_WEIGHTS = [0.70, 0.20, 0.10]
LOG_TYPES = ["firewall", "network", "application", "ids"]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/535.11 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "curl/7.64.1",
    "Nmap Scripting Engine",
    "SQLMap/1.6-dev",
    "python-requests/2.31.0",
    "Wget/1.21"
]
REQUEST_PATHS = [
    "/", "/login", "/admin/config", "/api/login", "/api/data",
    "/wp-login.php", "/backup", "/secure", "/auth", "/home/user",
    "/api/v1/users", "/api/v1/logs", "/dashboard", "/settings",
    "/upload", "/download", "/health", "/metrics"
]

class LogGenerator:
    def __init__(self):
        self.base_timestamp = datetime.now() - timedelta(hours=24)

    def _random_ip(self, internal: bool = True) -> str:
        if internal:
            return random.choice(INTERNAL_IP_POOL)
        return random.choice(EXTERNAL_IP_POOL)

    def _random_timestamp(self) -> str:
        offset = timedelta(seconds=random.uniform(0, 86400))
        ts = self.base_timestamp + offset
        return ts.strftime("%Y-%m-%dT%H:%M:%S")

    def _random_bytes(self) -> int:
        return random.randint(64, 65535)

    def generate_single_log(self) -> Dict[str, Any]:
        src_internal = random.random() > 0.3
        dest_internal = random.random() > 0.2
        threat = random.choices(THREAT_LABELS, weights=THREAT_WEIGHTS, k=1)[0]
        action = "blocked" if threat == "malicious" else random.choice(ACTIONS)
        return {
            "id": str(uuid.uuid4()),
            "timestamp": self._random_timestamp(),
            "source_ip": self._random_ip(internal=src_internal),
            "dest_ip": self._random_ip(internal=dest_internal),
            "protocol": random.choice(PROTOCOLS),
            "action": action,
            "threat_label": threat,
            "log_type": random.choice(LOG_TYPES),
            "bytes_transferred": self._random_bytes(),
            "user_agent": random.choice(USER_AGENTS),
            "request_path": random.choice(REQUEST_PATHS)
        }

    def generate_batch(self, count: int = 50) -> List[Dict[str, Any]]:
        return [self.generate_single_log() for _ in range(count)]

log_generator = LogGenerator()
