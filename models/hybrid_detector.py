import random
import re
import time
import logging
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger(__name__)

class SecurityRuleSet:
    RULES: Dict[str, List[Dict]] = {
        "sql_injection": [
            {"pattern": r"(\%27|\')\s*OR\s*1\s*=\s*1", "weight": 0.95},
            {"pattern": r"UNION\s+SELECT", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"DROP\s+TABLE", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"--", "weight": 0.60},
            {"pattern": r"(\%27|\')\s*;", "weight": 0.70},
            {"pattern": r"SELECT\s+.*\s+FROM", "weight": 0.50, "flags": re.IGNORECASE},
            {"pattern": r"INSERT\s+INTO", "weight": 0.50, "flags": re.IGNORECASE},
            {"pattern": r"OR\s+\'1\'=\'1\'", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"OR\s+1=1", "weight": 0.90, "flags": re.IGNORECASE},
            {"pattern": r"admin'\s*--", "weight": 0.90},
        ],
        "xss": [
            {"pattern": r"<script[^>]*>", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"onerror\s*=", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"javascript\s*:", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"onload\s*=", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"<iframe[^>]*>", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"alert\s*\(", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"<img[^>]*onerror", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"<[^>]*onmouseover", "weight": 0.75, "flags": re.IGNORECASE},
            {"pattern": r"document\.cookie", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"eval\s*\(", "weight": 0.80, "flags": re.IGNORECASE},
        ],
        "command_injection": [
            {"pattern": r"rm\s+-rf", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"cat\s+/etc/passwd", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r";\s*whoami", "weight": 0.90},
            {"pattern": r"&&\s*(whoami|id|pwd)", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"\|[\s]*sh", "weight": 0.90},
            {"pattern": r"`.*`", "weight": 0.80},
            {"pattern": r"\$\s*\(.*\)", "weight": 0.70},
            {"pattern": r"wget\s+http", "weight": 0.75, "flags": re.IGNORECASE},
            {"pattern": r"curl\s+.*\-O", "weight": 0.70, "flags": re.IGNORECASE},
            {"pattern": r"nc\s+-[e]", "weight": 0.90, "flags": re.IGNORECASE},
        ],
        "path_traversal": [
            {"pattern": r"\.\./", "weight": 0.80},
            {"pattern": r"\.\.\\", "weight": 0.80},
            {"pattern": r"/etc/passwd", "weight": 0.90},
            {"pattern": r"/etc/shadow", "weight": 0.90},
            {"pattern": r"\.\.%2f", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"%2e%2e%2f", "weight": 0.90, "flags": re.IGNORECASE},
            {"pattern": r"boot\.ini", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"windows\\system32", "weight": 0.80, "flags": re.IGNORECASE},
        ],
        "scanning_recon": [
            {"pattern": r"\bnmap\b", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"\bmasscan\b", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"\bsqlmap\b", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"\bgobuster\b", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"\bdirbuster\b", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"\bnikto\b", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"\bwfuzz\b", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"\bzap\b", "weight": 0.70, "flags": re.IGNORECASE},
            {"pattern": r"\bburp\b", "weight": 0.70, "flags": re.IGNORECASE},
        ],
        "brute_force": [
            {"pattern": r"failed.*login", "weight": 0.70, "flags": re.IGNORECASE},
            {"pattern": r"invalid.*password", "weight": 0.65, "flags": re.IGNORECASE},
            {"pattern": r"authentication.*fail", "weight": 0.65, "flags": re.IGNORECASE},
            {"pattern": r"login.*attempt", "weight": 0.55, "flags": re.IGNORECASE},
            {"pattern": r"brute.?force", "weight": 0.90, "flags": re.IGNORECASE},
            {"pattern": r"too many.*attempt", "weight": 0.75, "flags": re.IGNORECASE},
            {"pattern": r"account.*lockout", "weight": 0.70, "flags": re.IGNORECASE},
        ],
        "malware_ransomware": [
            {"pattern": r"\bpayload\b", "weight": 0.75, "flags": re.IGNORECASE},
            {"pattern": r"reverse\s+shell", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"\bmeterpreter\b", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"encrypt.*files", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"ransomware", "weight": 0.95, "flags": re.IGNORECASE},
            {"pattern": r"keylogger", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"trojan", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"backdoor", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"\bc2\b.*server", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"command.*control", "weight": 0.80, "flags": re.IGNORECASE},
        ],
        "suspicious_network": [
            {"pattern": r"blocked.*outbound", "weight": 0.60, "flags": re.IGNORECASE},
            {"pattern": r"unusual.*port", "weight": 0.55, "flags": re.IGNORECASE},
            {"pattern": r"\btor\b", "weight": 0.65, "flags": re.IGNORECASE},
            {"pattern": r"\bproxy\b", "weight": 0.50, "flags": re.IGNORECASE},
            {"pattern": r"exfiltrat", "weight": 0.90, "flags": re.IGNORECASE},
            {"pattern": r"dns.*tunnel", "weight": 0.85, "flags": re.IGNORECASE},
            {"pattern": r"data.*breach", "weight": 0.80, "flags": re.IGNORECASE},
            {"pattern": r"port.*scan", "weight": 0.70, "flags": re.IGNORECASE},
        ],
    }

    CATEGORY_SEVERITY: Dict[str, str] = {
        "sql_injection": "malicious",
        "xss": "malicious",
        "command_injection": "malicious",
        "path_traversal": "malicious",
        "malware_ransomware": "malicious",
        "brute_force": "suspicious",
        "scanning_recon": "suspicious",
        "suspicious_network": "suspicious",
    }

    @classmethod
    def scan(cls, text: str) -> Tuple[List[str], float, str]:
        hits: List[str] = []
        max_weight: float = 0.0
        highest_category: str = "benign"
        for category, patterns in cls.RULES.items():
            for rule in patterns:
                flags = rule.get("flags", 0)
                if re.search(rule["pattern"], text, flags):
                    hits.append(category)
                    weight = rule["weight"]
                    if weight > max_weight:
                        max_weight = weight
                        highest_category = category
                    break
        if max_weight >= 0.90:
            label = "malicious"
        elif max_weight >= 0.65:
            label = "suspicious"
        else:
            label = "benign"
        rule_label = cls.CATEGORY_SEVERITY.get(highest_category, label)
        return hits, max_weight, rule_label


class HybridDetector:

    def __init__(
        self,
        model_high_confidence_threshold: float = 0.85,
        malicious_override_threshold: float = 0.70,
        suspicious_override_threshold: float = 0.55,
        enable_rule_fallback: bool = True,
    ):
        self.model_high_conf = model_high_confidence_threshold
        self.malicious_override = malicious_override_threshold
        self.suspicious_override = suspicious_override_threshold
        self.enable_rules = enable_rule_fallback
        self.rule_set = SecurityRuleSet

    def analyze(self, model_result: Dict, raw_text: str) -> Dict:
        start = time.time()
        model_label: str = model_result.get("threat", "benign")
        model_confidence: float = model_result.get("confidence", 0.0)
        all_scores: Dict[str, float] = model_result.get("all_scores", {})

        if not self.enable_rules:
            return self._build_response(
                final_label=model_label,
                confidence=model_confidence,
                model_label=model_label,
                model_confidence=model_confidence,
                rule_label="benign",
                rule_hits=[],
                explanation=[f"Model predicted {model_label} with {model_confidence:.1%} confidence. Rule fallback disabled."],
                raw_text=raw_text,
                all_scores=all_scores,
                latency=time.time() - start,
            )

        rule_hits, rule_weight, rule_label = self.rule_set.scan(raw_text)
        has_malicious_rules = rule_label == "malicious"
        has_suspicious_rules = rule_label == "suspicious"
        is_high_confidence = model_confidence >= self.model_high_conf

        if is_high_confidence and model_label == "benign" and not has_malicious_rules:
            final_label = "benign"
            confidence = max(model_confidence, 0.50)
            explanation_parts = [
                f"Model is confident ({model_confidence:.1%}) that this is benign."
            ]
            if has_suspicious_rules and rule_weight >= 0.50:
                final_label = "suspicious"
                confidence = max(confidence, self.suspicious_override)
                explanation_parts.append(
                    f"Overridden to suspicious due to moderate rule hits: {', '.join(set(rule_hits))}."
                )
        elif model_label == "malicious" and model_confidence > 0.60:
            final_label = "malicious"
            confidence = model_confidence
            explanation_parts = [
                f"Model directly classified as malicious ({model_confidence:.1%})."
            ]
        elif has_malicious_rules:
            final_label = "malicious"
            confidence = max(model_confidence, self.malicious_override)
            explanation_parts = [
                f"Model confidence was {model_confidence:.1%} ({model_label}), "
                f"but strong malicious indicators were detected: {', '.join(set(rule_hits))}."
            ]
        elif has_suspicious_rules and model_confidence < self.model_high_conf:
            final_label = "suspicious"
            confidence = max(model_confidence, self.suspicious_override)
            explanation_parts = [
                f"Model confidence was moderate ({model_confidence:.1%}, {model_label}). "
                f"Suspicious indicators found: {', '.join(set(rule_hits))}."
            ]
        elif model_label == "suspicious" and model_confidence > 0.50:
            final_label = "suspicious"
            confidence = model_confidence
            explanation_parts = [
                f"Model classified as suspicious ({model_confidence:.1%}) with moderate rule indicators."
            ]
        else:
            final_label = model_label
            confidence = model_confidence
            explanation_parts = [
                f"Model predicted {model_label} ({model_confidence:.1%}). No strong rule overrides."
            ]

        if rule_hits:
            explanation_parts.append(
                f"Rule hits: {', '.join(sorted(set(rule_hits)))}."
            )

        return self._build_response(
            final_label=final_label,
            confidence=round(min(confidence, 1.0), 4),
            model_label=model_label,
            model_confidence=round(model_confidence, 4),
            rule_label=rule_label if rule_hits else "benign",
            rule_hits=sorted(set(rule_hits)),
            explanation=explanation_parts,
            raw_text=raw_text,
            all_scores=all_scores,
            latency=time.time() - start,
        )

    def _build_response(
        self,
        final_label: str,
        confidence: float,
        model_label: str,
        model_confidence: float,
        rule_label: str,
        rule_hits: List[str],
        explanation: List[str],
        raw_text: str,
        all_scores: Dict,
        latency: float,
    ) -> Dict:

        if final_label == "benign":
            risk_score = random.randint(0, 30)
            recommendation = "No immediate action required."
        elif final_label == "suspicious":
            risk_score = random.randint(31, 70)
            recommendation = "Review this event and correlate with user/session activity."
        else:
            risk_score = random.randint(71, 100)
            recommendation = "Investigate immediately, block source if confirmed, and preserve logs."

        return {
            "final_label": final_label,
            "confidence": confidence,
            "model_label": model_label,
            "model_confidence": model_confidence,
            "rule_label": rule_label,
            "rule_hits": rule_hits,
            "explanation": " ".join(explanation),
            "risk_score": risk_score,
            "recommendation": recommendation,
            "latency_ms": round(latency * 1000, 2),
            "all_scores": all_scores,
        }


