import torch
from transformers import pipeline
import os

class LogNormalizer:
    PROTOCOL_MAP = {
        'TCP': 'TCP connection', 'UDP': 'UDP datagram',
        'HTTP': 'HTTP request', 'HTTPS': 'HTTPS secure request',
        'FTP': 'FTP file transfer', 'SSH': 'SSH session',
        'ICMP': 'ICMP ping', 'DNS': 'DNS query'
    }
    ACTION_MAP = {'allowed': 'permitted', 'blocked': 'blocked', 'denied': 'denied', 'dropped': 'dropped'}
    SCANNER_AGENTS = ['nmap', 'sqlmap', 'nikto', 'masscan', 'zap', 'burp', 'dirbuster', 'gobuster', 'wfuzz']

    @staticmethod
    def detect_scanner(user_agent):
        ua_lower = str(user_agent).lower()
        for scanner in LogNormalizer.SCANNER_AGENTS:
            if scanner in ua_lower:
                return scanner
        return 'standard browser'

    @staticmethod
    def classify_path_risk(path):
        path_lower = str(path).lower()
        if any(x in path_lower for x in ['admin', 'config', 'backup', 'wp-', '.sql', '.env', 'shell']):
            return 'high-risk path'
        if any(x in path_lower for x in ['login', 'auth', 'secure']):
            return 'authentication path'
        if any(x in path_lower for x in ['api', 'upload', 'download']):
            return 'data operation path'
        return 'standard path'

    @staticmethod
    def bytes_category(b):
        b = int(b)
        if b < 1000: return 'minimal data transfer'
        if b < 10000: return 'small data transfer'
        if b < 30000: return 'moderate data transfer'
        return 'large data transfer'

    @classmethod
    def normalize(cls, row):
        protocol = cls.PROTOCOL_MAP.get(row.get('protocol', ''), row.get('protocol', 'unknown'))
        action = cls.ACTION_MAP.get(row.get('action', ''), row.get('action', 'unknown'))
        scanner = cls.detect_scanner(row.get('user_agent', ''))
        path_risk = cls.classify_path_risk(row.get('request_path', '/'))
        bytes_cat = cls.bytes_category(row.get('bytes_transferred', 0))
        log_type = row.get('log_type', 'unknown')
        action_cap = action.capitalize()
        if scanner != 'standard browser':
            return action_cap + ' ' + protocol + ' detected by ' + log_type + ' log using ' + scanner + ' scanner targeting ' + path_risk + ' with ' + bytes_cat + '.'
        return action_cap + ' ' + protocol + ' recorded by ' + log_type + ' log accessing ' + path_risk + ' with ' + bytes_cat + '.'

    @classmethod
    def normalize_batch(cls, rows):
        return [cls.normalize(row) for row in rows]


class ThreatIntelligenceEngine:
    LABEL_NAMES = ['benign', 'suspicious', 'malicious']
    SEVERITY_MAP = {
        'benign': {'base': 'Low', 'score': 1},
        'suspicious': {'base': 'Medium', 'score': 2},
        'malicious': {'base': 'High', 'score': 3}
    }

    def __init__(self, model_path=None, hf_model=None):
        if hf_model:
            self.classifier = pipeline(
                'text-classification', model=hf_model,
                tokenizer=hf_model, return_all_scores=True,
                device=0 if torch.cuda.is_available() else -1
            )
        else:
            path = model_path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'models', 'cyber-threat-model')
            self.classifier = pipeline(
                'text-classification', model=path,
                tokenizer=path, return_all_scores=True,
                device=0 if torch.cuda.is_available() else -1
            )

    def _get_severity(self, threat, confidence):
        base = self.SEVERITY_MAP.get(threat, {'base': 'Unknown', 'score': 0})
        if confidence > 0.95:
            severity = 'Critical' if threat == 'malicious' else base['base']
        elif confidence > 0.85:
            severity = base['base']
        elif confidence > 0.70:
            severity = 'Low' if base['score'] <= 1 else 'Medium'
        else:
            severity = 'Informational'
        return {'severity': severity, 'base_severity': base['base'], 'score': base['score']}

    def _get_explanation(self, text, threat, confidence):
        reasons = []
        t = text.lower()
        if 'scanner' in t:
            s = 'nmap' if 'nmap' in t else 'sqlmap' if 'sqlmap' in t else 'security scanner'
            s_cap = s.capitalize()
            reasons.append(s_cap + ' scanner detected')
        if 'blocked' in t or 'denied' in t:
            reasons.append('Request blocked/denied by security controls')
        if 'high-risk' in t:
            reasons.append('Targeting high-risk path (admin/config/backup)')
        if 'authentication' in t:
            reasons.append('Authentication endpoint targeted')
        if 'large data' in t:
            reasons.append('Unusually large data transfer')
        if not reasons:
            reasons.append('Pattern matches known threat signature')
        return reasons

    def predict(self, log_text):
        scores = self.classifier(log_text)[0]
        scores_dict = {}
        for s in scores:
            label = s['label'].replace('LABEL_', '')
            scores_dict[label] = s['score']
        label_scores = {}
        for key, val in scores_dict.items():
            idx = int(key.split('_')[-1]) if '_' in key else int(key)
            label_scores[self.LABEL_NAMES[idx]] = val
        threat = max(label_scores, key=label_scores.get)
        confidence = label_scores[threat]
        severity = self._get_severity(threat, confidence)
        explanation = self._get_explanation(log_text, threat, confidence)
        conf_pct = str(round(confidence * 100, 1)) + '%'
        return {
            'threat': threat,
            'confidence': round(confidence, 4),
            'confidence_pct': conf_pct,
            'severity': severity['severity'],
            'all_scores': {k: round(v, 4) for k, v in label_scores.items()},
            'explanation': explanation
        }


class CybersecurityAI:
    def __init__(self, model_path=None, hf_model=None):
        self.normalizer = LogNormalizer
        self.engine = ThreatIntelligenceEngine(model_path=model_path, hf_model=hf_model)

    def analyze_log(self, raw_log):
        normalized = self.normalizer.normalize(raw_log)
        result = self.engine.predict(normalized)
        result['raw_log'] = raw_log
        result['normalized_text'] = normalized
        return result

    def analyze_logs(self, raw_logs):
        return [self.analyze_log(log) for log in raw_logs]


ai_engine = CybersecurityAI()
