import gradio as gr
from transformers import pipeline
import torch

MODEL_NAME = "OMCHOKSI108/TheKavach"

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


class ThreatEngine:
    LABEL_NAMES = ['benign', 'suspicious', 'malicious']
    SEVERITY_MAP = {
        'benign': {'base': 'Low', 'score': 1},
        'suspicious': {'base': 'Medium', 'score': 2},
        'malicious': {'base': 'High', 'score': 3}
    }

    def __init__(self):
        self.classifier = pipeline(
            'text-classification', model=MODEL_NAME,
            tokenizer=MODEL_NAME, return_all_scores=True,
            device=0 if torch.cuda.is_available() else -1
        )

    def _get_severity(self, threat, confidence):
        base = self.SEVERITY_MAP.get(threat, {'base': 'Unknown', 'score': 0})
        if confidence > 0.95:
            return 'Critical' if threat == 'malicious' else base['base']
        elif confidence > 0.85:
            return base['base']
        elif confidence > 0.70:
            return 'Low' if base['score'] <= 1 else 'Medium'
        return 'Informational'

    def _get_explanation(self, text, threat):
        reasons = []
        t = text.lower()
        if 'scanner' in t:
            s = 'nmap' if 'nmap' in t else 'sqlmap' if 'sqlmap' in t else 'security scanner'
            reasons.append(s.capitalize() + ' scanner detected')
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
        explanation = self._get_explanation(log_text, threat)
        return threat, confidence, severity, label_scores, explanation


engine = ThreatEngine()

def analyze_log(protocol, action, user_agent, request_path, bytes_transferred, log_type):
    row = {
        'protocol': protocol, 'action': action, 'user_agent': user_agent,
        'request_path': request_path, 'bytes_transferred': int(bytes_transferred),
        'log_type': log_type
    }
    normalized = LogNormalizer.normalize(row)
    threat, confidence, severity, scores, explanation = engine.predict(normalized)

    score_text = '\n'.join(['  ' + k + ': ' + str(round(v*100, 1)) + '%' for k, v in scores.items()])
    explanation_text = '\n'.join(['  - ' + r for r in explanation])

    result = 'THREAT: ' + threat.upper() + '\nCONFIDENCE: ' + str(round(confidence*100, 1)) + '%\nSEVERITY: ' + severity + '\n\nSCORES:\n' + score_text + '\n\nEXPLANATION:\n' + explanation_text + '\n\nNORMALIZED LOG:\n' + normalized

    return result

demo = gr.Interface(
    fn=analyze_log,
    inputs=[
        gr.Dropdown(['TCP', 'UDP', 'HTTP', 'HTTPS', 'FTP', 'SSH', 'ICMP', 'DNS'], value='TCP', label='Protocol'),
        gr.Dropdown(['allowed', 'blocked', 'denied'], value='blocked', label='Action'),
        gr.Textbox(value='Nmap Scripting Engine', label='User Agent'),
        gr.Textbox(value='/admin/config', label='Request Path'),
        gr.Number(value=45000, label='Bytes Transferred'),
        gr.Dropdown(['firewall', 'ids', 'application'], value='firewall', label='Log Type')
    ],
    outputs=gr.Textbox(label='Threat Analysis Result', lines=15),
    title='TheKavach - AI Cybersecurity Threat Intelligence',
    description='Enter network log details and get AI-powered threat analysis with severity scoring and explainability. Model: OMCHOKSI108/TheKavach',
    examples=[
        ['TCP', 'blocked', 'Nmap Scripting Engine', '/admin/config', 45000, 'firewall'],
        ['HTTP', 'allowed', 'Mozilla/5.0 Chrome', '/login', 5000, 'application'],
        ['HTTPS', 'blocked', 'SQLMap/1.6-dev', '/api/login', 30000, 'ids'],
        ['ICMP', 'allowed', 'Mozilla/5.0', '/', 1000, 'firewall'],
    ],
    theme=gr.themes.Soft(primary_hue='green')
)

demo.launch()
