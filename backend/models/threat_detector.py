"""
Threat Detector Model
Machine Learning model for detecting cybersecurity threats in log data
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib
import os
import re
from datetime import datetime
import json

class ThreatDetector:
    def __init__(self):
        self.model = None
        self.scaler = StandardScaler()
        self.vectorizer = TfidfVectorizer(max_features=100)
        self.threat_patterns = self._load_threat_patterns()
        self.model_path = 'data/trained_models/threat_detector.pkl'
        self._initialize_model()

    def _initialize_model(self):
        """Initialize or load the threat detection model"""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
                print("Loaded existing threat detection model")
            except:
                self.model = IsolationForest(contamination=0.1, random_state=42)
                print("Created new threat detection model")
        else:
            self.model = IsolationForest(contamination=0.1, random_state=42)
            print("Initialized new threat detection model")

    def _load_threat_patterns(self):
        """Load known threat patterns for rule-based detection"""
        return {
            'sql_injection': {
                'patterns': [
                    r"(\%27)|(\')|(\-\-)|(\%23)|(#)",
                    r"((\%3D)|(=))[^\n]*((\%27)|(\')|(\-\-)|(\%3B)|(;))",
                    r"\w*((\%27)|(\'))((\%6F)|o|(\%4F))((\%72)|r|(\%52))",
                    r"((\%27)|(\'))union",
                    r"exec(\s|\+)+(s|x)p\w+",
                    r"UNION.*SELECT",
                    r"DROP.*TABLE"
                ],
                'severity': 'critical',
                'category': 'SQL Injection'
            },
            'xss_attack': {
                'patterns': [
                    r"<script[^>]*>.*?</script>",
                    r"javascript:",
                    r"on\w+\s*=",
                    r"<iframe[^>]*>.*?</iframe>",
                    r"alert\s*\(",
                    r"prompt\s*\(",
                    r"confirm\s*\("
                ],
                'severity': 'high',
                'category': 'Cross-Site Scripting'
            },
            'directory_traversal': {
                'patterns': [
                    r"\.\.\/",
                    r"\.\.\\",
                    r"\%2e\%2e\%2f",
                    r"\%2e\%2e\/",
                    r"\.\.\/\.\.\/",
                    r"etc\/passwd",
                    r"windows\/system32"
                ],
                'severity': 'high',
                'category': 'Directory Traversal'
            },
            'command_injection': {
                'patterns': [
                    r";\s*ls\s*",
                    r";\s*cat\s*",
                    r";\s*wget\s*",
                    r";\s*curl\s*",
                    r"\|\s*nc\s*",
                    r"&&\s*whoami",
                    r"`.*`",
                    r"\$\(.*\)"
                ],
                'severity': 'critical',
                'category': 'Command Injection'
            },
            'brute_force': {
                'patterns': [
                    r"Failed password",
                    r"authentication failure",
                    r"Invalid user",
                    r"Failed login"
                ],
                'severity': 'medium',
                'category': 'Brute Force',
                'threshold': 5  # Number of attempts to trigger
            },
            'ddos_pattern': {
                'patterns': [
                    r"SYN_RECV",
                    r"connection reset",
                    r"connection refused",
                    r"timeout"
                ],
                'severity': 'high',
                'category': 'DDoS Attack'
            },
            'malware_indicators': {
                'patterns': [
                    r"\/tmp\/\.\w+",
                    r"chmod\s+777",
                    r"base64\s+\-d",
                    r"eval\s*\(",
                    r"exec\s*\(",
                    r"system\s*\(",
                    r"backdoor",
                    r"rootkit"
                ],
                'severity': 'critical',
                'category': 'Malware'
            },
            'privilege_escalation': {
                'patterns': [
                    r"sudo\s+",
                    r"su\s+root",
                    r"\/etc\/shadow",
                    r"\/etc\/sudoers",
                    r"privilege\s+escalation",
                    r"SUID",
                    r"setuid"
                ],
                'severity': 'critical',
                'category': 'Privilege Escalation'
            }
        }

    def analyze(self, logs):
        """Analyze logs for threats"""
        threats = []
        threat_summary = {
            'total_threats': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }

        # Rule-based detection
        for log_entry in logs:
            if isinstance(log_entry, dict):
                log_text = json.dumps(log_entry)
            else:
                log_text = str(log_entry)

            for threat_type, threat_info in self.threat_patterns.items():
                for pattern in threat_info['patterns']:
                    if re.search(pattern, log_text, re.IGNORECASE):
                        threat = {
                            'timestamp': datetime.now().isoformat(),
                            'type': threat_type,
                            'category': threat_info['category'],
                            'severity': threat_info['severity'],
                            'pattern_matched': pattern,
                            'log_entry': log_text[:200],  # First 200 chars
                            'recommendation': self._get_recommendation(threat_type)
                        }
                        threats.append(threat)
                        threat_summary['total_threats'] += 1
                        threat_summary[threat_info['severity']] += 1
                        break  # One match per threat type per log

        # ML-based anomaly detection if we have enough data
        if len(logs) > 10:
            try:
                features = self._extract_features(logs)
                if features is not None and len(features) > 0:
                    # Fit the model if not trained
                    if not hasattr(self.model, 'offset_'):
                        self.model.fit(features)

                    predictions = self.model.predict(features)
                    anomalies = np.where(predictions == -1)[0]

                    for idx in anomalies:
                        if idx < len(logs):
                            threat = {
                                'timestamp': datetime.now().isoformat(),
                                'type': 'anomaly',
                                'category': 'Anomaly Detection',
                                'severity': 'medium',
                                'pattern_matched': 'ML-based detection',
                                'log_entry': str(logs[idx])[:200],
                                'recommendation': 'Review this log entry for unusual behavior'
                            }
                            if threat not in threats:  # Avoid duplicates
                                threats.append(threat)
                                threat_summary['total_threats'] += 1
                                threat_summary['medium'] += 1
            except Exception as e:
                print(f"ML analysis error: {e}")

        return {
            'threats': threats,
            'summary': threat_summary,
            'risk_score': self._calculate_threat_score(threat_summary)
        }

    def _extract_features(self, logs):
        """Extract numerical features from logs for ML analysis"""
        try:
            features = []
            for log in logs:
                if isinstance(log, dict):
                    log_text = json.dumps(log)
                else:
                    log_text = str(log)

                feature_vector = [
                    len(log_text),  # Length of log entry
                    log_text.count(' '),  # Number of spaces
                    log_text.count('.'),  # Number of dots
                    log_text.count('/'),  # Number of slashes
                    log_text.count('='),  # Number of equals
                    log_text.count('?'),  # Number of question marks
                    sum(1 for c in log_text if c.isupper()),  # Uppercase count
                    sum(1 for c in log_text if c.isdigit()),  # Digit count
                    len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', log_text)),  # IP count
                ]
                features.append(feature_vector)

            return np.array(features) if features else None
        except Exception as e:
            print(f"Feature extraction error: {e}")
            return None

    def _get_recommendation(self, threat_type):
        """Get security recommendation for detected threat"""
        recommendations = {
            'sql_injection': 'Implement parameterized queries and input validation. Review database access logs.',
            'xss_attack': 'Enable Content Security Policy (CSP) headers. Sanitize all user inputs.',
            'directory_traversal': 'Implement proper access controls and validate file paths.',
            'command_injection': 'Avoid system calls with user input. Use safe APIs instead.',
            'brute_force': 'Implement account lockout policy and CAPTCHA. Consider IP-based rate limiting.',
            'ddos_pattern': 'Enable DDoS protection. Implement rate limiting and traffic filtering.',
            'malware_indicators': 'Isolate affected system immediately. Run full security scan.',
            'privilege_escalation': 'Review user permissions. Enable audit logging for privileged operations.'
        }
        return recommendations.get(threat_type, 'Review security policies and enable comprehensive logging.')

    def _calculate_threat_score(self, summary):
        """Calculate overall threat score"""
        score = (
                summary['critical'] * 40 +
                summary['high'] * 25 +
                summary['medium'] * 15 +
                summary['low'] * 5
        )
        return min(score, 100)  # Cap at 100

    def train(self, training_data):
        """Train the model with new data"""
        try:
            features = self._extract_features(training_data)
            if features is not None and len(features) > 0:
                self.model.fit(features)
                # Save the trained model
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                joblib.dump(self.model, self.model_path)
                return {
                    'success': True,
                    'samples_trained': len(features),
                    'model_saved': True
                }
            else:
                return {
                    'success': False,
                    'error': 'Could not extract features from training data'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }

    def get_threat_level(self, score):
        """Convert threat score to threat level"""
        if score < 25:
            return 'low'
        elif score < 50:
            return 'medium'
        elif score < 75:
            return 'high'
        else:
            return 'critical'