"""
Anomaly Detector Model
Machine Learning model for detecting anomalies in system behavior and network traffic
"""

import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.decomposition import PCA
import joblib
import os
from datetime import datetime, timedelta
import json
import re

class AnomalyDetector:
    def __init__(self):
        self.model = IsolationForest(
            contamination=0.05,  # Expect 5% anomalies
            random_state=42,
            n_estimators=100
        )
        self.scaler = StandardScaler()
        self.pca = PCA(n_components=10)
        self.baseline_metrics = None
        self.model_path = 'data/trained_models/anomaly_detector.pkl'
        self._initialize_model()
        self._initialize_baseline()

    def _initialize_model(self):
        """Initialize or load the anomaly detection model"""
        if os.path.exists(self.model_path):
            try:
                saved_data = joblib.load(self.model_path)
                self.model = saved_data['model']
                self.scaler = saved_data['scaler']
                self.baseline_metrics = saved_data.get('baseline', None)
                print("Loaded existing anomaly detection model")
            except:
                print("Error loading model, creating new one")
                self._create_default_model()
        else:
            self._create_default_model()

    def _create_default_model(self):
        """Create a default model with synthetic training data"""
        print("Creating new anomaly detection model")
        # Generate synthetic normal data for initial training
        normal_data = self._generate_synthetic_normal_data(1000)
        features = self._extract_statistical_features(normal_data)

        # Fit the scaler and model
        scaled_features = self.scaler.fit_transform(features)
        self.model.fit(scaled_features)

    def _initialize_baseline(self):
        """Initialize baseline metrics for comparison"""
        self.baseline_metrics = {
            'avg_request_rate': 100,
            'avg_error_rate': 0.02,
            'avg_response_time': 200,
            'avg_bandwidth': 1000,
            'avg_connections': 50,
            'patterns': {
                'normal_hours': (6, 22),  # 6 AM to 10 PM
                'peak_hours': (9, 17),     # 9 AM to 5 PM
                'weekend_factor': 0.3      # 30% of weekday traffic
            }
        }

    def detect(self, logs):
        """Detect anomalies in log data"""
        anomalies = []
        anomaly_summary = {
            'total_anomalies': 0,
            'behavioral': 0,
            'statistical': 0,
            'temporal': 0,
            'network': 0
        }

        # Extract features from logs
        features = self._extract_features_from_logs(logs)

        # Statistical anomaly detection
        if len(features) > 0:
            statistical_anomalies = self._detect_statistical_anomalies(features, logs)
            anomalies.extend(statistical_anomalies)
            anomaly_summary['statistical'] = len(statistical_anomalies)

        # Behavioral anomaly detection
        behavioral_anomalies = self._detect_behavioral_anomalies(logs)
        anomalies.extend(behavioral_anomalies)
        anomaly_summary['behavioral'] = len(behavioral_anomalies)

        # Temporal anomaly detection
        temporal_anomalies = self._detect_temporal_anomalies(logs)
        anomalies.extend(temporal_anomalies)
        anomaly_summary['temporal'] = len(temporal_anomalies)

        # Network anomaly detection
        network_anomalies = self._detect_network_anomalies(logs)
        anomalies.extend(network_anomalies)
        anomaly_summary['network'] = len(network_anomalies)

        anomaly_summary['total_anomalies'] = len(anomalies)

        return {
            'anomalies': anomalies,
            'summary': anomaly_summary,
            'anomaly_score': self._calculate_anomaly_score(anomaly_summary),
            'recommendations': self._generate_recommendations(anomalies)
        }

    def _extract_features_from_logs(self, logs):
        """Extract numerical features from logs for anomaly detection"""
        features = []

        for log in logs:
            if isinstance(log, dict):
                feature = self._extract_dict_features(log)
            else:
                feature = self._extract_text_features(str(log))

            if feature is not None:
                features.append(feature)

        return np.array(features) if features else np.array([])

    def _extract_dict_features(self, log_dict):
        """Extract features from dictionary log entry"""
        try:
            features = [
                log_dict.get('response_time', 0),
                log_dict.get('status_code', 200),
                log_dict.get('bytes_sent', 0),
                log_dict.get('bytes_received', 0),
                log_dict.get('error_count', 0),
                log_dict.get('request_rate', 0),
                len(log_dict.get('user_agent', '')),
                len(log_dict.get('request_path', '')),
                log_dict.get('connection_count', 0),
                1 if log_dict.get('is_authenticated', False) else 0
            ]
            return features
        except:
            return None

    def _extract_text_features(self, log_text):
        """Extract features from text log entry"""
        try:
            features = [
                len(log_text),
                log_text.count(' '),
                log_text.count('error'),
                log_text.count('warning'),
                log_text.count('failed'),
                len(re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', log_text)),
                len(re.findall(r'\b[4-5]\d{2}\b', log_text)),  # HTTP error codes
                len(re.findall(r':\d+', log_text)),  # Port numbers
                sum(1 for c in log_text if c.isupper()) / max(len(log_text), 1),
                sum(1 for c in log_text if c.isdigit()) / max(len(log_text), 1)
            ]
            return features
        except:
            return None

    def _detect_statistical_anomalies(self, features, logs):
        """Detect statistical anomalies using Isolation Forest"""
        anomalies = []

        try:
            if len(features) > 0:
                # Scale features
                scaled_features = self.scaler.fit_transform(features)

                # Predict anomalies
                predictions = self.model.predict(scaled_features)
                anomaly_indices = np.where(predictions == -1)[0]

                for idx in anomaly_indices:
                    if idx < len(logs):
                        anomaly = {
                            'timestamp': datetime.now().isoformat(),
                            'type': 'statistical',
                            'severity': 'medium',
                            'description': 'Statistical anomaly detected in log pattern',
                            'log_entry': str(logs[idx])[:200],
                            'confidence': 0.85,
                            'details': {
                                'feature_deviation': self._calculate_feature_deviation(features[idx])
                            }
                        }
                        anomalies.append(anomaly)
        except Exception as e:
            print(f"Statistical anomaly detection error: {e}")

        return anomalies

    def _detect_behavioral_anomalies(self, logs):
        """Detect anomalies in user/system behavior"""
        anomalies = []

        # Track user behavior patterns
        user_activities = {}
        suspicious_patterns = [
            {'pattern': r'admin.*login.*failed', 'severity': 'high', 'desc': 'Failed admin login attempts'},
            {'pattern': r'download.*database', 'severity': 'critical', 'desc': 'Database download attempt'},
            {'pattern': r'delete.*from.*users', 'severity': 'critical', 'desc': 'User deletion attempt'},
            {'pattern': r'grant.*privileges', 'severity': 'high', 'desc': 'Privilege escalation attempt'},
            {'pattern': r'export.*sensitive', 'severity': 'high', 'desc': 'Sensitive data export'},
            {'pattern': r'unusual.*activity', 'severity': 'medium', 'desc': 'Unusual activity flagged'}
        ]

        for log in logs:
            log_text = json.dumps(log) if isinstance(log, dict) else str(log)

            # Check for suspicious patterns
            for pattern_info in suspicious_patterns:
                if re.search(pattern_info['pattern'], log_text, re.IGNORECASE):
                    anomaly = {
                        'timestamp': datetime.now().isoformat(),
                        'type': 'behavioral',
                        'severity': pattern_info['severity'],
                        'description': pattern_info['desc'],
                        'log_entry': log_text[:200],
                        'confidence': 0.90,
                        'details': {
                            'pattern_matched': pattern_info['pattern']
                        }
                    }
                    anomalies.append(anomaly)

            # Track user activities for unusual behavior
            if 'user' in log_text.lower():
                user_match = re.search(r'user[:\s]+(\w+)', log_text, re.IGNORECASE)
                if user_match:
                    user = user_match.group(1)
                    if user not in user_activities:
                        user_activities[user] = {'count': 0, 'actions': []}
                    user_activities[user]['count'] += 1

                    # Flag if user activity is unusually high
                    if user_activities[user]['count'] > 100:
                        anomaly = {
                            'timestamp': datetime.now().isoformat(),
                            'type': 'behavioral',
                            'severity': 'medium',
                            'description': f'Unusually high activity for user: {user}',
                            'log_entry': log_text[:200],
                            'confidence': 0.75,
                            'details': {
                                'user': user,
                                'activity_count': user_activities[user]['count']
                            }
                        }
                        anomalies.append(anomaly)

        return anomalies

    def _detect_temporal_anomalies(self, logs):
        """Detect anomalies based on time patterns"""
        anomalies = []
        current_hour = datetime.now().hour

        # Check for activities outside normal hours
        if not (self.baseline_metrics['patterns']['normal_hours'][0] <=
                current_hour <=
                self.baseline_metrics['patterns']['normal_hours'][1]):

            for log in logs[:5]:  # Check first 5 logs
                anomaly = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'temporal',
                    'severity': 'low',
                    'description': 'Activity detected outside normal business hours',
                    'log_entry': str(log)[:200],
                    'confidence': 0.60,
                    'details': {
                        'current_hour': current_hour,
                        'normal_hours': self.baseline_metrics['patterns']['normal_hours']
                    }
                }
                anomalies.append(anomaly)
                break  # Only add one temporal anomaly

        return anomalies

    def _detect_network_anomalies(self, logs):
        """Detect network-related anomalies"""
        anomalies = []

        # Track IP addresses and connections
        ip_counts = {}
        port_scans = []

        for log in logs:
            log_text = json.dumps(log) if isinstance(log, dict) else str(log)

            # Extract IP addresses
            ips = re.findall(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', log_text)
            for ip in ips:
                if ip not in ip_counts:
                    ip_counts[ip] = 0
                ip_counts[ip] += 1

            # Check for port scanning patterns
            ports = re.findall(r':(\d+)', log_text)
            if len(ports) > 10:
                anomaly = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'network',
                    'severity': 'high',
                    'description': 'Possible port scanning detected',
                    'log_entry': log_text[:200],
                    'confidence': 0.80,
                    'details': {
                        'ports_accessed': len(ports),
                        'sample_ports': ports[:10]
                    }
                }
                anomalies.append(anomaly)

        # Check for IP flooding
        for ip, count in ip_counts.items():
            if count > 50:  # Threshold for flooding
                anomaly = {
                    'timestamp': datetime.now().isoformat(),
                    'type': 'network',
                    'severity': 'high',
                    'description': f'Possible flooding from IP: {ip}',
                    'log_entry': f'Multiple requests from {ip}',
                    'confidence': 0.85,
                    'details': {
                        'source_ip': ip,
                        'request_count': count
                    }
                }
                anomalies.append(anomaly)

        return anomalies

    def _calculate_feature_deviation(self, features):
        """Calculate how much features deviate from baseline"""
        if self.baseline_metrics is None:
            return "No baseline available"

        # Simple deviation calculation
        deviation = np.mean(np.abs(features - np.mean(features)))
        return f"{deviation:.2f} standard deviations from normal"

    def _calculate_anomaly_score(self, summary):
        """Calculate overall anomaly score"""
        score = (
                summary['behavioral'] * 30 +
                summary['statistical'] * 25 +
                summary['network'] * 25 +
                summary['temporal'] * 10
        )
        return min(score, 100)

    def _generate_recommendations(self, anomalies):
        """Generate security recommendations based on detected anomalies"""
        recommendations = []

        if any(a['type'] == 'behavioral' for a in anomalies):
            recommendations.append("Review user access logs and implement stricter authentication")

        if any(a['type'] == 'statistical' for a in anomalies):
            recommendations.append("Investigate unusual patterns and update baseline metrics")

        if any(a['type'] == 'network' for a in anomalies):
            recommendations.append("Enable network monitoring and implement rate limiting")

        if any(a['type'] == 'temporal' for a in anomalies):
            recommendations.append("Review after-hours access policies")

        return recommendations

    def _generate_synthetic_normal_data(self, n_samples):
        """Generate synthetic normal data for model initialization"""
        data = []
        for _ in range(n_samples):
            entry = {
                'response_time': np.random.normal(200, 50),
                'status_code': np.random.choice([200, 201, 204, 301, 302], p=[0.7, 0.1, 0.1, 0.05, 0.05]),
                'bytes_sent': np.random.normal(5000, 1000),
                'error_count': np.random.poisson(0.5),
                'request_rate': np.random.normal(100, 20)
            }
            data.append(entry)
        return data

    def _extract_statistical_features(self, data):
        """Extract statistical features for model training"""
        features = []
        for entry in data:
            if isinstance(entry, dict):
                feature = [
                    entry.get('response_time', 0),
                    entry.get('status_code', 200),
                    entry.get('bytes_sent', 0),
                    entry.get('error_count', 0),
                    entry.get('request_rate', 0)
                ]
                features.append(feature)
        return np.array(features)

    def train(self, training_data):
        """Train the anomaly detection model with new data"""
        try:
            features = self._extract_statistical_features(training_data)

            if len(features) > 0:
                # Scale and fit the model
                scaled_features = self.scaler.fit_transform(features)
                self.model.fit(scaled_features)

                # Save the model
                os.makedirs(os.path.dirname(self.model_path), exist_ok=True)
                joblib.dump({
                    'model': self.model,
                    'scaler': self.scaler,
                    'baseline': self.baseline_metrics
                }, self.model_path)

                return {
                    'success': True,
                    'samples_trained': len(features),
                    'model_saved': True
                }
            else:
                return {
                    'success': False,
                    'error': 'No valid features extracted from training data'
                }
        except Exception as e:
            return {
                'success': False,
                'error': str(e)
            }