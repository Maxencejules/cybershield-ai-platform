"""
CyberShield AI Platform - Backend Server
Main Flask application with API endpoints for threat detection and monitoring
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import numpy as np
import pandas as pd
from datetime import datetime
import os
import sys

# Add backend directory to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

# Fix import paths - remove the dots for relative imports
from models.threat_detector import ThreatDetector
from models.anomaly_detector import AnomalyDetector
from utils.log_parser import LogParser
from api.routes import api_blueprint
# Initialize Flask app
app = Flask(__name__)
CORS(app)

# Configuration
app.config['SECRET_KEY'] = os.getenv('SECRET_KEY', 'cybershield-secret-key-change-in-production')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size

# Initialize models
threat_detector = ThreatDetector()
anomaly_detector = AnomalyDetector()
log_parser = LogParser()

# Register API blueprint
app.register_blueprint(api_blueprint, url_prefix='/api')

@app.route('/')
def home():
    """Health check endpoint"""
    return jsonify({
        'status': 'online',
        'service': 'CyberShield AI Platform',
        'version': '1.0.0',
        'timestamp': datetime.now().isoformat()
    })

@app.route('/api/analyze', methods=['POST'])
def analyze_logs():
    """Analyze log files for threats and anomalies"""
    try:
        data = request.json
        log_content = data.get('log_content', '')
        analysis_type = data.get('analysis_type', 'all')

        # Parse logs
        parsed_logs = log_parser.parse(log_content)

        results = {
            'timestamp': datetime.now().isoformat(),
            'total_logs': len(parsed_logs),
            'analysis_type': analysis_type
        }

        # Perform threat detection
        if analysis_type in ['all', 'threats']:
            threat_results = threat_detector.analyze(parsed_logs)
            results['threats'] = threat_results

        # Perform anomaly detection
        if analysis_type in ['all', 'anomalies']:
            anomaly_results = anomaly_detector.detect(parsed_logs)
            results['anomalies'] = anomaly_results

        # Calculate risk score
        risk_score = calculate_risk_score(results)
        results['risk_score'] = risk_score
        results['risk_level'] = get_risk_level(risk_score)

        return jsonify({
            'success': True,
            'results': results
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 400

@app.route('/api/threat-intelligence', methods=['GET'])
def get_threat_intelligence():
    """Get latest threat intelligence data"""
    try:
        # Mock threat intelligence data
        intel_data = {
            'last_updated': datetime.now().isoformat(),
            'active_threats': [
                {
                    'name': 'DDoS Attack Pattern',
                    'severity': 'high',
                    'indicators': ['Multiple failed login attempts', 'High request rate'],
                    'mitigation': 'Enable rate limiting and IP blocking'
                },
                {
                    'name': 'SQL Injection Attempts',
                    'severity': 'critical',
                    'indicators': ['SQL keywords in parameters', 'Unusual query patterns'],
                    'mitigation': 'Implement input validation and parameterized queries'
                },
                {
                    'name': 'Brute Force Attack',
                    'severity': 'medium',
                    'indicators': ['Sequential password attempts', 'Single source multiple targets'],
                    'mitigation': 'Implement account lockout policies'
                }
            ],
            'statistics': {
                'threats_detected_today': np.random.randint(10, 50),
                'threats_blocked': np.random.randint(5, 30),
                'false_positives': np.random.randint(1, 10)
            }
        }

        return jsonify({
            'success': True,
            'data': intel_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/monitor/realtime', methods=['GET'])
def realtime_monitor():
    """Get real-time monitoring data"""
    try:
        # Generate mock real-time data
        monitoring_data = {
            'timestamp': datetime.now().isoformat(),
            'metrics': {
                'requests_per_second': np.random.randint(100, 1000),
                'active_connections': np.random.randint(50, 500),
                'cpu_usage': np.random.uniform(20, 80),
                'memory_usage': np.random.uniform(30, 70),
                'bandwidth_usage': np.random.uniform(10, 90)
            },
            'alerts': generate_mock_alerts(),
            'status': 'operational'
        }

        return jsonify({
            'success': True,
            'data': monitoring_data
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/upload', methods=['POST'])
def upload_log_file():
    """Upload and analyze log files"""
    try:
        if 'file' not in request.files:
            return jsonify({'success': False, 'error': 'No file provided'}), 400

        file = request.files['file']
        if file.filename == '':
            return jsonify({'success': False, 'error': 'No file selected'}), 400

        # Read file content
        content = file.read().decode('utf-8')

        # Process the log file
        parsed_logs = log_parser.parse(content)
        threat_results = threat_detector.analyze(parsed_logs)
        anomaly_results = anomaly_detector.detect(parsed_logs)

        return jsonify({
            'success': True,
            'filename': file.filename,
            'lines_processed': len(parsed_logs),
            'threats_found': len(threat_results.get('threats', [])),
            'anomalies_detected': len(anomaly_results.get('anomalies', [])),
            'results': {
                'threats': threat_results,
                'anomalies': anomaly_results
            }
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

@app.route('/api/train', methods=['POST'])
def train_model():
    """Train ML models with new data"""
    try:
        data = request.json
        model_type = data.get('model_type', 'threat_detector')
        training_data = data.get('training_data', [])

        if model_type == 'threat_detector':
            result = threat_detector.train(training_data)
        elif model_type == 'anomaly_detector':
            result = anomaly_detector.train(training_data)
        else:
            return jsonify({'success': False, 'error': 'Invalid model type'}), 400

        return jsonify({
            'success': True,
            'model_type': model_type,
            'training_result': result
        })

    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        }), 500

def calculate_risk_score(results):
    """Calculate overall risk score based on analysis results"""
    score = 0

    if 'threats' in results:
        threat_count = len(results['threats'].get('threats', []))
        score += min(threat_count * 20, 50)  # Max 50 points from threats

    if 'anomalies' in results:
        anomaly_count = len(results['anomalies'].get('anomalies', []))
        score += min(anomaly_count * 10, 30)  # Max 30 points from anomalies

    # Add random factor for demonstration
    score += np.random.randint(0, 20)

    return min(score, 100)  # Cap at 100

def get_risk_level(score):
    """Convert risk score to risk level"""
    if score < 25:
        return 'low'
    elif score < 50:
        return 'medium'
    elif score < 75:
        return 'high'
    else:
        return 'critical'

def generate_mock_alerts():
    """Generate mock alerts for demonstration"""
    alert_types = [
        {'type': 'info', 'message': 'System scan completed successfully'},
        {'type': 'warning', 'message': 'Unusual network activity detected'},
        {'type': 'danger', 'message': 'Potential security breach attempt'},
        {'type': 'success', 'message': 'Threat successfully mitigated'}
    ]

    # Randomly select 1-3 alerts
    num_alerts = np.random.randint(1, 4)
    return np.random.choice(alert_types, num_alerts, replace=False).tolist()

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs('data/sample_logs', exist_ok=True)
    os.makedirs('data/trained_models', exist_ok=True)

    # Run the Flask app
    app.run(debug=True, host='0.0.0.0', port=5000)