# CyberShield AI Platform

A comprehensive AI-powered cybersecurity monitoring and threat detection platform built with Flask, scikit-learn, and TensorFlow.

## 🚀 Features

- **Real-time Threat Detection**: ML-powered detection of SQL injection, XSS, DDoS, and other attacks
- **Anomaly Detection**: Behavioral and statistical anomaly detection using Isolation Forest
- **Log Analysis**: Support for multiple log formats (Apache, Nginx, JSON, Syslog)
- **Dashboard**: Real-time monitoring dashboard with threat visualization
- **Alert System**: Automated alert generation and management
- **Threat Intelligence**: Latest threat intelligence and recommendations
- **RESTful API**: Comprehensive API for integration with other systems

## 📋 Prerequisites

- Python 3.12+
- pip package manager
- Virtual environment (recommended)

## 🛠️ Installation

### 1. Clone the repository
```bash
cd ~/IdeaProjects/cybershield-ai-platform
```

### 2. Create and activate virtual environment
```bash
python3 -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
```

### 3. Install dependencies
```bash
pip install --upgrade pip
pip install flask==3.0.3 flask-cors==4.0.1 scikit-learn==1.5.2 pandas==2.2.3 numpy==1.26.4 joblib==1.4.2 tensorflow==2.17.0 requests==2.32.3 python-dotenv==1.0.1
```

### 4. Create necessary directories
```bash
mkdir -p backend/models backend/api backend/utils data/sample_logs data/trained_models
```

### 5. Create `__init__.py` files
```bash
touch backend/__init__.py backend/models/__init__.py backend/api/__init__.py backend/utils/__init__.py
```

### 6. Set up environment variables
Create a `.env` file in the project root:
```bash
echo "SECRET_KEY=your-secret-key-here-change-in-production" > .env
echo "FLASK_ENV=development" >> .env
echo "FLASK_DEBUG=True" >> .env
```

## 🏃‍♂️ Running the Application

### Start the Flask backend server:
```bash
cd backend
python app.py
```

The server will start on `http://localhost:5000`

## 📡 API Endpoints

### Core Endpoints

- `GET /` - Health check
- `POST /api/analyze` - Analyze logs for threats
- `GET /api/threat-intelligence` - Get threat intelligence data
- `GET /api/monitor/realtime` - Real-time monitoring data
- `POST /api/upload` - Upload and analyze log files
- `POST /api/train` - Train ML models

### Additional Endpoints

- `GET /api/dashboard` - Dashboard overview data
- `GET /api/alerts` - Get security alerts
- `GET /api/reports` - Generate security reports
- `GET /api/system/health` - System health status
- `GET /api/recommendations` - Security recommendations

## 📊 Testing the API

### Test threat detection:
```bash
curl -X POST http://localhost:5000/api/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "log_content": "192.168.1.1 - - [01/Jan/2025:12:00:00] \"GET /admin OR 1=1-- HTTP/1.1\" 200 1234",
    "analysis_type": "all"
  }'
```

### Test file upload:
```bash
curl -X POST http://localhost:5000/api/upload \
  -F "file=@sample.log"
```

### Get threat intelligence:
```bash
curl http://localhost:5000/api/threat-intelligence
```

## 🗂️ Project Structure

```
cybershield-ai-platform/
├── backend/
│   ├── app.py                 # Main Flask application
│   ├── models/
│   │   ├── __init__.py
│   │   ├── threat_detector.py  # ML threat detection model
│   │   └── anomaly_detector.py # Anomaly detection model
│   ├── api/
│   │   ├── __init__.py
│   │   └── routes.py           # API route definitions
│   └── utils/
│       ├── __init__.py
│       └── log_parser.py       # Log parsing utilities
├── data/
│   ├── sample_logs/           # Sample log files
│   └── trained_models/        # Saved ML models
├── requirements.txt           # Python dependencies
├── .env                       # Environment variables
└── README.md                  # This file
```

## 🧠 Machine Learning Models

### Threat Detector
- Uses Isolation Forest for anomaly detection
- Rule-based pattern matching for known threats
- Detects: SQL injection, XSS, command injection, brute force, DDoS, malware

### Anomaly Detector
- Statistical anomaly detection using Isolation Forest
- Behavioral analysis for user activity patterns
- Temporal anomaly detection for off-hours activity
- Network anomaly detection for flooding and port scanning

## 🔧 Configuration

### IntelliJ IDEA Setup

1. Open Project Structure (`Ctrl+Alt+Shift+S`)
2. Set Project SDK to your Python 3.12 interpreter
3. Configure Python Interpreter:
   - File → Settings → Project → Python Interpreter
   - Select `.venv/bin/python` from your project

## 🐛 Troubleshooting

### Import errors in IntelliJ:
1. Invalidate caches: File → Invalidate Caches → Invalidate and Restart
2. Ensure the correct Python interpreter is selected
3. Check that all packages are installed in the virtual environment

### Module not found errors:
```bash
# Verify packages are installed
pip list

# Reinstall if needed
pip install -r requirements.txt
```

### Port already in use:
```bash
# Find and kill the process using port 5000
lsof -i :5000
kill -9 <PID>
```

## 🔒 Security Considerations

- Change the `SECRET_KEY` in production
- Use HTTPS in production
- Implement proper authentication and authorization
- Regularly update dependencies
- Review and customize threat detection patterns
- Enable rate limiting for API endpoints

## 📝 Sample Log Formats

The platform supports various log formats:

### Apache Combined Log:
```
192.168.1.1 - - [01/Jan/2025:12:00:00 +0000] "GET /index.html HTTP/1.1" 200 1234 "http://example.com" "Mozilla/5.0"
```

### JSON Log:
```json
{
  "timestamp": "2025-01-01T12:00:00",
  "level": "ERROR",
  "message": "Failed login attempt",
  "ip": "192.168.1.1"
}
```

### Syslog:
```
Jan 1 12:00:00 server sshd[1234]: Failed password for root from 192.168.1.1
```

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Commit your changes
4. Push to the branch
5. Create a Pull Request

## 📄 License

This project is licensed under the MIT License.

## 🆘 Support

For issues or questions, please create an issue in the GitHub repository.

---

**Note**: This is a demonstration platform. For production use, implement proper security measures, authentication, and thoroughly test all components.