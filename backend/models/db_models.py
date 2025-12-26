from datetime import datetime
from extensions import db

class User(db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)

class LogEntry(db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    log_content = db.Column(db.Text, nullable=False)
    source_ip = db.Column(db.String(50))
    severity = db.Column(db.String(20))
    parsed_data = db.Column(db.JSON)

class Alert(db.Model):
    __table_args__ = {'extend_existing': True}
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    type = db.Column(db.String(50), nullable=False)
    severity = db.Column(db.String(20), nullable=False)
    message = db.Column(db.String(200), nullable=False)
    details = db.Column(db.JSON)
    status = db.Column(db.String(20), default='new')  # new, investigating, resolved
    source_ip = db.Column(db.String(50))
