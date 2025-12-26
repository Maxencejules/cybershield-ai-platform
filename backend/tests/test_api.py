import os
import sys

# Ensure backend directory is in path
sys.path.append(os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

import pytest
import json
from backend.app import app, db
from backend.models.db_models import User, Alert

@pytest.fixture(scope='module')
def test_client():
    # Setup
    app.config['TESTING'] = True
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
    app.config['JWT_SECRET_KEY'] = 'test-secret'

    with app.test_client() as testing_client:
        with app.app_context():
            db.create_all()
            yield testing_client
            db.session.remove()
            db.drop_all()

def test_health_check(test_client):
    rv = test_client.get('/health')
    assert rv.status_code == 200

def test_auth_flow(test_client):
    # Register
    rv = test_client.post('/api/auth/register', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert rv.status_code == 201

    # Login
    rv = test_client.post('/api/auth/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert 'access_token' in data

    # Return token for next tests if needed, but pytest fixtures are better
    # For simplicity, we just assert here

def test_analyze(test_client):
    log_data = {
        "log_content": "192.168.1.1 - - [01/Jan/2025:12:00:00] \"GET /admin OR 1=1-- HTTP/1.1\" 200 1234",
        "analysis_type": "all"
    }

    rv = test_client.post('/api/analyze', json=log_data)
    assert rv.status_code == 200
    data = json.loads(rv.data)
    assert data['success'] is True
    assert len(data['results']['threats']['threats']) > 0

def test_dashboard_protected(test_client):
    # 1. Try without token
    rv = test_client.get('/api/dashboard')
    assert rv.status_code == 401 # Unauthorized

    # 2. Get token
    rv_login = test_client.post('/api/auth/login', json={
        'username': 'testuser',
        'password': 'testpassword'
    })
    token = json.loads(rv_login.data)['access_token']

    # 3. Try with token
    rv_auth = test_client.get('/api/dashboard', headers={
        'Authorization': f'Bearer {token}'
    })
    assert rv_auth.status_code == 200
    assert 'overview' in json.loads(rv_auth.data)['data']
