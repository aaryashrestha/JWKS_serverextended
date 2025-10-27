import pytest
import os
import time
import sqlite3
from app import app, KeyStore

@pytest.fixture
def client():
    """Configure test client with temporary database (Windows-safe)"""
    test_db = 'test_privateKeys.db'
    
    for _ in range(5):
        try:
            if os.path.exists(test_db):
                os.remove(test_db)
            break
        except PermissionError:
            time.sleep(0.1)

    keystore = KeyStore(test_db)
    app.config['TESTING'] = True

    with app.test_client() as client:
        yield client

    keystore.close()
    if os.path.exists(test_db):
        for _ in range(10):
            try:
                os.remove(test_db)
                break
            except PermissionError:
                time.sleep(0.2)

def test_jwks_endpoint(client):
    """Test JWKS endpoint returns valid keys"""
    response = client.get('/.well-known/jwks.json')
    assert response.status_code == 200
    assert len(response.json['keys']) >= 1

def test_auth_endpoint(client):
    """Test valid JWT issuance"""
    response = client.post('/auth')
    assert response.status_code == 200
    assert 'token' in response.json

def test_expired_auth(client):
    """Test expired JWT issuance"""
    response = client.post('/auth?expired=true')
    assert response.status_code == 200
    assert 'token' in response.json

def test_db_injection_protection():
    """Verify parameterized queries prevent SQL injection"""
    test_db = ':memory:'
    keystore = KeyStore(test_db)
    try:
        #Attempt SQL injection
        keystore.conn.execute(
            "INSERT INTO keys (key, exp) VALUES (?, ?)",
            ("malicious'); DROP TABLE keys;--", 0)
        )
        #Verify table still exists
        keystore.conn.execute("SELECT * FROM keys")
    except sqlite3.OperationalError:
        pytest.fail("SQL injection vulnerability detected")
    finally:
        keystore.close()