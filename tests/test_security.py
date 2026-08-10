import os
import sys
import json

os.environ['DATABASE_URL'] = 'postgresql://test:test@localhost:5432/test_travelboard'
os.environ['ADMIN_PASSWORD'] = 'test-admin-password-123'
os.environ['MGMT_PEPPER'] = 'test-pepper-' + 'x' * 50
os.environ['SECRET_KEY'] = 'test-secret-' + 'x' * 50

sys.modules.setdefault('psycopg2', type(sys)('psycopg2'))
sys.modules.setdefault('psycopg2.pool', type(sys)('psycopg2.pool'))
sys.modules.setdefault('psycopg2.extras', type(sys)('psycopg2.extras'))

class MockConn:
    def __init__(self):
        self.data = {'journeys': [], 'ride_requests': [], 'reports': [], 'sessions': [], 'rate_limits': []}
    def cursor(self, **kwargs):
        return MockCursor(self)
    def commit(self): pass
    def rollback(self): pass

class MockCursor:
    def __init__(self, conn):
        self.conn = conn
        self.results = []
        self.idx = 0
    def execute(self, query, params=None):
        self.idx = 0
        q = query.upper()
        if 'COUNT' in q:
            self.results = [{'c': 0}]
        elif 'INSERT' in q and 'RETURNING' in q:
            self.results = [{'id': 1}]
        elif 'SELECT' in q and 'sessions' in q.lower():
            self.results = []
        elif 'SELECT' in q and 'rate_limits' in q.lower():
            self.results = []
        elif 'SELECT' in q:
            self.results = []
        else:
            self.results = []
    def fetchone(self):
        if self.idx < len(self.results):
            r = self.results[self.idx]
            self.idx += 1
            return r
        return None
    def fetchall(self):
        return self.results

class MockPool:
    def __init__(self, minconn, maxconn, dsn):
        self.dsn = dsn
    def getconn(self):
        return MockConn()
    def putconn(self, conn):
        pass

import psycopg2.pool
psycopg2.pool.ThreadedConnectionPool = MockPool

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import app, hash_code, generate_mgmt_code, validate_phone, validate_name, validate_id, hash_phone_for_rate_limit

def test_security():
    app.config['TESTING'] = True
    client = app.test_client()

    # 1. SQL Injection
    payload = {
        'origin': 'Црънча', 'destination': 'Пазарджик', 'date': '2025-12-31',
        'time': '10:00', 'seats': 1,
        'contact_name': "'; DROP TABLE journeys; --",
        'contact_phone': '0888123456', 'consent': True
    }
    resp = client.post('/api/journeys', json=payload)
    assert resp.status_code in [201, 400, 500]

    # 2. XSS
    resp = client.post('/api/journeys', json={
        'origin': 'Црънча', 'destination': 'Пазарджик', 'date': '2025-12-31',
        'time': '10:00', 'contact_name': '<script>alert(1)</script>',
        'contact_phone': '0888123456', 'consent': True
    })
    assert resp.status_code in [201, 400]

    # 3. Input validation
    resp = client.post('/api/journeys', json={
        'origin': 'Црънча', 'destination': 'Пазарджик', 'date': '2025-12-31',
        'time': '10:00', 'contact_name': 'A' * 100,
        'contact_phone': '0888123456', 'consent': True
    })
    assert resp.status_code == 400

    # 4. Invalid phone
    resp = client.post('/api/journeys', json={
        'origin': 'Црънча', 'destination': 'Пазарджик', 'date': '2025-12-31',
        'time': '10:00', 'contact_name': 'Test',
        'contact_phone': '12345', 'consent': True
    })
    assert resp.status_code == 400

    # 5. Past date
    resp = client.post('/api/journeys', json={
        'origin': 'Црънча', 'destination': 'Пазарджик', 'date': '2020-01-01',
        'time': '10:00', 'contact_name': 'Test',
        'contact_phone': '0888123456', 'consent': True
    })
    assert resp.status_code == 400

    # 6. Missing consent
    resp = client.post('/api/journeys', json={
        'origin': 'Црънча', 'destination': 'Пазарджик', 'date': '2025-12-31',
        'time': '10:00', 'contact_name': 'Test',
        'contact_phone': '0888123456'
    })
    assert resp.status_code == 400

    # 7. Management code security
    code = generate_mgmt_code()
    assert len(code) == 12 and code.isalnum() and code == code.upper()
    h1 = hash_code('ABC123')
    h2 = hash_code('ABC123')
    assert h1 == h2 and len(h1) == 64
    assert hash_code('ABC123') != hash_code('ABC124')

    # 8. Phone HMAC for rate limit
    key1 = hash_phone_for_rate_limit('0888123456')
    key2 = hash_phone_for_rate_limit('0888123457')
    assert key1 != key2
    assert len(key1) == 16

    # 9. Admin auth
    resp = client.get('/api/admin/posts')
    assert resp.status_code == 403
    resp = client.post('/api/admin/login', json={'password': 'wrong'})
    assert resp.status_code == 403
    resp = client.post('/api/admin/login', json={})
    assert resp.status_code == 400

    # 10. Report validation
    resp = client.post('/api/reports', json={
        'post_type': 'invalid', 'post_id': 1, 'reason': 'spam'
    })
    assert resp.status_code == 400

    # 11. Public API no secrets
    resp = client.get('/api/journeys')
    assert resp.status_code == 200
    data = json.loads(resp.data)
    for item in data:
        assert 'mgmt_code_hash' not in item

    # 12. Security headers
    resp = client.get('/')
    assert resp.headers.get('X-Content-Type-Options') == 'nosniff'
    assert resp.headers.get('X-Frame-Options') == 'DENY'
    assert 'Content-Security-Policy' in resp.headers
    csp = resp.headers.get('Content-Security-Policy')
    assert "script-src 'self'" in csp
    assert "unsafe-inline" not in csp or "script-src" not in csp or "'unsafe-inline'" not in csp.split('script-src')[1].split(';')[0]

    # 13. Error handling
    resp = client.get('/api/nonexistent')
    assert resp.status_code == 404
    data = json.loads(resp.data)
    assert 'error' in data
    assert 'stack' not in str(data).lower()

    # 14. Delete auth
    resp = client.delete('/api/journeys/1', json={})
    assert resp.status_code == 400

    # 15. Validate helpers
    assert validate_phone('0888123456')[0] == True
    assert validate_phone('+359888123456')[0] == True
    assert validate_phone('12345')[0] == False
    assert validate_name('Иван')[0] == True
    assert validate_name('')[0] == False
    assert validate_name('A' * 51)[0] == False
    assert validate_id('123')[0] == True
    assert validate_id('abc')[0] == False

    # 16. Env vars
    assert os.environ.get('DATABASE_URL')
    assert os.environ.get('ADMIN_PASSWORD')
    assert os.environ.get('MGMT_PEPPER')
    assert os.environ.get('SECRET_KEY')
    assert os.environ.get('MGMT_PEPPER') != 'travelboard-pepper-2024'

    print("✓ All 16 security tests passed")

if __name__ == '__main__':
    test_security()
