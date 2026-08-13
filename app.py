import os
import re
import hashlib
import hmac
import secrets
import string
import json
import logging
from datetime import datetime, timedelta, date, timezone
from functools import wraps

from flask import Flask, request, jsonify, send_from_directory, render_template, redirect
from werkzeug.middleware.proxy_fix import ProxyFix

from database import get_db, put_db, init_db, db_cursor

app = Flask(__name__, static_folder='static', template_folder='templates')
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

# ========== CONFIGURATION VALIDATION ==========
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required.")

ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD")
if not ADMIN_PASSWORD:
    raise ValueError("ADMIN_PASSWORD environment variable is required.")

MGMT_PEPPER = os.environ.get("MGMT_PEPPER")
if not MGMT_PEPPER:
    raise ValueError(
        "MGMT_PEPPER environment variable is required. "
        "Generate a strong random value (e.g., openssl rand -hex 32) and set it in Render."
    )

SECRET_KEY = os.environ.get("SECRET_KEY")
if not SECRET_KEY:
    raise ValueError(
        "SECRET_KEY environment variable is required for secure admin sessions. "
        "Generate a strong random value (e.g., openssl rand -hex 32) and set it in Render."
    )

CITIES = ["Црънча", "Пазарджик", "Паталеница", "Дебращица"]
REPORT_REASONS = {
    'fake': 'Фалшива обява',
    'wrong_phone': 'Грешен/чужд телефон',
    'spam': 'Спам',
    'inappropriate': 'Неподходящо съдържание'
}

app.config['MAX_CONTENT_LENGTH'] = 1024 * 1024  # 1MB max request size

# ========== LOGGING ==========
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s %(levelname)s %(name)s: %(message)s'
)
logger = logging.getLogger('travelboard')

# ========== SECURITY HEADERS ==========
@app.after_request
def add_security_headers(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self'; "
        "script-src 'self' 'unsafe-inline'; "
        "style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; "
        "font-src 'self'; "
        "connect-src 'self'; "
        "frame-ancestors 'none'; "
        "base-uri 'self'; "
        "form-action 'self'; "
        "upgrade-insecure-requests"
    )
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = (
        'accelerometer=(), camera=(), geolocation=(), gyroscope=(), '
        'magnetometer=(), microphone=(), payment=(), usb=()'
    )
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'
    response.headers['X-Robots-Tag'] = 'noindex, nofollow'
    if request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https':
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
    if request.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
        response.headers['Pragma'] = 'no-cache'
    return response

# ========== HTTPS REDIRECT ==========
@app.before_request
def force_https():
    if request.headers.get('X-Forwarded-Proto') == 'http':
        return redirect(request.url.replace('http://', 'https://', 1), code=301)

# ========== RATE LIMITING (PostgreSQL-backed, atomic) ==========
def check_rate_limit(key, max_req=5, window=3600):
    """Atomic rate limiting using PostgreSQL UPSERT."""
    now = datetime.utcnow()
    window_start = now - timedelta(seconds=window)
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("""
            INSERT INTO rate_limits (key, count, window_start)
            VALUES (%s, 1, %s)
            ON CONFLICT (key) DO UPDATE SET
                count = CASE
                    WHEN rate_limits.window_start < %s THEN 1
                    ELSE rate_limits.count + 1
                END,
                window_start = CASE
                    WHEN rate_limits.window_start < %s THEN %s
                    ELSE rate_limits.window_start
                END
            RETURNING count, window_start
        """, (key, now, window_start, window_start, now))
        row = c.fetchone()
        conn.commit()
        count = row[0]
        if count > max_req:
            logger.info("Rate limit hit for key: %s", key[:30])
            return False
        return True
    except Exception as e:
        logger.error("Rate limit error: %s", e)
        conn.rollback()
        if 'admin' in key or 'delete' in key or 'manage' in key:
            return False
        return True
    finally:
        put_db(conn)

def get_client_ip():
    return request.remote_addr or 'unknown'

def hash_phone_for_rate_limit(phone):
    """HMAC phone number so raw phone is not used as rate-limit key."""
    return hmac.new(SECRET_KEY.encode(), phone.encode(), hashlib.sha256).hexdigest()[:16]

# ========== CLOUDFLARE TURNSTILE (optional bot protection) ==========
TURNSTILE_SECRET_KEY = os.environ.get("TURNSTILE_SECRET_KEY")
TURNSTILE_VERIFY_URL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"


def verify_turnstile(token):
    """Verify Cloudflare Turnstile token. Fail-open if not configured or on error."""
    if not TURNSTILE_SECRET_KEY:
        return True
    if not token:
        return True
    try:
        import urllib.request
        import urllib.parse
        data = urllib.parse.urlencode({
            'secret': TURNSTILE_SECRET_KEY,
            'response': token
        }).encode()
        req = urllib.request.Request(TURNSTILE_VERIFY_URL, data=data, method='POST')
        with urllib.request.urlopen(req, timeout=5) as resp:
            result = json.loads(resp.read())
            if not result.get('success'):
                logger.warning("Turnstile verification failed: %s", result.get('error-codes'))
            return result.get('success', False)
    except Exception as e:
        logger.error("Turnstile verification error: %s", e)
        return True

# ========== SESSION MANAGEMENT (Server-side, PostgreSQL-backed) ==========
def create_session(data, expires_hours=2):
    session_id = secrets.token_urlsafe(32)
    expires_at = datetime.utcnow() + timedelta(hours=expires_hours)
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute(
            "INSERT INTO sessions (id, data, expires_at) VALUES (%s, %s, %s)",
            (session_id, json.dumps(data), expires_at)
        )
        conn.commit()
        logger.info("Admin session created: %s...", session_id[:8])
        return session_id
    except Exception as e:
        logger.error("Session creation error: %s", e)
        conn.rollback()
        return None
    finally:
        put_db(conn)

def get_session(session_id):
    if not session_id or len(session_id) > 64:
        return None
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("SELECT data, expires_at FROM sessions WHERE id = %s", (session_id,))
        row = c.fetchone()
        if not row:
            return None
        data_raw, expires_at = row[0], row[1]
        now = datetime.utcnow()
        if expires_at.tzinfo is not None:
            now = datetime.now(expires_at.tzinfo)
        if expires_at < now:
            c.execute("DELETE FROM sessions WHERE id = %s", (session_id,))
            conn.commit()
            return None
        if isinstance(data_raw, str):
            return json.loads(data_raw)
        if isinstance(data_raw, dict):
            return data_raw
        return None
    except Exception as e:
        logger.error("Session read error: %s", e)
        return None
    finally:
        put_db(conn)

def delete_session(session_id):
    if not session_id:
        return
    conn = get_db()
    try:
        c = conn.cursor()
        c.execute("DELETE FROM sessions WHERE id = %s", (session_id,))
        conn.commit()
    except Exception as e:
        logger.error("Session delete error: %s", e)
        conn.rollback()
    finally:
        put_db(conn)

def rotate_session(session_id):
    """Rotate session ID after login to prevent session fixation."""
    session_data = get_session(session_id)
    if not session_data:
        return None
    delete_session(session_id)
    return create_session(session_data, expires_hours=2)

def admin_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        session_id = request.cookies.get('admin_session')
        session_data = get_session(session_id)
        if not session_data or not session_data.get('is_admin'):
            return jsonify({'error': 'Forbidden'}), 403
        current_ip = get_client_ip()
        stored_ip = session_data.get('ip')
        if stored_ip and stored_ip != current_ip:
            logger.warning("Admin session IP mismatch: stored=%s current=%s", stored_ip, current_ip)
        return f(*args, **kwargs)
    return decorated

# ========== HELPERS ==========
def hash_code(code):
    return hashlib.sha256((code + MGMT_PEPPER).encode('utf-8')).hexdigest()

def generate_mgmt_code(length=12):
    alphabet = string.ascii_uppercase + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))

def sanitize(text, max_len=200):
    if not text:
        return ''
    text = str(text).strip()
    if len(text) > max_len:
        text = text[:max_len]
    text = re.sub(r'<[^>]+>', '', text)
    return text

def validate_phone(phone):
    clean = phone.replace(' ', '').replace('-', '')
    if re.match(r'^0[8-9]\d{8}$', clean):
        return True, clean
    if re.match(r'^\+359[8-9]\d{8}$', clean):
        return True, clean
    return False, phone

def validate_date_str(date_str):
    if not date_str or len(date_str) > 20:
        return False, 'Невалидна дата'
    try:
        d = datetime.strptime(date_str, '%Y-%m-%d').date()
        if d < date.today():
            return False, 'Датата не може да е в миналото'
        return True, d
    except ValueError:
        return False, 'Невалидна дата'

def validate_time_str(time_str):
    if not time_str or len(time_str) > 10:
        return False, 'Невалиден час'
    try:
        datetime.strptime(time_str, '%H:%M')
        return True, time_str
    except ValueError:
        return False, 'Невалиден час'

def validate_datetime(date_str, time_str):
    valid, d = validate_date_str(date_str)
    if not valid:
        return False, d
    valid, t = validate_time_str(time_str)
    if not valid:
        return False, t
    now = datetime.now(timezone.utc)
    today_utc = now.date()
    if d == today_utc:
        post_dt = datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")
        post_dt = post_dt.replace(tzinfo=timezone.utc)
        if post_dt < now:
            return False, 'Часът не може да е в миналото'
    return True, None

def validate_name(name):
    if not name or len(name.strip()) < 2:
        return False, 'Името трябва да е поне 2 символа'
    if len(name.strip()) > 50:
        return False, 'Името е твърде дълго'
    return True, name.strip()

def check_recent_duplicate(c, table, origin, destination, date_str, time_str, phone, window_minutes=10):
    """Check if an identical post was created very recently."""
    if table not in ('journeys', 'ride_requests'):
        return False
    since = datetime.utcnow() - timedelta(minutes=window_minutes)
    c.execute(f"""
        SELECT id FROM {table}
        WHERE origin = %s AND destination = %s AND date = %s AND time = %s
        AND contact_phone = %s AND created_at > %s
        LIMIT 1
    """, (origin, destination, date_str, time_str, phone, since))
    return c.fetchone() is not None

def validate_id(val):
    try:
        return True, int(val)
    except (ValueError, TypeError):
        return False, None

# ========== CLEANUP ==========
last_cleanup = datetime.min.replace(tzinfo=timezone.utc)

def cleanup_old_posts():
    global last_cleanup
    now = datetime.now(timezone.utc)
    if now - last_cleanup < timedelta(hours=1):
        return
    last_cleanup = now
    try:
        conn = get_db()
        c = conn.cursor()
        today_str = now.date().strftime('%Y-%m-%d')
        c.execute("DELETE FROM journeys WHERE date < %s", (today_str,))
        c.execute("DELETE FROM ride_requests WHERE date < %s", (today_str,))
        c.execute("DELETE FROM sessions WHERE expires_at < %s", (now,))
        c.execute(
            "DELETE FROM rate_limits WHERE window_start < %s",
            (now - timedelta(hours=24),)
        )
        conn.commit()
        logger.info("Cleanup completed")
    except Exception as e:
        logger.error("Cleanup error: %s", e)
        try:
            conn.rollback()
        except Exception:
            pass
    finally:
        try:
            put_db(conn)
        except Exception:
            pass

@app.before_request
def maybe_cleanup():
    if request.path.startswith('/api/'):
        cleanup_old_posts()

# ========== JOURNEYS ==========
@app.route('/api/journeys', methods=['POST'])
def create_journey():
    data = request.get_json() or {}
    contact_phone = str(data.get('contact_phone', '')).strip()

    if not data.get('consent'):
        return jsonify({'error': 'Трябва да се съгласиш, че телефонът ти ще бъде публичен'}), 400

    ip = get_client_ip()
    if not check_rate_limit(f'post_ip:{ip}', max_req=15, window=3600):
        return jsonify({'error': 'Твърде много обяви от тази мрежа. Опитайте отново след час.'}), 429
    if contact_phone:
        phone_key = hash_phone_for_rate_limit(contact_phone)
        if not check_rate_limit(f'post_phone:{phone_key}', max_req=2, window=3600):
            return jsonify({'error': 'Твърде много обяви от този телефон. Опитайте отново след час.'}), 429

    origin = str(data.get('origin', '')).strip()
    destination = str(data.get('destination', '')).strip()
    date_str = str(data.get('date', '')).strip()
    time_str = str(data.get('time', '')).strip()
    seats = data.get('seats', 1)
    contact_name = sanitize(data.get('contact_name', ''), 50)

    if not origin or not destination or not date_str or not time_str or not contact_name or not contact_phone:
        return jsonify({'error': 'Всички полета са задължителни'}), 400
    if origin not in CITIES or destination not in CITIES:
        return jsonify({'error': 'Невалиден маршрут'}), 400
    if origin == destination:
        return jsonify({'error': 'Началото и краят не могат да са еднакви'}), 400
    if 'Пазарджик' not in (origin, destination):
        return jsonify({'error': 'Невалиден маршрут. Пътуванията трябва да включват Пазарджик.'}), 400

    valid, msg = validate_datetime(date_str, time_str)
    if not valid:
        return jsonify({'error': msg}), 400

    valid, msg = validate_name(contact_name)
    if not valid:
        return jsonify({'error': msg}), 400

    valid, phone = validate_phone(contact_phone)
    if not valid:
        return jsonify({'error': 'Невалиден телефонен номер. Използвай формат 0888123456 или +359888123456'}), 400

    try:
        seats = max(1, min(8, int(seats)))
    except (ValueError, TypeError):
        seats = 1

    # Optional bot protection (frontend can send turnstile_token when ready)
    turnstile_token = data.get('turnstile_token', '')
    if not verify_turnstile(turnstile_token):
        return jsonify({'error': 'Bot verification failed. Моля, опитайте отново.'}), 403

    mgmt_code = generate_mgmt_code()
    mgmt_hash = hash_code(mgmt_code)

    conn = get_db()
    c = db_cursor(conn)
    try:
        # Duplicate/spam protection
        if check_recent_duplicate(c, 'journeys', origin, destination, date_str, time_str, phone, window_minutes=10):
            return jsonify({'error': 'Вече има публикувана идентична обява от този телефон преди малко. Моля, изчакайте няколко минути или редактирайте съществуващата.'}), 429

        c.execute("""
            INSERT INTO journeys (origin, destination, date, time, seats, contact_name, contact_phone, mgmt_code_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (origin, destination, date_str, time_str, seats, contact_name, phone, mgmt_hash))
        row = c.fetchone()
        jid = row['id']
        conn.commit()
        return jsonify({
            'id': jid,
            'management_code': mgmt_code,
            'message': 'Пътуването е публикувано'
        }), 201
    except Exception as e:
        logger.error("Create journey error: %s", e)
        conn.rollback()
        return jsonify({'error': 'Грешка при публикуване'}), 500
    finally:
        put_db(conn)


@app.route('/api/journeys', methods=['GET'])
def get_journeys():
    origin = request.args.get('origin', '').strip()
    destination = request.args.get('destination', '').strip()
    date_q = request.args.get('date', '').strip()

    if origin and origin not in CITIES:
        return jsonify({'error': 'Невалиден филтър'}), 400
    if destination and destination not in CITIES:
        return jsonify({'error': 'Невалиден филтър'}), 400
    if date_q:
        valid, _ = validate_date_str(date_q)
        if not valid:
            return jsonify({'error': 'Невалидна дата'}), 400

    ip = get_client_ip()
    if not check_rate_limit(f'list_ip:{ip}', max_req=60, window=300):
        return jsonify({'error': 'Твърде много заявки. Опитайте отново след малко.'}), 429

    conn = get_db()
    c = db_cursor(conn)
    try:
        today_str = datetime.now(timezone.utc).date().strftime('%Y-%m-%d')
        # Show all posts from today onwards (don't filter by time — user-friendly)
        query = """
            SELECT id, origin, destination, date, time, seats, contact_name, contact_phone
            FROM journeys
            WHERE status = 'active'
            AND date >= %s
        """
        params = [today_str]
        if origin:
            query += " AND origin = %s"
            params.append(origin)
        if destination:
            query += " AND destination = %s"
            params.append(destination)
        if date_q:
            query += " AND date = %s"
            params.append(date_q)
        query += " ORDER BY date, time LIMIT 200"
        c.execute(query, params)
        rows = c.fetchall()
        return jsonify([{
            'id': r['id'],
            'origin': r['origin'],
            'destination': r['destination'],
            'date': r['date'],
            'time': r['time'],
            'seats': r['seats'],
            'contact_name': r['contact_name'],
            'contact_phone': r['contact_phone']
        } for r in rows])
    except Exception as e:
        logger.error("Get journeys error: %s", e)
        return jsonify({'error': 'Грешка при зареждане'}), 500
    finally:
        put_db(conn)


@app.route('/api/journeys/<int:jid>', methods=['DELETE'])
def delete_journey(jid):
    data = request.get_json() or {}
    code = str(data.get('delete_code', '')).strip().upper()
    if not code:
        return jsonify({'error': 'Нужен е код за изтриване'}), 400

    ip = get_client_ip()
    if not check_rate_limit(f'delete_ip:{ip}', max_req=10, window=3600):
        return jsonify({'error': 'Твърде много опити за изтриване. Опитайте отново след час.'}), 429

    mgmt_hash = hash_code(code)
    conn = get_db()
    c = db_cursor(conn)
    try:
        c.execute(
            "SELECT mgmt_code_hash FROM journeys WHERE id = %s AND status = 'active'",
            (jid,)
        )
        row = c.fetchone()
        if not row:
            return jsonify({'error': 'Не е намерено'}), 404
        if row['mgmt_code_hash'] != mgmt_hash:
            return jsonify({'error': 'Грешен код'}), 403
        c.execute("DELETE FROM journeys WHERE id = %s", (jid,))
        conn.commit()
        return jsonify({'message': 'Пътуването е премахнато'})
    except Exception as e:
        logger.error("Delete journey error: %s", e)
        conn.rollback()
        return jsonify({'error': 'Грешка при изтриване'}), 500
    finally:
        put_db(conn)


# ========== RIDE REQUESTS ==========

@app.route('/api/ride-requests', methods=['POST'])
def create_request():
    data = request.get_json() or {}
    contact_phone = str(data.get('contact_phone', '')).strip()

    if not data.get('consent'):
        return jsonify({'error': 'Трябва да се съгласиш, че телефонът ти ще бъде публичен'}), 400

    ip = get_client_ip()
    if not check_rate_limit(f'post_ip:{ip}', max_req=15, window=3600):
        return jsonify({'error': 'Твърде много заявки от тази мрежа. Опитайте отново след час.'}), 429
    if contact_phone:
        phone_key = hash_phone_for_rate_limit(contact_phone)
        if not check_rate_limit(f'post_phone:{phone_key}', max_req=2, window=3600):
            return jsonify({'error': 'Твърде много заявки от този телефон. Опитайте отново след час.'}), 429

    origin = str(data.get('origin', '')).strip()
    destination = str(data.get('destination', '')).strip()
    date_str = str(data.get('date', '')).strip()
    time_str = str(data.get('time', '')).strip()
    people = data.get('people', 1)
    contact_name = sanitize(data.get('contact_name', ''), 50)

    if not origin or not destination or not date_str or not time_str or not contact_name or not contact_phone:
        return jsonify({'error': 'Всички полета са задължителни'}), 400
    if origin not in CITIES or destination not in CITIES:
        return jsonify({'error': 'Невалиден маршрут'}), 400
    if origin == destination:
        return jsonify({'error': 'Началото и краят не могат да са еднакви'}), 400
    if 'Пазарджик' not in (origin, destination):
        return jsonify({'error': 'Невалиден маршрут. Пътуванията трябва да включват Пазарджик.'}), 400

    valid, msg = validate_datetime(date_str, time_str)
    if not valid:
        return jsonify({'error': msg}), 400

    valid, msg = validate_name(contact_name)
    if not valid:
        return jsonify({'error': msg}), 400

    valid, phone = validate_phone(contact_phone)
    if not valid:
        return jsonify({'error': 'Невалиден телефонен номер. Използвай формат 0888123456 или +359888123456'}), 400

    try:
        people = max(1, min(8, int(people)))
    except (ValueError, TypeError):
        people = 1

    # Optional bot protection (frontend can send turnstile_token when ready)
    turnstile_token = data.get('turnstile_token', '')
    if not verify_turnstile(turnstile_token):
        return jsonify({'error': 'Bot verification failed. Моля, опитайте отново.'}), 403

    mgmt_code = generate_mgmt_code()
    mgmt_hash = hash_code(mgmt_code)

    conn = get_db()
    c = db_cursor(conn)
    try:
        # Duplicate/spam protection
        if check_recent_duplicate(c, 'ride_requests', origin, destination, date_str, time_str, phone, window_minutes=10):
            return jsonify({'error': 'Вече има публикувана идентична заявка от този телефон преди малко. Моля, изчакайте няколко минути или редактирайте съществуващата.'}), 429

        c.execute("""
            INSERT INTO ride_requests (origin, destination, date, time, people, contact_name, contact_phone, mgmt_code_hash)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
            RETURNING id
        """, (origin, destination, date_str, time_str, people, contact_name, phone, mgmt_hash))
        row = c.fetchone()
        rid = row['id']
        conn.commit()
        return jsonify({
            'id': rid,
            'management_code': mgmt_code,
            'message': 'Заявката е публикувана'
        }), 201
    except Exception as e:
        logger.error("Create request error: %s", e)
        conn.rollback()
        return jsonify({'error': 'Грешка при публикуване'}), 500
    finally:
        put_db(conn)


@app.route('/api/ride-requests', methods=['GET'])
def get_requests():
    origin = request.args.get('origin', '').strip()
    destination = request.args.get('destination', '').strip()
    date_q = request.args.get('date', '').strip()

    if origin and origin not in CITIES:
        return jsonify({'error': 'Невалиден филтър'}), 400
    if destination and destination not in CITIES:
        return jsonify({'error': 'Невалиден филтър'}), 400
    if date_q:
        valid, _ = validate_date_str(date_q)
        if not valid:
            return jsonify({'error': 'Невалидна дата'}), 400

    ip = get_client_ip()
    if not check_rate_limit(f'list_ip:{ip}', max_req=60, window=300):
        return jsonify({'error': 'Твърде много заявки. Опитайте отново след малко.'}), 429

    conn = get_db()
    c = db_cursor(conn)
    try:
        today_str = datetime.now(timezone.utc).date().strftime('%Y-%m-%d')
        query = """
            SELECT id, origin, destination, date, time, people, contact_name, contact_phone
            FROM ride_requests
            WHERE date >= %s
        """
        params = [today_str]
        if origin:
            query += " AND origin = %s"
            params.append(origin)
        if destination:
            query += " AND destination = %s"
            params.append(destination)
        if date_q:
            query += " AND date = %s"
            params.append(date_q)
        query += " ORDER BY date, time LIMIT 200"
        c.execute(query, params)
        rows = c.fetchall()
        return jsonify([{
            'id': r['id'],
            'origin': r['origin'],
            'destination': r['destination'],
            'date': r['date'],
            'time': r['time'],
            'people': r['people'],
            'contact_name': r['contact_name'],
            'contact_phone': r['contact_phone']
        } for r in rows])
    except Exception as e:
        logger.error("Get requests error: %s", e)
        return jsonify({'error': 'Грешка при зареждане'}), 500
    finally:
        put_db(conn)


@app.route('/api/ride-requests/<int:rid>', methods=['DELETE'])
def delete_request(rid):
    data = request.get_json() or {}
    code = str(data.get('delete_code', '')).strip().upper()
    if not code:
        return jsonify({'error': 'Нужен е код за изтриване'}), 400

    ip = get_client_ip()
    if not check_rate_limit(f'delete_ip:{ip}', max_req=10, window=3600):
        return jsonify({'error': 'Твърде много опити за изтриване. Опитайте отново след час.'}), 429

    mgmt_hash = hash_code(code)
    conn = get_db()
    c = db_cursor(conn)
    try:
        c.execute("SELECT mgmt_code_hash FROM ride_requests WHERE id = %s", (rid,))
        row = c.fetchone()
        if not row:
            return jsonify({'error': 'Не е намерено'}), 404
        if row['mgmt_code_hash'] != mgmt_hash:
            return jsonify({'error': 'Грешен код'}), 403
        c.execute("DELETE FROM ride_requests WHERE id = %s", (rid,))
        conn.commit()
        return jsonify({'message': 'Заявката е премахната'})
    except Exception as e:
        logger.error("Delete request error: %s", e)
        conn.rollback()
        return jsonify({'error': 'Грешка при изтриване'}), 500
    finally:
        put_db(conn)


# ========== MANAGEMENT (МОИТЕ ОБЯВИ) ==========

@app.route('/api/manage', methods=['POST'])
def manage_post():
    ip = get_client_ip()
    if not check_rate_limit(f'manage:{ip}', max_req=10, window=60):
        return jsonify({'error': 'Твърде много опити. Опитайте отново след малко.'}), 429

    data = request.get_json() or {}
    code = str(data.get('code', '')).strip().upper()
    if not code:
        return jsonify({'error': 'Въведи код за управление'}), 400

    mgmt_hash = hash_code(code)
    today_str = datetime.now(timezone.utc).date().strftime('%Y-%m-%d')

    conn = get_db()
    c = db_cursor(conn)
    try:
        c.execute("""
            SELECT id, origin, destination, date, time, seats, contact_name, contact_phone
            FROM journeys
            WHERE mgmt_code_hash = %s AND status = 'active'
            AND date >= %s
        """, (mgmt_hash, today_str))
        row = c.fetchone()
        if row:
            return jsonify({
                'found': True,
                'type': 'journey',
                'post': {
                    'id': row['id'],
                    'origin': row['origin'],
                    'destination': row['destination'],
                    'date': row['date'],
                    'time': row['time'],
                    'seats': row['seats'],
                    'contact_name': row['contact_name'],
                    'contact_phone': row['contact_phone']
                }
            })

        c.execute("""
            SELECT id, origin, destination, date, time, people, contact_name, contact_phone
            FROM ride_requests
            WHERE mgmt_code_hash = %s
            AND date >= %s
        """, (mgmt_hash, today_str))
        row = c.fetchone()
        if row:
            return jsonify({
                'found': True,
                'type': 'request',
                'post': {
                    'id': row['id'],
                    'origin': row['origin'],
                    'destination': row['destination'],
                    'date': row['date'],
                    'time': row['time'],
                    'people': row['people'],
                    'contact_name': row['contact_name'],
                    'contact_phone': row['contact_phone']
                }
            })

        return jsonify({'found': False, 'error': 'Невалиден код'}), 404
    except Exception as e:
        logger.error("Manage lookup error: %s", e)
        return jsonify({'error': 'Грешка при търсене'}), 500
    finally:
        put_db(conn)


@app.route('/api/manage/delete', methods=['POST'])
def manage_delete():
    ip = get_client_ip()
    if not check_rate_limit(f'manage:{ip}', max_req=10, window=60):
        return jsonify({'error': 'Твърде много опити. Опитайте отново след малко.'}), 429

    data = request.get_json() or {}
    code = str(data.get('code', '')).strip().upper()
    post_type = str(data.get('type', '')).strip()
    post_id = data.get('id')

    valid, post_id = validate_id(post_id)
    if not valid:
        return jsonify({'error': 'Невалиден ID'}), 400

    if not code or post_type not in ('journey', 'request'):
        return jsonify({'error': 'Невалидни данни'}), 400

    mgmt_hash = hash_code(code)

    conn = get_db()
    c = db_cursor(conn)
    try:
        if post_type == 'journey':
            c.execute(
                "SELECT mgmt_code_hash FROM journeys WHERE id = %s AND status = 'active'",
                (post_id,)
            )
        else:
            c.execute("SELECT mgmt_code_hash FROM ride_requests WHERE id = %s", (post_id,))

        row = c.fetchone()
        if not row:
            return jsonify({'error': 'Обявата не е намерена'}), 404
        if row['mgmt_code_hash'] != mgmt_hash:
            return jsonify({'error': 'Грешен код'}), 403

        if post_type == 'journey':
            c.execute("DELETE FROM journeys WHERE id = %s", (post_id,))
        else:
            c.execute("DELETE FROM ride_requests WHERE id = %s", (post_id,))

        conn.commit()
        return jsonify({'message': 'Обявата е изтрита'})
    except Exception as e:
        logger.error("Manage delete error: %s", e)
        conn.rollback()
        return jsonify({'error': 'Грешка при изтриване'}), 500
    finally:
        put_db(conn)


# ========== REPORTS ==========

@app.route('/api/reports', methods=['POST'])
def create_report():
    ip = get_client_ip()
    if not check_rate_limit(f'report:{ip}', max_req=3, window=3600):
        return jsonify({'error': 'Твърде много сигнали. Опитайте отново след час.'}), 429

    data = request.get_json() or {}
    post_type = str(data.get('post_type', '')).strip()
    post_id = data.get('post_id')
    reason = str(data.get('reason', '')).strip()

    if post_type not in ('journey', 'request'):
        return jsonify({'error': 'Невалиден тип обява'}), 400

    valid, post_id = validate_id(post_id)
    if not valid:
        return jsonify({'error': 'Невалиден ID'}), 400

    if reason not in REPORT_REASONS:
        return jsonify({'error': 'Невалидна причина'}), 400

    conn = get_db()
    c = db_cursor(conn)
    try:
        if post_type == 'journey':
            c.execute(
                "SELECT id FROM journeys WHERE id = %s AND status = 'active'",
                (post_id,)
            )
        else:
            c.execute("SELECT id FROM ride_requests WHERE id = %s", (post_id,))
        if not c.fetchone():
            return jsonify({'error': 'Обявата не съществува'}), 404

        c.execute("""
            SELECT id FROM reports
            WHERE post_type = %s AND post_id = %s AND reason = %s
            AND created_at > NOW() - INTERVAL '1 day'
        """, (post_type, post_id, reason))
        if c.fetchone():
            return jsonify({'message': 'Сигналът вече е изпратен'}), 200

        c.execute(
            "INSERT INTO reports (post_type, post_id, reason) VALUES (%s, %s, %s)",
            (post_type, post_id, reason)
        )
        conn.commit()
        return jsonify({'message': 'Сигналът е изпратен'}), 201
    except Exception as e:
        logger.error("Report error: %s", e)
        conn.rollback()
        return jsonify({'error': 'Грешка при обработка'}), 500
    finally:
        put_db(conn)


@app.route('/api/reports/reasons', methods=['GET'])
def get_report_reasons():
    return jsonify(REPORT_REASONS)


# ========== ADMIN ==========

@app.route('/api/admin/login', methods=['POST'])
def admin_login():
    ip = get_client_ip()
    if not check_rate_limit(f'admin_login:{ip}', max_req=5, window=900):
        return jsonify({'error': 'Твърде много опити. Опитайте отново след 15 минути.'}), 429

    data = request.get_json() or {}
    password = str(data.get('password', ''))

    if not password:
        return jsonify({'error': 'Нужна е парола'}), 400

    if not secrets.compare_digest(password, ADMIN_PASSWORD):
        logger.warning("Failed admin login attempt from %s", ip)
        return jsonify({'error': 'Невалидна парола'}), 403

    # Create session, then rotate to prevent session fixation
    temp_session = create_session({'is_admin': True, 'ip': ip}, expires_hours=2)
    if not temp_session:
        return jsonify({'error': 'Грешка при създаване на сесия'}), 500

    session_id = rotate_session(temp_session)
    if not session_id:
        return jsonify({'error': 'Грешка при ротация на сесия'}), 500

    is_https = request.is_secure or request.headers.get('X-Forwarded-Proto') == 'https'
    resp = jsonify({'success': True})
    resp.set_cookie(
        'admin_session',
        session_id,
        httponly=True,
        secure=is_https,
        samesite='Lax',
        path='/',
        max_age=7200
    )
    return resp


@app.route('/api/admin/logout', methods=['POST'])
@admin_required
def admin_logout():
    session_id = request.cookies.get('admin_session')
    delete_session(session_id)
    resp = jsonify({'success': True})
    resp.set_cookie('admin_session', '', expires=0, path='/')
    return resp


@app.route('/api/admin/posts', methods=['GET'])
@admin_required
def admin_posts():
    conn = get_db()
    c = db_cursor(conn)
    try:
        c.execute("""
            SELECT id, origin, destination, date, time, seats, contact_name, contact_phone
            FROM journeys WHERE status = 'active'
            ORDER BY date, time
            LIMIT 500
        """)
        journeys = [{
            'id': r['id'], 'type': 'journey',
            'origin': r['origin'], 'destination': r['destination'],
            'date': r['date'], 'time': r['time'], 'seats': r['seats'],
            'contact_name': r['contact_name'], 'contact_phone': r['contact_phone']
        } for r in c.fetchall()]

        c.execute("""
            SELECT id, origin, destination, date, time, people, contact_name, contact_phone
            FROM ride_requests
            ORDER BY date, time
            LIMIT 500
        """)
        requests = [{
            'id': r['id'], 'type': 'request',
            'origin': r['origin'], 'destination': r['destination'],
            'date': r['date'], 'time': r['time'], 'people': r['people'],
            'contact_name': r['contact_name'], 'contact_phone': r['contact_phone']
        } for r in c.fetchall()]

        c.execute("SELECT COUNT(*) as c FROM reports")
        report_count = c.fetchone()['c']

        return jsonify({'journeys': journeys, 'requests': requests, 'report_count': report_count})
    except Exception as e:
        logger.error("Admin posts error: %s", e)
        return jsonify({'error': 'Грешка при зареждане'}), 500
    finally:
        put_db(conn)


@app.route('/api/admin/delete', methods=['POST'])
@admin_required
def admin_delete():
    data = request.get_json() or {}
    post_type = str(data.get('type', '')).strip()
    post_id = data.get('id')

    valid, post_id = validate_id(post_id)
    if not valid:
        return jsonify({'error': 'Невалиден ID'}), 400

    if post_type not in ('journey', 'request'):
        return jsonify({'error': 'Невалиден тип'}), 400

    conn = get_db()
    c = db_cursor(conn)
    try:
        if post_type == 'journey':
            c.execute("DELETE FROM journeys WHERE id = %s", (post_id,))
        else:
            c.execute("DELETE FROM ride_requests WHERE id = %s", (post_id,))
        conn.commit()
        return jsonify({'message': 'Изтрито'})
    except Exception as e:
        logger.error("Admin delete error: %s", e)
        conn.rollback()
        return jsonify({'error': 'Грешка при изтриване'}), 500
    finally:
        put_db(conn)


@app.route('/api/admin/reports', methods=['GET'])
@admin_required
def admin_reports():
    conn = get_db()
    c = db_cursor(conn)
    try:
        c.execute("""
            SELECT r.id, r.post_type, r.post_id, r.reason, r.created_at,
                COALESCE(j.origin, req.origin) as origin,
                COALESCE(j.destination, req.destination) as destination,
                COALESCE(j.contact_name, req.contact_name) as contact_name
            FROM reports r
            LEFT JOIN journeys j ON r.post_type = 'journey' AND r.post_id = j.id
            LEFT JOIN ride_requests req ON r.post_type = 'request' AND r.post_id = req.id
            ORDER BY r.created_at DESC
            LIMIT 500
        """)
        rows = c.fetchall()
        return jsonify([{
            'id': r['id'],
            'post_type': r['post_type'],
            'post_id': r['post_id'],
            'reason': REPORT_REASONS.get(r['reason'], r['reason']),
            'origin': r['origin'] or '—',
            'destination': r['destination'] or '—',
            'contact_name': r['contact_name'] or '—',
            'created_at': r['created_at'].isoformat() if r['created_at'] else None
        } for r in rows])
    except Exception as e:
        logger.error("Admin reports error: %s", e)
        return jsonify({'error': 'Грешка при зареждане'}), 500
    finally:
        put_db(conn)


@app.route('/api/admin/cleanup', methods=['POST'])
@admin_required
def admin_cleanup():
    cleanup_old_posts()
    return jsonify({'message': 'Почистването е извършено'})


# ========== CITIES & STATS ==========

@app.route('/api/cities', methods=['GET'])
def get_cities():
    return jsonify(CITIES)


@app.route('/api/stats', methods=['GET'])
def stats():
    conn = get_db()
    c = db_cursor(conn)
    try:
        today_str = datetime.now(timezone.utc).date().strftime('%Y-%m-%d')
        c.execute(
            "SELECT COUNT(*) as c FROM journeys WHERE status = 'active' AND date >= %s",
            (today_str,)
        )
        active = c.fetchone()['c']
        c.execute(
            "SELECT COUNT(*) as c FROM ride_requests WHERE date >= %s",
            (today_str,)
        )
        requests = c.fetchone()['c']
        return jsonify({'active_journeys': active, 'active_requests': requests})
    except Exception as e:
        logger.error("Stats error: %s", e)
        return jsonify({'error': 'Грешка'}), 500
    finally:
        put_db(conn)


@app.route('/api/legal/<page>', methods=['GET'])
def legal(page):
    pages = {
        'terms': {
            'title': 'Условия за ползване',
            'content': (
                'Travel Board е платформа, която помага на потребителите да откриват и се свързват с други хора със съвместими планове за пътуване. '
                'Travel Board НЕ предоставя транспортни услуги, НЕ организира пътувания, НЕ продава билети, НЕ обработва плащания и НЕ гарантира никакво пътуване. '
                'Потребителите са изцяло отговорни за собствените си решения. '
                'Телефонният номер, който публикувате, е публичен и се вижда от всички посетители на таблото. '
                'Публикуването на телефонен номер НЕ потвърждава самоличността на човека. '
                'Може да бъдете контактиран(а) от непознати — не споделяйте чувствителна лична информация. '
                'Не изпращайте пари предварително на непознати.'
            )
        },
        'privacy': {
            'title': 'Политика за поверителност',
            'content': (
                'Събираме минимално количество информация: име и телефон за контакт. '
                'Телефонният номер е публичен, защото Travel Board е табло за директно свързване между пътуващи. '
                'Публикуването на номер означава, че всеки посетител може да го види и да се свърже с вас. '
                'Не споделяме данни с трети страни. '
                'Старите обяви се изтриват автоматично след датата на пътуването. '
                'Можете да изтриете обявата си по всяко време с кода за управление.'
            )
        },
        'safety': {
            'title': 'Безопасност',
            'content': (
                'Никога не споделяйте лична информация, ако не сте сигурни. '
                'Срещайте се на публични места. Не изпращайте пари предварително. '
                'Travel Board е само дъска за обяви — не носи отговорност за взаимодействията между потребителите. '
                'Телефонният номер в обявата НЕ потвърждава самоличността на човека. '
                'Винаги потвърждавайте личността на шофьора/пътника преди пътуване. '
                'Ако видите подозрителна обява, използвайте бутона "Сигнал".'
            )
        },
        'contact': {
            'title': 'Контакт',
            'content': 'За въпроси и сигнали: travelboard@proton.me'
        }
    }
    p = pages.get(page)
    if not p:
        return jsonify({'error': 'Не е намерено'}), 404
    return jsonify(p)


# ========== FRONTEND ==========

@app.route('/admin')
@admin_required
def admin_page():
    return render_template('admin.html')


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/static/<path:filename>')
def static_files(filename):
    return send_from_directory('static', filename)


@app.errorhandler(404)
def not_found(e):
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Не е намерено'}), 404
    return render_template('index.html')


@app.errorhandler(Exception)
def handle_error(e):
    logger.error("Unhandled error: %s", e, exc_info=True)
    if request.path.startswith('/api/'):
        return jsonify({'error': 'Възникна грешка. Опитайте отново по-късно.'}), 500
    return render_template('index.html'), 500


# Initialize
init_db()

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=int(os.environ.get('PORT', 5000)), debug=False)
