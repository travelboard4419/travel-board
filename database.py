import os
import psycopg2
from psycopg2 import pool
from psycopg2.extras import RealDictCursor

DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise ValueError("DATABASE_URL environment variable is required")

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

db_pool = pool.ThreadedConnectionPool(1, 20, DATABASE_URL)


def get_db():
    """Get a connection from the pool. Caller MUST call put_db(conn) when done."""
    return db_pool.getconn()


def put_db(conn):
    """Return a connection to the pool."""
    db_pool.putconn(conn)


def db_cursor(conn):
    """Create a RealDictCursor for dict-like row access."""
    return conn.cursor(cursor_factory=RealDictCursor)


def init_db():
    conn = get_db()
    c = conn.cursor()
    try:
        c.execute("""
            CREATE TABLE IF NOT EXISTS journeys (
                id SERIAL PRIMARY KEY,
                origin TEXT NOT NULL,
                destination TEXT NOT NULL,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                seats INTEGER DEFAULT 1,
                contact_name TEXT NOT NULL,
                contact_phone TEXT NOT NULL,
                mgmt_code_hash TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS ride_requests (
                id SERIAL PRIMARY KEY,
                origin TEXT NOT NULL,
                destination TEXT NOT NULL,
                date TEXT NOT NULL,
                time TEXT NOT NULL,
                people INTEGER DEFAULT 1,
                contact_name TEXT NOT NULL,
                contact_phone TEXT NOT NULL,
                mgmt_code_hash TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS reports (
                id SERIAL PRIMARY KEY,
                post_type TEXT NOT NULL,
                post_id INTEGER NOT NULL,
                reason TEXT NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        c.execute("""
            CREATE TABLE IF NOT EXISTS sessions (
                id TEXT PRIMARY KEY,
                data TEXT NOT NULL DEFAULT '{}',
                expires_at TIMESTAMP NOT NULL
            )
        """)
        c.execute("CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at)")
        c.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                key TEXT PRIMARY KEY,
                count INTEGER NOT NULL DEFAULT 1,
                window_start TIMESTAMP NOT NULL
            )
        """)
        # Performance indexes for common queries
        c.execute("CREATE INDEX IF NOT EXISTS idx_journeys_active_date ON journeys(status, date, time)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_journeys_origin_dest ON journeys(origin, destination, date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_journeys_mgmt ON journeys(mgmt_code_hash, status)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_requests_date ON ride_requests(date, time)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_requests_origin_dest ON ride_requests(origin, destination, date)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_requests_mgmt ON ride_requests(mgmt_code_hash)")
        c.execute("CREATE INDEX IF NOT EXISTS idx_reports_post ON reports(post_type, post_id, reason, created_at)")
        conn.commit()
        print("Database initialized with indexes")
    except Exception as e:
        conn.rollback()
        raise
    finally:
        put_db(conn)


if __name__ == '__main__':
    init_db()
