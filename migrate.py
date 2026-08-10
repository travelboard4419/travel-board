#!/usr/bin/env python3
"""
Travel Board — SQLite to PostgreSQL Migration Script

Usage:
    1. Set DATABASE_URL environment variable pointing to your PostgreSQL database.
    2. Place your old SQLite database as 'travelboard_v3.db' in the same directory.
    3. Run: python migrate.py

This script will:
    - Read all data from the old SQLite database
    - Insert it into the new PostgreSQL database
    - Preserve IDs where possible
    - Reset PostgreSQL sequences after migration
"""

import os
import sqlite3

# PostgreSQL connection
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    print("ERROR: DATABASE_URL environment variable is required")
    exit(1)

if DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = DATABASE_URL.replace("postgres://", "postgresql://", 1)

SQLITE_DB = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'travelboard_v3.db')
if not os.path.exists(SQLITE_DB):
    print(f"ERROR: SQLite database not found at {SQLITE_DB}")
    print("Place your old database file in the project root directory.")
    exit(1)

import psycopg2
from psycopg2.extras import RealDictCursor

def main():
    print("Connecting to SQLite...")
    sqlite_conn = sqlite3.connect(SQLITE_DB)
    sqlite_conn.row_factory = sqlite3.Row
    sqlite_cur = sqlite_conn.cursor()

    print("Connecting to PostgreSQL...")
    pg_conn = psycopg2.connect(DATABASE_URL)
    pg_cur = pg_conn.cursor()

    # Ensure tables exist in PostgreSQL
    print("Creating PostgreSQL tables if needed...")
    pg_cur.execute("""
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
    pg_cur.execute("""
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
    pg_cur.execute("""
        CREATE TABLE IF NOT EXISTS reports (
            id SERIAL PRIMARY KEY,
            post_type TEXT NOT NULL,
            post_id INTEGER NOT NULL,
            reason TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    pg_conn.commit()

    # Migrate journeys
    print("Migrating journeys...")
    sqlite_cur.execute("SELECT * FROM journeys")
    journeys = sqlite_cur.fetchall()
    for row in journeys:
        pg_cur.execute("""
            INSERT INTO journeys (id, origin, destination, date, time, seats, contact_name, contact_phone, mgmt_code_hash, status, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, (
            row['id'], row['origin'], row['destination'], row['date'], row['time'],
            row['seats'], row['contact_name'], row['contact_phone'],
            row['mgmt_code_hash'], row['status'], row['created_at']
        ))
    pg_conn.commit()
    print(f"  Migrated {len(journeys)} journeys")

    # Migrate ride requests
    print("Migrating ride requests...")
    sqlite_cur.execute("SELECT * FROM ride_requests")
    requests = sqlite_cur.fetchall()
    for row in requests:
        pg_cur.execute("""
            INSERT INTO ride_requests (id, origin, destination, date, time, people, contact_name, contact_phone, mgmt_code_hash, created_at)
            VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, (
            row['id'], row['origin'], row['destination'], row['date'], row['time'],
            row['people'], row['contact_name'], row['contact_phone'],
            row['mgmt_code_hash'], row['created_at']
        ))
    pg_conn.commit()
    print(f"  Migrated {len(requests)} ride requests")

    # Migrate reports
    print("Migrating reports...")
    sqlite_cur.execute("SELECT * FROM reports")
    reports = sqlite_cur.fetchall()
    for row in reports:
        pg_cur.execute("""
            INSERT INTO reports (id, post_type, post_id, reason, created_at)
            VALUES (%s, %s, %s, %s, %s)
            ON CONFLICT (id) DO NOTHING
        """, (
            row['id'], row['post_type'], row['post_id'], row['reason'], row['created_at']
        ))
    pg_conn.commit()
    print(f"  Migrated {len(reports)} reports")

    # Reset sequences
    print("Resetting PostgreSQL sequences...")
    pg_cur.execute("SELECT setval('journeys_id_seq', COALESCE((SELECT MAX(id) FROM journeys), 1), true)")
    pg_cur.execute("SELECT setval('ride_requests_id_seq', COALESCE((SELECT MAX(id) FROM ride_requests), 1), true)")
    pg_cur.execute("SELECT setval('reports_id_seq', COALESCE((SELECT MAX(id) FROM reports), 1), true)")
    pg_conn.commit()

    # Verify
    pg_cur.execute("SELECT COUNT(*) FROM journeys")
    j_count = pg_cur.fetchone()[0]
    pg_cur.execute("SELECT COUNT(*) FROM ride_requests")
    r_count = pg_cur.fetchone()[0]
    pg_cur.execute("SELECT COUNT(*) FROM reports")
    rep_count = pg_cur.fetchone()[0]

    print("\nMigration complete!")
    print(f"  PostgreSQL journeys: {j_count}")
    print(f"  PostgreSQL requests: {r_count}")
    print(f"  PostgreSQL reports:  {rep_count}")
    print("\nYou can now delete the old SQLite database if everything looks correct.")

    sqlite_conn.close()
    pg_conn.close()

if __name__ == '__main__':
    main()
