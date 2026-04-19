"""
Database - Persistent user and alert storage using SQLite.

Passwords are stored as hash + salt (salt = 'helloworld').
Users can register once and re-login anytime.
"""

import os
import sqlite3
import secrets
import hashlib
from datetime import datetime

# Salt value for password hashing
SALT = "helloworld"

# Database file path (stored in server/ directory)
DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lolbins.db")


def _get_db():
    """Get a SQLite database connection."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    """Create tables if they don't exist."""
    conn = _get_db()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            api_key TEXT UNIQUE NOT NULL,
            created_at TEXT NOT NULL
        )
    """)

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            command TEXT NOT NULL,
            severity TEXT NOT NULL,
            reason TEXT,
            confidence REAL,
            method TEXT,
            timestamp TEXT NOT NULL,
            FOREIGN KEY (username) REFERENCES users(username)
        )
    """)

    conn.commit()
    conn.close()


def _hash_password(password):
    """Hash a password using SHA-256 with the salt value."""
    salted = password + SALT
    return hashlib.sha256(salted.encode()).hexdigest()


def generate_api_key():
    """Generate a 128-bit secure API key (16 bytes = 32 hex chars)."""
    return secrets.token_hex(16)


def create_user(username, password):
    """Create a new user. Returns the user dict, or None if username exists."""
    conn = _get_db()
    cursor = conn.cursor()

    try:
        api_key = generate_api_key()
        password_hash = _hash_password(password)
        created_at = datetime.now().isoformat()

        cursor.execute(
            "INSERT INTO users (username, password_hash, api_key, created_at) VALUES (?, ?, ?, ?)",
            (username, password_hash, api_key, created_at)
        )
        conn.commit()

        return {
            "username": username,
            "api_key": api_key,
        }

    except sqlite3.IntegrityError:
        # Username already exists
        return None

    finally:
        conn.close()


def verify_user(username, password):
    """Verify credentials. Returns user dict on success, None on failure."""
    conn = _get_db()
    cursor = conn.cursor()

    password_hash = _hash_password(password)

    cursor.execute(
        "SELECT username, api_key FROM users WHERE username = ? AND password_hash = ?",
        (username, password_hash)
    )
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"username": row["username"], "api_key": row["api_key"]}
    return None


def get_user_by_key(key):
    """Look up a user by their API key."""
    conn = _get_db()
    cursor = conn.cursor()

    cursor.execute("SELECT username, api_key FROM users WHERE api_key = ?", (key,))
    row = cursor.fetchone()
    conn.close()

    if row:
        return {"username": row["username"], "api_key": row["api_key"]}
    return None


def store_alert(alert, username):
    """Store a detection alert associated with a user."""
    conn = _get_db()
    cursor = conn.cursor()

    timestamp = datetime.now().isoformat()
    alert["timestamp"] = timestamp
    alert["user"] = username

    cursor.execute(
        """INSERT INTO alerts (username, command, severity, reason, confidence, method, timestamp)
           VALUES (?, ?, ?, ?, ?, ?, ?)""",
        (
            username,
            alert.get("command", ""),
            alert.get("severity", "low"),
            alert.get("reason", ""),
            alert.get("confidence"),
            alert.get("method", ""),
            timestamp,
        )
    )
    conn.commit()
    conn.close()


def get_user_alerts(username):
    """Return all alerts for a given user."""
    conn = _get_db()
    cursor = conn.cursor()

    cursor.execute(
        "SELECT command, severity, reason, confidence, method, timestamp FROM alerts WHERE username = ? ORDER BY id DESC",
        (username,)
    )
    rows = cursor.fetchall()
    conn.close()

    return [
        {
            "command": row["command"],
            "severity": row["severity"],
            "reason": row["reason"],
            "confidence": row["confidence"],
            "method": row["method"],
            "timestamp": row["timestamp"],
            "user": username,
        }
        for row in rows
    ]


# Initialize database on import
init_db()