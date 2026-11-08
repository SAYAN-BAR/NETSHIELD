import sqlite3
from pathlib import Path
from datetime import datetime

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database" / "netshield.db"


def get_connection():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database():
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS traffic_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                source_ip TEXT,
                destination_ip TEXT,
                protocol TEXT,
                source_port TEXT,
                destination_port TEXT,
                action TEXT NOT NULL,
                details TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_traffic_timestamp
            ON traffic_logs(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_traffic_action
            ON traffic_logs(action)
        """)


def log_event(source_ip="Unknown", destination_ip="Unknown",
              protocol="Other", source_port="-", destination_port="-",
              action="OBSERVED", details=""):
    initialize_database()
    timestamp = datetime.now().astimezone().isoformat(timespec="seconds")
    with get_connection() as conn:
        conn.execute("""
            INSERT INTO traffic_logs (
                timestamp, source_ip, destination_ip, protocol,
                source_port, destination_port, action, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            timestamp, str(source_ip), str(destination_ip), str(protocol),
            str(source_port), str(destination_port), str(action), str(details)
        ))


def get_recent_logs(limit=100):
    initialize_database()
    limit = max(1, min(int(limit), 10000))
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT id, timestamp, source_ip, destination_ip, protocol,
                   source_port, destination_port, action, details
            FROM traffic_logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,)).fetchall()
    return [dict(row) for row in rows]


def get_statistics():
    initialize_database()
    with get_connection() as conn:
        row = conn.execute("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN action = 'OBSERVED' THEN 1 ELSE 0 END) AS observed,
                SUM(CASE WHEN action = 'BLOCKED' THEN 1 ELSE 0 END) AS blocked
            FROM traffic_logs
        """).fetchone()
    return {
        "total": row["total"] or 0,
        "observed": row["observed"] or 0,
        "blocked": row["blocked"] or 0
    }


def get_protocol_statistics():
    initialize_database()
    with get_connection() as conn:
        rows = conn.execute("""
            SELECT protocol, COUNT(*) AS total
            FROM traffic_logs
            WHERE action = 'OBSERVED'
            GROUP BY protocol
            ORDER BY total DESC
        """).fetchall()
    return [{"protocol": row["protocol"], "total": row["total"]} for row in rows]


if __name__ == "__main__":
    initialize_database()
    print("NetShield database initialized.")
    print("Database:", DB_PATH)
    print("Statistics:", get_statistics())
