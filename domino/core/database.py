import json
import sqlite3
from datetime import datetime
from pathlib import Path


class DominoDB:
    def __init__(self, db_path=None):
        if db_path is None:
            db_path = Path.home() / ".domino" / "domino.db"

        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.conn = sqlite3.connect(str(self.db_path))
        self.conn.row_factory = sqlite3.Row
        self._create_tables()

    def _create_tables(self):
        with self.conn:
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    profile TEXT,
                    region TEXT,
                    data TEXT
                )
            """
            )
            self.conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    snapshot_id INTEGER,
                    start_principal TEXT,
                    timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                    chains TEXT,
                    FOREIGN KEY (snapshot_id) REFERENCES snapshots (id)
                )
            """
            )

    def save_snapshot(self, profile, region, data):
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO snapshots (profile, region, data) VALUES (?, ?, ?)",
                (profile, region, json.dumps(data)),
            )
            return cursor.lastrowid

    def save_scan(self, snapshot_id, start_principal, chains):
        with self.conn:
            cursor = self.conn.execute(
                "INSERT INTO scans (snapshot_id, start_principal, chains) VALUES (?, ?, ?)",
                (snapshot_id, start_principal, json.dumps(chains)),
            )
            return cursor.lastrowid

    def get_latest_snapshot(self, profile=None):
        query = "SELECT * FROM snapshots ORDER BY timestamp DESC LIMIT 1"
        cursor = self.conn.execute(query)
        row = cursor.fetchone()
        if row:
            return dict(row)
        return None
