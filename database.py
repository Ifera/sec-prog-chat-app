import sqlite3
import json
from typing import Optional, Dict, Any

class Database:
    def __init__(self, db_path: str = "socp.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # Users table
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS users (
                    user_id TEXT PRIMARY KEY,
                    pubkey TEXT NOT NULL,
                    privkey_store TEXT NOT NULL,
                    pake_password TEXT NOT NULL,
                    meta TEXT,
                    version INTEGER NOT NULL DEFAULT 1
                )
            ''')

            # Groups table (public channel is "public")
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS groups (
                    group_id TEXT PRIMARY KEY,
                    creator_id TEXT NOT NULL,
                    created_at INTEGER,
                    meta TEXT,
                    version INTEGER NOT NULL DEFAULT 1
                )
            ''')

            # Group members
            cursor.execute('''
                CREATE TABLE IF NOT EXISTS group_members (
                    group_id TEXT NOT NULL,
                    member_id TEXT NOT NULL,
                    role TEXT NOT NULL,
                    wrapped_key TEXT NOT NULL,
                    added_at INTEGER,
                    PRIMARY KEY (group_id, member_id)
                )
            ''')

            # Initialize public channel if not exists
            cursor.execute("SELECT COUNT(*) FROM groups WHERE group_id = 'public'")
            if cursor.fetchone()[0] == 0:
                import time
                cursor.execute('''
                    INSERT INTO groups (group_id, creator_id, created_at, meta, version)
                    VALUES (?, ?, ?, ?, ?)
                ''', ('public', 'system', int(time.time() * 1000), json.dumps({"title": "Public Channel"}), 1))

            conn.commit()

    def get_user(self, user_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM users WHERE user_id = ?", (user_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "user_id": row[0],
                    "pubkey": row[1],
                    "privkey_store": row[2],
                    "pake_password": row[3],
                    "meta": json.loads(row[4]) if row[4] else None,
                    "version": row[5]
                }
        return None

    def add_user(self, user_id: str, pubkey: str, privkey_store: str, pake_password: str, meta: Optional[Dict] = None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO users (user_id, pubkey, privkey_store, pake_password, meta, version)
                VALUES (?, ?, ?, ?, ?, 1)
            ''', (user_id, pubkey, privkey_store, pake_password, json.dumps(meta) if meta else None))
            conn.commit()

    def get_group_members(self, group_id: str) -> Dict[str, Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT member_id, role, wrapped_key FROM group_members WHERE group_id = ?", (group_id,))
            members = {}
            for row in cursor.fetchall():
                members[row[0]] = {
                    "role": row[1],
                    "wrapped_key": row[2]
                }
            return members

    def add_group_member(self, group_id: str, member_id: str, role: str, wrapped_key: str):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            import time
            cursor.execute('''
                INSERT OR REPLACE INTO group_members (group_id, member_id, role, wrapped_key, added_at)
                VALUES (?, ?, ?, ?, ?)
            ''', (group_id, member_id, role, wrapped_key, int(time.time() * 1000)))
            conn.commit()

    def get_group(self, group_id: str) -> Optional[Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM groups WHERE group_id = ?", (group_id,))
            row = cursor.fetchone()
            if row:
                return {
                    "group_id": row[0],
                    "creator_id": row[1],
                    "created_at": row[2],
                    "meta": json.loads(row[3]) if row[3] else None,
                    "version": row[4]
                }
        return None

    def update_group_version(self, group_id: str, version: int):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE groups SET version = ? WHERE group_id = ?", (version, group_id))
            conn.commit()
