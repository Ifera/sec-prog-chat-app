# Group 59
# ----------------------------------
# Muhammad Tayyab Rashid - a1988298
# Nguyen Duc Tung Bui - a1976012
# Guilin Luo - a1989840
# Mazharul Islam Rakib - a1990942
# Masud Ahammad - a1993200

import json
import sqlite3
from typing import Optional, Dict, Any

from crypto import load_public_key, rsa_encrypt, rsa_decrypt, load_private_key, generate_aes_key, hash_string


class Database:
    def __init__(self, db_path: str = "chat.db"):
        self.db_path = db_path
        self.init_db()

    def init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # remove all users from public channel on bootup
            # users will be added back on demand
            cursor.execute("DROP TABLE IF EXISTS group_members")

            # Users
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS users
                           (
                               user_id       TEXT PRIMARY KEY,
                               pubkey        TEXT    NOT NULL,
                               privkey_store TEXT,
                               pake_password TEXT,
                               meta          TEXT,
                               version       INTEGER NOT NULL DEFAULT 1
                           )
                           ''')

            # Public channel + members
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS groups
                           (
                               group_id   TEXT PRIMARY KEY,
                               creator_id TEXT    NOT NULL,
                               created_at INTEGER,
                               meta       TEXT,
                               version    INTEGER NOT NULL DEFAULT 1
                           )
                           ''')

            # Group members
            cursor.execute('''
                           CREATE TABLE IF NOT EXISTS group_members
                           (
                               group_id    TEXT NOT NULL,
                               member_id   TEXT NOT NULL,
                               role        TEXT NOT NULL,
                               wrapped_key TEXT NOT NULL,
                               added_at    INTEGER,
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
                               ''',
                               ('public', 'system', int(time.time() * 1000), json.dumps({"title": "Public Channel"}),
                                1))
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

    def add_user(self, user_id: str, pubkey: str, password: str, meta: Optional[Dict] = None, version: int = 1, *, remote_user: bool = False):
        pake_password = "" if remote_user else hash_string(password)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT OR REPLACE INTO users (user_id, pubkey, pake_password, meta, version)
                VALUES (?, ?, ?, ?, ?)
            ''', (user_id, pubkey, pake_password, json.dumps(meta) if meta else None, version))
            conn.commit()

    def update_user(self, user_id: str, pubkey: str, meta: Optional[Dict] = None, version: int = 1):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("UPDATE users SET pubkey = ?, meta = COALESCE(?, meta), version = COALESCE(?, version) WHERE user_id = ?", (
                pubkey,
                json.dumps(meta) if meta is not None else None,
                version,
                user_id,
            ))
            conn.commit()

    def get_group_members(self, group_id: str) -> Dict[str, Dict[str, Any]]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT member_id, role, wrapped_key FROM group_members WHERE group_id = ?", (group_id,))
            members = {}
            for row in cursor.fetchall():
                members[row[0]] = {"role": row[1], "wrapped_key": row[2]}
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

    def remove_user_from_group_members(self, user_id: str) -> None:
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            cur.execute("DELETE FROM group_members WHERE member_id = ?", (user_id,))
            conn.commit()

    def get_group_key(self, group_id: str, server_private_key_b64: str) -> Optional[bytes]:
        from crypto import load_private_key, rsa_decrypt
        group = self.get_group(group_id)
        if group and group['meta']:  # use meta for encrypted key
            try:
                encrypted_key_b64 = group['meta'].get('encrypted_group_key')
                if encrypted_key_b64:
                    server_priv = load_private_key(server_private_key_b64)
                    return rsa_decrypt(server_priv, encrypted_key_b64)
            except:
                pass
        return None

    def set_group_key(self, group_id: str, key: bytes, server_public_key_b64: str):
        from crypto import load_public_key, rsa_encrypt
        pub_key = load_public_key(server_public_key_b64)
        encrypted = rsa_encrypt(pub_key, key)
        # store in meta
        with sqlite3.connect(self.db_path) as conn:
            cur = conn.cursor()
            group = self.get_group(group_id)
            meta = group['meta'] if group else {}
            meta['encrypted_group_key'] = encrypted
            meta_json = json.dumps(meta)
            cur.execute("UPDATE groups SET meta = ? WHERE group_id = ?", (meta_json, group_id))
            conn.commit()

    def add_user_to_public_channel(self, user_id: str, server_public_key_b64: str):
        group = self.get_group("public")
        if not group:
            return False
        members = self.get_group_members("public")
        if user_id in members:
            return False  # already member

        # Determine the current key: if existing members, decrypt from one; else generate new
        if members:
            # Pick the first existing member to decrypt the key
            existing_uid, info = next(iter(members.items()))
            existing_user = self.get_user(existing_uid)
            if not existing_user:
                return False
            try:
                current_key = rsa_decrypt(load_private_key(existing_user['pubkey']), info['wrapped_key'])
                # No need to set_group_key if already set, but to ensure
                self.set_group_key("public", current_key, server_public_key_b64)
            except:
                # Perhaps corrupt, regenerate
                current_key = generate_aes_key()
                self.set_group_key("public", current_key, server_public_key_b64)
        else:
            # No existing members, generate new random key
            current_key = generate_aes_key()
            self.set_group_key("public", current_key, server_public_key_b64)

        # Bump version
        new_version = group['version'] + 1
        self.update_group_version("public", new_version)

        # Wrap the current key for ALL members (existing + new)
        all_user_ids = list(members.keys()) + [user_id]
        for uid in all_user_ids:
            user_rec = self.get_user(uid)
            if not user_rec:
                continue  # skip if no user rec, but should not happen
            member_pub = load_public_key(user_rec['pubkey'])
            wrapped_key = rsa_encrypt(member_pub, current_key)
            self.add_group_member("public", uid, "member", wrapped_key)

        return True
