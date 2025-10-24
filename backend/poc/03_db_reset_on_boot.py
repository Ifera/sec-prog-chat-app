"""
Proof of Concept: Database Reset on Boot

This script demonstrates a vulnerability where the database initialization process incorrectly drops
and recreates existing tables on every server reboot or initialization, leading to data loss.
In a secure and well-designed system, database schema should only be created if it doesn't exist,
not dropped and recreated, which removes all data.

This PoC exploits the faulty initialization logic to show how data (e.g., user information)
can be permanently lost during restarts.
"""

import os
import sqlite3
import tempfile

from database import Database  # uses init_db() that drops tables


def count_users(db_path):
    with sqlite3.connect(db_path) as c:
        try:
            return c.execute("select count(*) from users").fetchone()[0]
        except sqlite3.OperationalError:
            return -1


db_fd, db_path = tempfile.mkstemp(prefix="chat_poc_", suffix=".db")
os.close(db_fd)

# First init (creates schema, drops anything existing)
db = Database(db_path)
print("[init1] users:", count_users(db_path))

# Add a user row
with sqlite3.connect(db_path) as c:
    c.execute("insert into users(user_id,pubkey,privkey_store,pake_password,meta,version) values(?,?,?,?,?,1)",
              ("u1", "pk", "sk", "pw", "{}"))
    c.commit()
print("[after insert] users:", count_users(db_path))

# Second init (simulates server reboot) -> DROPs & recreates
db2 = Database(db_path)
print("[init2] users after reboot (should not be 1 if drop happened):", count_users(db_path))
