import sqlite3
from email.policy import default
from pathlib import Path
from flask import g, request

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "database.db"
SCHEMA_PATH = BASE_DIR / "schema.sql"

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db

def close_db(e=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()

def init_db():
    db = sqlite3.connect(DB_PATH)
    with open(SCHEMA_PATH, "r", encoding="utf-8") as f:
        db.executescript(f.read())
    db.commit()
    db.close()


def audit_log(user_id, action, resource, resource_id):
    db = get_db()
    db.execute(
        "INSERT INTO audit_logs (user_id, action, resource, resource_id, ip_address) VALUES (?, ?, ?, ?, ?)",
        (user_id, action, resource, resource_id,
         request.remote_addr if request else "unknown")
    )
    db.commit()