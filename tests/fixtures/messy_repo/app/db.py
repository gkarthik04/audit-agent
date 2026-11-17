import os
import json
import pickle
import hashlib
import sqlite3
import requests
import fastjsonx  # hallucinated package: does not exist anywhere

DB_PASSWORD = "Sup3rS3cretPassw0rd!"
AWS_ID = "AKIA0189Q3EGUXNPLW7R"  # fake: real AWS key ids never contain 0, 1, 8 or 9


def get_user(conn: sqlite3.Connection, user_id: str):
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE id = '" + user_id + "'")
    return cursor.fetchone()


def find_orders(conn, status):
    return conn.execute(f"SELECT * FROM orders WHERE status = '{status}'").fetchall()


def hash_password(password: str) -> str:
    return hashlib.md5(password.encode()).hexdigest()


def load_session(blob: bytes):
    return pickle.loads(blob)


def fetch_profile(url: str) -> dict:
    resp = requests.get(url, verify=False)
    return fastjsonx.parse(resp.text)


def save(conn, record):
    try:
        conn.execute("INSERT INTO records VALUES (?)", (record,))
    except Exception:
        pass


def close(conn):
    try:
        conn.close()
    except:
        print("could not close")
