"""Seed a local SQLite database for the mcp-shield example server.

Run from the project root:
    python examples/mcp_server/seed.py

Writes ``examples/mcp_server/shield_demo.sqlite`` with four tables:
- customers: tenant-scoped, contains an email column we want redacted
- orders: region-scoped, what 'support' should see filtered by region
- products: open to all roles
- users_credentials: globally denied; here only to prove the deny works
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).parent / "shield_demo.sqlite"

SCHEMA = """
DROP TABLE IF EXISTS customers;
DROP TABLE IF EXISTS orders;
DROP TABLE IF EXISTS products;
DROP TABLE IF EXISTS users_credentials;

CREATE TABLE customers (
    id INTEGER PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    full_name TEXT NOT NULL,
    email TEXT NOT NULL,
    tier TEXT NOT NULL
);

CREATE TABLE orders (
    id INTEGER PRIMARY KEY,
    customer_id INTEGER NOT NULL,
    region TEXT NOT NULL,
    amount REAL NOT NULL,
    status TEXT NOT NULL
);

CREATE TABLE products (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    price REAL NOT NULL
);

CREATE TABLE users_credentials (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL,
    password_hash TEXT NOT NULL
);
"""

CUSTOMERS = [
    (1, "acme",   "Alice Cooper",  "alice@acme.test",   "gold"),
    (2, "acme",   "Bob Marley",    "bob@acme.test",     "silver"),
    (3, "globex", "Carol Danvers", "carol@globex.test", "gold"),
    (4, "globex", "Dan Brown",     "dan@globex.test",   "silver"),
]

ORDERS = [
    (1, 1, "us", 199.00, "completed"),
    (2, 1, "us",  49.00, "completed"),
    (3, 2, "us",  19.00, "cancelled"),
    (4, 3, "eu", 299.00, "completed"),
    (5, 4, "eu",  79.00, "completed"),
    (6, 4, "eu",  39.00, "pending"),
]

PRODUCTS = [
    (1, "Pro Plan",  99.00),
    (2, "Team Plan", 299.00),
    (3, "Add-on",    19.00),
]

CREDS = [
    (1, "admin", "should-never-be-readable"),
]


def main() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    conn = sqlite3.connect(DB_PATH)
    try:
        conn.executescript(SCHEMA)
        conn.executemany("INSERT INTO customers VALUES (?, ?, ?, ?, ?)", CUSTOMERS)
        conn.executemany("INSERT INTO orders VALUES (?, ?, ?, ?, ?)", ORDERS)
        conn.executemany("INSERT INTO products VALUES (?, ?, ?)", PRODUCTS)
        conn.executemany("INSERT INTO users_credentials VALUES (?, ?, ?)", CREDS)
        conn.commit()
    finally:
        conn.close()
    print(f"seeded {DB_PATH}")


if __name__ == "__main__":
    main()
