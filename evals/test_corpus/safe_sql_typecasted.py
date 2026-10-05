"""
Test Corpus File: Benign Honeypot — Parameterized SQL (Real Defense)
Vulnerability: False
Defense: cursor.execute() called with parameterized placeholder + tuple binding.
         The SQL structure is compiled BEFORE user data is bound — injection impossible.

Why this is safe vs. the int() pattern:
  - int() + f-string: still puts a value INTO the SQL string (numeric, but still formatting)
  - Parameterized: SQL structure and user data are COMPLETELY SEPARATED at the DB driver level
"""

def fetch_order_by_id(db_conn, raw_order_id):
    # SAFE: Parameterized query — SQL compiled before user data is inserted
    cursor = db_conn.cursor()
    cursor.execute("SELECT * FROM orders WHERE order_id = ?", (raw_order_id,))
    return cursor.fetchone()
