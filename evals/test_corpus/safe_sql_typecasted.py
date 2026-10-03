"""
Test Corpus File: Benign Honeypot (SQL with explicit typecasting)
Vulnerability: False (Input strictly cast to integer, neutralizing injection)
"""

def fetch_order_by_id(db_conn, raw_order_id):
    # SAFE: Coerced to int, raises ValueError if payload is string or SQL injection
    clean_id = int(raw_order_id)
    query = f"SELECT * FROM orders WHERE order_id = {clean_id}"
    cursor = db_conn.cursor()
    cursor.execute(query)
    return cursor.fetchone()
