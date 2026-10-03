"""
Test Corpus File: CWE-89 SQL Injection
Vulnerability: True (Unescaped user input interpolated into SQL query)
"""

def get_user_profile(db_connection, user_id):
    # DANGEROUS: Direct f-string interpolation into SQL statement
    query = f"SELECT id, username, email, is_admin FROM users WHERE id = '{user_id}'"
    cursor = db_connection.cursor()
    cursor.execute(query)
    return cursor.fetchone()
