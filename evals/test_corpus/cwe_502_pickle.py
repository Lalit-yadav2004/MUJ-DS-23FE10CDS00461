"""
Test Corpus File: CWE-502 Deserialization of Untrusted Data
Vulnerability: True (Direct pickle.loads on unvalidated network stream)
"""
import pickle

def restore_session(raw_session_bytes):
    # DANGEROUS: pickle.loads can execute arbitrary bytecode instructions
    session_data = pickle.loads(raw_session_bytes)
    return session_data
