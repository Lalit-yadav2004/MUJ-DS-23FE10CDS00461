"""
Test Corpus File: Benign Honeypot (Path traversal bounded by os.path.realpath)
Vulnerability: False (Validates resolved path stays within sandbox root)
"""
import os

def load_static_asset(user_filename):
    sandbox_root = "/var/www/static"
    # SAFE: Path bounded with realpath and commonpath check
    candidate = os.path.realpath(os.path.join(sandbox_root, os.path.basename(user_filename)))
    if os.path.commonpath([sandbox_root, candidate]) != sandbox_root:
        raise PermissionError("Access outside sandbox forbidden")

    with open(candidate, "r", encoding="utf-8") as f:
        return f.read()
