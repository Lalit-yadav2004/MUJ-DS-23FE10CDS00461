"""
Test Corpus File: CWE-22 Path Traversal
Vulnerability: True (Direct filename concatenation without boundary check)
"""

def serve_document(filename):
    base_dir = "/var/www/uploads"
    # DANGEROUS: filename may contain ../../etc/passwd
    target_path = f"{base_dir}/{filename}"
    with open(target_path, "r", encoding="utf-8") as f:
        return f.read()
