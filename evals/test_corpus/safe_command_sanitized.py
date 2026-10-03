"""
Test Corpus File: Benign Honeypot (Command with shlex.quote)
Vulnerability: False (Input quoted and escaped safely)
"""
import shlex
import subprocess

def run_diagnostic_ping(hostname):
    # SAFE: shlex.quote sanitizes all shell metacharacters
    safe_host = shlex.quote(hostname)
    result = subprocess.run(["ping", "-c", "1", safe_host], capture_output=True, text=True)
    return result.returncode == 0
