"""
Test Corpus File: CWE-78 OS Command Injection
Vulnerability: True (Raw string concatenated into shell execution sink)
"""
import os

def ping_server(target_host):
    # DANGEROUS: Untrusted target_host passed directly to os.system()
    command = f"ping -c 1 {target_host}"
    exit_code = os.system(command)
    return exit_code == 0
