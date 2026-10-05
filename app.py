"""
CodePulse AI - Quick Web Launcher
=================================
Allows running: python3 app.py or python3 main.py web
"""

import os
import socket
import sys
from pathlib import Path
import uvicorn

# Ensure project root is in sys.path
root_dir = Path(__file__).resolve().parent
if str(root_dir) not in sys.path:
    sys.path.insert(0, str(root_dir))


def is_port_in_use(port: int, host: str = "127.0.0.1") -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        return s.connect_ex((host, port)) == 0


if __name__ == "__main__":
    env_port = os.getenv("PORT")
    env_host = os.getenv("HOST", "0.0.0.0" if env_port else "127.0.0.1")

    if env_port and env_port.isdigit():
        port = int(env_port)
        host = env_host
    elif len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
        host = env_host
    else:
        port = 8000
        host = env_host
        # Check if port 8000 is occupied locally; if so, fallback to 8001
        if host == "127.0.0.1" and is_port_in_use(port):
            print(f"[!] Notice: Port {port} is already in use by another process.")
            port = 8001
            print(f"[*] Switching automatically to http://127.0.0.1:{port}...")

    print(f"\n[✓] CodePulse AI Web Dashboard live at: http://{host}:{port}\n")
    uvicorn.run("web.app:app", host=host, port=port, reload=False)
