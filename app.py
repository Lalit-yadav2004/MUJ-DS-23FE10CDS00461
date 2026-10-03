"""
CodePulse AI - Quick Web Launcher
=================================
Allows running: python3 app.py or python3 main.py web
"""

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
    port = 8000
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        port = int(sys.argv[1])
    else:
        # Check if port 8000 is occupied; if so, fallback to 8001
        if is_port_in_use(port):
            print(f"[!] Notice: Port {port} is already in use by another process.")
            port = 8001
            print(f"[*] Switching automatically to http://127.0.0.1:{port}...")

    print(f"\n[✓] CodePulse AI Web Dashboard live at: http://127.0.0.1:{port}\n")
    uvicorn.run("web.app:app", host="127.0.0.1", port=port, reload=False)
