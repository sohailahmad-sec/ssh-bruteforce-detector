import os
import socket
import threading
from datetime import datetime

import paramiko

HOST, PORT = "127.0.0.1", 2222
VALID_USER = "testuser"
VALID_PASS = "Summer2026"   # jo yahi password hoga, login "Accepted" hoga

LOG_PATH = os.path.join("data", "live_auth.log")
os.makedirs("data", exist_ok=True)

HOST_KEY = paramiko.RSAKey.generate(2048)


def write_log(line):
    with open(LOG_PATH, "a") as f:
        f.write(line + "\n")
    print(line)


class Server(paramiko.ServerInterface):
    def __init__(self, client_ip):
        self.ip = client_ip

    def check_auth_password(self, username, password):
        stamp = datetime.now().strftime("%b %d %H:%M:%S")
        if username == VALID_USER and password == VALID_PASS:
            write_log(f"{stamp} server sshd[1234]: Accepted password for "
                      f"{username} from {self.ip} port 50000 ssh2")
            return paramiko.AUTH_SUCCESSFUL
        write_log(f"{stamp} server sshd[1234]: Failed password for "
                  f"{username} from {self.ip} port 50000 ssh2")
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "password"

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED


def handle(client_sock, addr):
    try:
        t = paramiko.Transport(client_sock)
        t.add_server_key(HOST_KEY)
        server = Server(addr[0])
        t.start_server(server=server)
        chan = t.accept(5)
        if chan:
            chan.close()
    except Exception:
        pass


print(f"Mini SSH server listening on {HOST}:{PORT}")
print(f"Valid login -> user: {VALID_USER}  pass: {VALID_PASS}")
print(f"Logging to: {LOG_PATH}\n")

sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
sock.bind((HOST, PORT))
sock.listen(20)

while True:
    client, addr = sock.accept()
    threading.Thread(target=handle, args=(client, addr), daemon=True).start()