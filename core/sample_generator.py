import random
from datetime import datetime, timedelta

USERS = ["root", "admin", "ubuntu", "test", "oracle", "user", "postgres"]


def _line(ts, user, ip, ok=False, invalid=False):
    stamp = f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')}"
    pid = random.randint(1000, 9999)
    port = random.randint(30000, 60000)
    if ok:
        return f"{stamp} server sshd[{pid}]: Accepted password for {user} from {ip} port {port} ssh2"
    inv = "invalid user " if invalid else ""
    return f"{stamp} server sshd[{pid}]: Failed password for {inv}{user} from {ip} port {port} ssh2"


def generate_sample_log(path):
    """Realistic fake auth.log banata hai: normal users + attackers."""
    now = datetime.now().replace(microsecond=0)
    lines = []

    # Normal users
    for _ in range(25):
        t = now - timedelta(minutes=random.randint(1, 120))
        ip = f"192.168.1.{random.randint(10, 30)}"
        lines.append((t, _line(t, "alice", ip, ok=True)))
    for _ in range(4):
        t = now - timedelta(minutes=random.randint(1, 120))
        lines.append((t, _line(t, "alice", "192.168.1.15")))

    # Attacker 1: heavy brute-force, phir successful login (CRITICAL)
    base = now - timedelta(minutes=50)
    for i in range(40):
        t = base + timedelta(seconds=i * 2)
        lines.append((t, _line(t, random.choice(USERS), "45.33.12.9", invalid=True)))
    t = base + timedelta(seconds=90)
    lines.append((t, _line(t, "root", "45.33.12.9", ok=True)))

    # Attacker 2: medium brute-force
    base = now - timedelta(minutes=30)
    for i in range(9):
        t = base + timedelta(seconds=i * 8)
        lines.append((t, _line(t, random.choice(USERS), "103.77.5.21", invalid=True)))

    # Attacker 3: slow scan (alert nahi hona chahiye)
    base = now - timedelta(minutes=80)
    for i in range(4):
        t = base + timedelta(minutes=i * 10)
        lines.append((t, _line(t, "admin", "185.220.101.4")))

    lines.sort(key=lambda x: x[0])
    with open(path, "w") as f:
        f.write("\n".join(l for _, l in lines) + "\n")
    return path