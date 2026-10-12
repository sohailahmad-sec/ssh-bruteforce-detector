import re
from datetime import datetime

# Example line:
# Oct 11 14:22:01 server sshd[1234]: Failed password for root from 192.168.1.50 port 4022 ssh2
# Example line:
# Oct 11 14:22:05 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 4023 ssh2

FAILED_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Failed password for\s+"
    r"(?:invalid user\s+)?(?P<user>\S+)\s+from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)

ACCEPTED_PATTERN = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd\[\d+\]:\s+Accepted \w+ for\s+(?P<user>\S+)\s+"
    r"from\s+(?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def _to_datetime(month, day, time_str, year=None):
    year = year or datetime.now().year
    return datetime.strptime(f"{year} {month} {day} {time_str}", "%Y %b %d %H:%M:%S")


def parse_log_file(path):
    """
    Log file read karke events ki list return karta hai.
    Har event: {"time", "ip", "user", "status"}  status = FAILED / ACCEPTED
    """
    events = []
    with open(path, "r", errors="ignore") as f:
        for line in f:
            line = line.strip()
            m = FAILED_PATTERN.match(line)
            if m:
                events.append({
                    "time": _to_datetime(m["month"], m["day"], m["time"]),
                    "ip": m["ip"],
                    "user": m["user"],
                    "status": "FAILED",
                })
                continue
            m = ACCEPTED_PATTERN.match(line)
            if m:
                events.append({
                    "time": _to_datetime(m["month"], m["day"], m["time"]),
                    "ip": m["ip"],
                    "user": m["user"],
                    "status": "ACCEPTED",
                })
    events.sort(key=lambda e: e["time"])
    return events