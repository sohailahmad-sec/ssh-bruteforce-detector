from collections import defaultdict
from datetime import timedelta


def detect_bruteforce(events, threshold=5, window_minutes=2):
    """
    Sliding window detection:
    Agar ek IP se `window_minutes` ke andar `threshold` ya zyada FAILED attempts hon
    to alert banao.

    Return: list of alerts (dict)
    """
    failed_by_ip = defaultdict(list)
    accepted_by_ip = defaultdict(list)

    for e in events:
        if e["status"] == "FAILED":
            failed_by_ip[e["ip"]].append(e)
        else:
            accepted_by_ip[e["ip"]].append(e)

    window = timedelta(minutes=window_minutes)
    alerts = []

    for ip, items in failed_by_ip.items():
        items.sort(key=lambda x: x["time"])
        start = 0
        best = None  # sabse bada burst track karne ke liye

        for end in range(len(items)):
            while items[end]["time"] - items[start]["time"] > window:
                start += 1
            count = end - start + 1
            if count >= threshold and (best is None or count > best["count"]):
                best = {"start": start, "end": end, "count": count}

        if best:
            burst = items[best["start"]: best["end"] + 1]
            users = sorted({b["user"] for b in burst})
            total_failed = len(items)

            # Agar brute-force ke baad successful login bhi hua = Critical (compromise)
            last_fail_time = burst[-1]["time"]
            compromised = any(a["time"] >= last_fail_time for a in accepted_by_ip.get(ip, []))

            if compromised:
                severity = "CRITICAL"
            elif best["count"] >= threshold * 3:
                severity = "HIGH"
            else:
                severity = "MEDIUM"

            alerts.append({
                "ip": ip,
                "attempts_in_window": best["count"],
                "total_failed": total_failed,
                "first_seen": burst[0]["time"],
                "last_seen": burst[-1]["time"],
                "users_targeted": ", ".join(users),
                "severity": severity,
                "compromised": "YES" if compromised else "NO",
            })

    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2}
    alerts.sort(key=lambda a: (order[a["severity"]], -a["attempts_in_window"]))
    return alerts


def top_attackers(events, n=10):
    counts = defaultdict(int)
    for e in events:
        if e["status"] == "FAILED":
            counts[e["ip"]] += 1
    return sorted(counts.items(), key=lambda x: x[1], reverse=True)[:n]


def attempts_per_minute(events):
    buckets = defaultdict(int)
    for e in events:
        if e["status"] == "FAILED":
            key = e["time"].replace(second=0)
            buckets[key] += 1
    keys = sorted(buckets)
    return keys, [buckets[k] for k in keys]