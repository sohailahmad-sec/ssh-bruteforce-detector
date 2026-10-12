# 🛡️ SSH Brute-Force Detector

A Python desktop tool that analyzes SSH authentication logs and detects **brute-force attacks** (MITRE ATT&CK **T1110**). It flags IP addresses with repeated failed logins inside a configurable time window and highlights the most dangerous case: **a successful login after multiple failures**.

Built as a blue-team / SOC learning project

## ✨ Features

- **Configurable detection rule**: alert when one IP has at least *N* failed logins within *M* minutes (default: 5 failures in 2 minutes)
- **Compromise indicator**: shows *Login succeeded: YES* when an attacker got in after failing
- **Severity and threat level** (e.g. `CRITICAL`) based on the activity
- **Alert details** per source IP: attempts, failed count, usernames tried, first/last seen
- **Recommended response** shown for each alert
- **Raw Events tab** to inspect every parsed log entry
- **Charts**: top attacker IPs and failed login attempts per minute
- **Export to CSV** for reports and evidence
- **Built-in sample log generator** so you can try it without a real server

---

## 🖥️ How it works

```
auth log  →  parser  →  detection rule (IP + time window)  →  alerts  →  dashboard / CSV
```

1. Load an SSH authentication log (or generate a sample one)
2. Set the rule (failed logins and time window)
3. Click **RUN DETECTION**
4. Review alerts, details and the recommended response

---

## 📁 Project structure

```
ssh_bruteforce_detector/
├── core/                  # detection and parsing logic
├── gui/                   # dashboard interface
├── data/                  # sample / test logs
├── main.py                # entry point
├── mini_ssh_server.py     # local test helper (localhost only)
├── brute_force_test.py    # local test helper (localhost only)
├── requirements.txt
└── README.md
```

---

## 🚀 Getting started

```bash
git clone https://github.com/sohailahmad-sec/ssh-bruteforce-detector.git
cd ssh-bruteforce-detector
pip install -r requirements.txt
python main.py
```

Then click **Generate Sample Log** and **RUN DETECTION**.

To analyze a real log, click **Open Log File** and choose your authentication log, for example:

| System | Typical log path |
|---|---|
| Ubuntu / Debian | `/var/log/auth.log` |
| CentOS / RHEL | `/var/log/secure` |

---

## 🧪 Testing on your own machine

`mini_ssh_server.py` and `brute_force_test.py` let you simulate failed logins against **your own computer (localhost)** to see the detector react.

> ⚠️ **Only run them on `127.0.0.1` / systems you own.** Never aim them at anyone else's server.

---

## 🔎 What an alert tells you

| Field | Meaning |
|---|---|
| Source IP | Where the attempts came from (may be a VPN or proxy) |
| Attempts / Failed | How many tries, and how many failed |
| Users | Usernames the attacker tried |
| First / Last seen | The attack window |
| Login succeeded | Whether a login worked after the failures |
| MITRE ATT&CK | T1110: Brute Force |

---

## ⚠️ Limitations

- Works on SSH authentication logs only
- Detects and reports; it does **not** block IPs automatically
- The source IP may belong to a VPN, so it does not reveal the attacker's real location
- A slow attack that stays under the threshold can go unnoticed

## 🗺️ Roadmap

- [ ] Automatic IP blocking (Fail2ban-style)
- [ ] Email / Telegram alerts
- [ ] IP reputation lookup (AbuseIPDB)
- [ ] Combine with port-scan detection to catch full attack chains

---

## 🛠️ Tech

Python · Tkinter · Matplotlib

## ⚖️ Disclaimer

For **learning and authorized use only**. Analyze logs from systems you own or are permitted to monitor.

## 👤 Author

**Sohail Ahmad**
Aspiring SOC Analyst | Python | Log Analysis & Threat Detection
GitHub: [@sohailahmad-sec](https://github.com/sohailahmad-sec)
