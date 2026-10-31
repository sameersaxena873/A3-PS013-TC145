"""Synthetic test data generator for the 3 mandatory PS-013 scenarios.
Run:  python generate_testdata.py   (test-data folder ke andar)
"""
import os
from datetime import datetime, timedelta

def auth(ts, msg, host="srv1", proc="sshd[1201]"):
    return f"{ts.strftime('%b')} {ts.day:2d} {ts.strftime('%H:%M:%S')} {host} {proc}: {msg}"

def web(ts, ip, req, status, size=512, ua="Mozilla/5.0", user="-"):
    return f'{ip} - {user} [{ts.strftime("%d/%b/%Y:%H:%M:%S")} +0000] "{req} HTTP/1.1" {status} {size} "-" "{ua}"'

def write(path, lines):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="\n") as f:
        f.write("\n".join(lines) + "\n")

t0 = datetime(2026, 10, 20, 10, 0, 0)

# ---- Scenario 1: SSH brute force then success (+2 malformed lines => parsing gaps)
s1 = [auth(t0 - timedelta(minutes=5), "Accepted publickey for deploy from 198.51.100.7 port 50111 ssh2")]
for i in range(8):
    user = ["root", "admin", "oracle", "test"][i % 4]
    s1.append(auth(t0 + timedelta(seconds=3 * i), f"Failed password for invalid user {user} from 203.0.113.45 port {40000 + i} ssh2"))
s1.append("this line is corrupted and cannot be parsed")
s1.append(auth(t0 + timedelta(seconds=30), "Accepted password for admin from 203.0.113.45 port 40010 ssh2"))
s1.append("Oct 32 25:61:00 srv1 sshd[1201]: impossible timestamp")
s1.append(auth(t0 + timedelta(minutes=2), "Disconnected from user admin 203.0.113.45 port 40010", proc="sshd[1230]"))
write("scenario-1/auth.log", s1)

# ---- Scenario 2: web attack (SQLi-like + path scanning)
s2 = []
for i in range(5):
    s2.append(web(t0 + timedelta(seconds=10 * i), "192.0.2.10", "GET /index.html", 200, 1024))
sqli = ["/products?id=1' OR '1'='1", "/products?id=1 UNION SELECT username,password FROM users--",
        "/login?user=admin'--", "/search?q=1;SELECT SLEEP(5)"]
for i, p in enumerate(sqli):
    s2.append(web(t0 + timedelta(seconds=60 + 2 * i), "198.18.0.99", f"GET {p.replace(' ', '%20')}", 500, 200, "sqlmap/1.7"))
for i, p in enumerate(["/.env", "/wp-login.php", "/phpmyadmin/", "/admin", "/.git/config", "/../../etc/passwd"]):
    s2.append(web(t0 + timedelta(seconds=90 + i), "198.18.0.99", f"GET {p}", 404, 150, "Nikto/2.5"))
s2.append("malformed access log entry")
write("scenario-2/access.log", s2)

# ---- Scenario 3: clock skew. auth server clock is 120 s AHEAD, web server correct.
true = datetime(2026, 10, 20, 10, 0, 0)
skew = timedelta(seconds=120)
s3a = [auth(true + timedelta(seconds=5) + skew, "Failed password for root from 203.0.113.77 port 41000 ssh2"),
       auth(true + timedelta(seconds=15) + skew, "Accepted password for root from 203.0.113.77 port 41001 ssh2")]
s3b = [web(true, "203.0.113.77", "GET /login", 200),
       web(true + timedelta(seconds=10), "203.0.113.77", "POST /login", 200),
       web(true + timedelta(seconds=30), "203.0.113.77", "GET /dashboard", 200)]
write("scenario-3/auth_serverA.log", s3a)
write("scenario-3/access_serverB.log", s3b)
print("Test data generated.")
