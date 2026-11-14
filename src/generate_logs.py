"""
Energy Security Monitor - Phase 1: simulated log generator.

Creates three CSV files in ./data (now with realistic noise and stealthy attacks):
  auth_logs.csv     - login attempts (normal + attacks)
  network_logs.csv  - network connections (normal + attacks)
  ground_truth.csv  - the attacks we planted (used later to measure detection rate)

All data is SIMULATED. No real company or person is involved.
Run:  python src/generate_logs.py
"""

import csv
import random
from datetime import datetime, timedelta
from pathlib import Path

SEED = 42                      # same seed = same data every run (reproducible)
DAYS = 7                       # length of the simulated period
START = datetime(2026, 11, 1)  # first simulated day
SCANNER_IP = "10.0.99.10"   # approved IT vulnerability scanner
DATA_DIR = Path(__file__).resolve().parent.parent / "data"

random.seed(SEED)


# ---------- helpers ----------

def random_external_ip():
    """A random public-looking IP address (simulated)."""
    return f"{random.choice([45, 91, 103, 185, 194])}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"


def random_internal_ip():
    return f"10.0.{random.randint(0, 5)}.{random.randint(2, 250)}"


def random_time_on_day(day, hour_from, hour_to):
    seconds = random.randint(hour_from * 3600, hour_to * 3600 - 1)
    return day + timedelta(seconds=seconds)


# ---------- users ----------

def build_users():
    """40 employees: 4 admins, 36 normal users. Each has a fixed office IP."""
    users = []
    for i in range(1, 41):
        users.append({
            "username": f"user{i:02d}",
            "role": "admin" if i <= 4 else "employee",
            "ip": random_internal_ip(),
            "country": "DE",
        })
    return users


# ---------- normal behaviour ----------

def normal_auth_logs(users):
    rows = []
    for d in range(DAYS):
        day = START + timedelta(days=d)
        is_weekend = day.weekday() >= 5
        for u in users:
            if is_weekend and random.random() < 0.85:
                continue  # most people do not work on weekends
            for _ in range(random.randint(1, 3)):
                ts = random_time_on_day(day, 7, 18)
                success = 1 if random.random() < 0.97 else 0  # occasional typo
                rows.append([ts, u["username"], u["role"], u["ip"], u["country"], success])
    return rows


def normal_network_logs(users):
    rows = []
    common_ports = [443, 443, 443, 80, 22, 8080, 3389, 53]
    servers = [f"10.0.10.{n}" for n in range(2, 12)]
    for d in range(DAYS):
        day = START + timedelta(days=d)
        for u in users:
            for _ in range(random.randint(20, 40)):
                ts = random_time_on_day(day, 7, 18)
                rows.append([ts, u["ip"], random.choice(servers),
                             random.choice(common_ports), "TCP", "allowed"])
    return rows


# ---------- planted attacks ----------

def attack_brute_force(users, attack_id):
    """One IP, one account, many failed logins in a few minutes."""
    ip = random_external_ip()
    target = random.choice(users)
    start = random_time_on_day(START + timedelta(days=random.randint(0, DAYS - 1)), 9, 22)
    attempts = random.randint(60, 150)
    rows = []
    for i in range(attempts):
        ts = start + timedelta(seconds=i * random.randint(1, 4))
        rows.append([ts, target["username"], target["role"], ip, random.choice(["RU", "CN", "BR", "VN"]), 0])
    end = rows[-1][0]
    return rows, [], [attack_id, "brute_force", "obvious", ip, start, end]


def attack_password_spraying(users, attack_id):
    """One IP, many accounts, only 1-2 tries each (stays under simple lockout limits)."""
    ip = random_external_ip()
    start = random_time_on_day(START + timedelta(days=random.randint(0, DAYS - 1)), 9, 22)
    targets = random.sample(users, random.randint(15, 30))
    rows = []
    t = start
    for u in targets:
        for _ in range(random.randint(1, 2)):
            t += timedelta(seconds=random.randint(20, 60))
            rows.append([t, u["username"], u["role"], ip, random.choice(["RU", "CN", "IR", "KP"]), 0])
    return rows, [], [attack_id, "password_spraying", "obvious", ip, start, t]


def attack_port_scan(attack_id):
    """One IP touching many different ports on a server within two minutes."""
    ip = random_external_ip()
    start = random_time_on_day(START + timedelta(days=random.randint(0, DAYS - 1)), 0, 24)
    target = f"10.0.10.{random.randint(2, 11)}"
    ports = random.sample(range(1, 10000), random.randint(100, 500))
    rows = []
    for i, port in enumerate(ports):
        ts = start + timedelta(milliseconds=i * random.randint(100, 250))
        rows.append([ts, ip, target, port, "TCP", random.choice(["blocked", "blocked", "allowed"])])
    return [], rows, [attack_id, "port_scan", "obvious", ip, start, rows[-1][0]]


def attack_suspicious_admin_login(users, attack_id, daytime=False):
    """Admin account logs in successfully at night from a foreign country."""
    admins = [u for u in users if u["role"] == "admin"]
    target = random.choice(admins)
    ip = random_external_ip()
    day = START + timedelta(days=random.randint(0, DAYS - 1))
    ts = random_time_on_day(day, 10, 16) if daytime else random_time_on_day(day, 2, 4)
    rows = [[ts, target["username"], "admin", ip, random.choice(["RU", "CN", "BR"]), 1]]
    return rows, [], [attack_id, "suspicious_admin_login", "obvious", ip, ts, ts]



# ---------- realistic noise (normal behaviour that LOOKS suspicious) ----------

def noise_clumsy_users(users):
    """Employees who forget their password: 5-9 failed tries, then success."""
    rows = []
    employees = [u for u in users if u["role"] == "employee"]
    for u in random.sample(employees, 4):
        for day_no in random.sample(range(DAYS), 2):
            day = START + timedelta(days=day_no)
            t = random_time_on_day(day, 8, 17)
            for _ in range(random.randint(5, 9)):
                t += timedelta(seconds=random.randint(20, 40))
                rows.append([t, u["username"], u["role"], u["ip"], "DE", 0])
            t += timedelta(seconds=30)
            rows.append([t, u["username"], u["role"], u["ip"], "DE", 1])
    return rows


def noise_traveling_admin(users):
    """An admin on a business trip logs in during the day from France."""
    admin = [u for u in users if u["username"] == "user02"][0]
    ip = random_external_ip()
    rows = []
    for day_no in (1, 2, 3):
        day = START + timedelta(days=day_no)
        rows.append([random_time_on_day(day, 9, 17), admin["username"], "admin", ip, "FR", 1])
    return rows


def noise_oncall_admin(users):
    """An admin on call logs in late in the evening from the office network."""
    admin = [u for u in users if u["username"] == "user01"][0]
    rows = []
    for day_no in (0, 2, 4):
        day = START + timedelta(days=day_no)
        rows.append([random_time_on_day(day, 23, 24), admin["username"], "admin", admin["ip"], "DE", 1])
    return rows


def noise_it_scanner():
    """The IT team's approved vulnerability scanner scans servers (looks like a port scan)."""
    ip = SCANNER_IP
    day = START + timedelta(days=3)
    start = random_time_on_day(day, 12, 13)
    rows = []
    for server in ("10.0.10.2", "10.0.10.3", "10.0.10.4"):
        for i, port in enumerate(range(1, 1025)):
            ts = start + timedelta(milliseconds=i * 60)
            rows.append([ts, ip, server, port, "TCP", "allowed"])
        start += timedelta(minutes=3)
    return rows


# ---------- stealthy attacks (slow, below the obvious limits) ----------

def attack_slow_brute_force(users, attack_id, attempts, minutes, style):
    """Same as brute force, but spread over many minutes."""
    ip = random_external_ip()
    target = random.choice(users)
    start = random_time_on_day(START + timedelta(days=random.randint(0, DAYS - 1)), 9, 20)
    step = minutes * 60 / attempts
    rows = []
    for i in range(attempts):
        ts = start + timedelta(seconds=int(i * step + random.randint(0, 10)))
        rows.append([ts, target["username"], target["role"], ip, random.choice(["RU", "CN", "BR"]), 0])
    return rows, [], [attack_id, "brute_force", style, ip, start, rows[-1][0]]


def attack_slow_spraying(users, attack_id):
    """Password spraying with one try every 6-10 minutes (about 1.5 hours total)."""
    ip = random_external_ip()
    start = random_time_on_day(START + timedelta(days=random.randint(0, DAYS - 1)), 8, 18)
    targets = random.sample(users, random.randint(12, 16))
    rows, t = [], start
    for u in targets:
        t += timedelta(minutes=random.randint(6, 10))
        rows.append([t, u["username"], u["role"], ip, random.choice(["RU", "CN", "IR"]), 0])
    return rows, [], [attack_id, "password_spraying", "slow", ip, start, t]


def attack_slow_port_scan(attack_id):
    """Port scan spread over 6-9 minutes."""
    ip = random_external_ip()
    start = random_time_on_day(START + timedelta(days=random.randint(0, DAYS - 1)), 0, 24)
    target = f"10.0.10.{random.randint(5, 11)}"
    ports = random.sample(range(1, 10000), random.randint(70, 120))
    minutes = random.randint(6, 9)
    step = minutes * 60 / len(ports)
    rows = []
    for i, port in enumerate(ports):
        ts = start + timedelta(seconds=int(i * step))
        rows.append([ts, ip, target, port, "TCP", random.choice(["blocked", "blocked", "allowed"])])
    return [], rows, [attack_id, "port_scan", "slow", ip, start, rows[-1][0]]

# ---------- main ----------

def write_csv(path, header, rows):
    rows.sort(key=lambda r: r[0])
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(header)
        for r in rows:
            writer.writerow([r[0].strftime("%Y-%m-%d %H:%M:%S")] + r[1:])


def main():
    DATA_DIR.mkdir(exist_ok=True)
    users = build_users()

    auth = normal_auth_logs(users)
    network = normal_network_logs(users)

    # normal behaviour that can look suspicious (tests for false alarms)
    auth += noise_clumsy_users(users)
    auth += noise_traveling_admin(users)
    auth += noise_oncall_admin(users)
    network += noise_it_scanner()

    truth = []
    attack_id = 1

    def add(result):
        nonlocal attack_id
        a, n, t = result
        auth.extend(a)
        network.extend(n)
        truth.append(t)
        attack_id += 1

    for _ in range(4):
        add(attack_brute_force(users, attack_id))
    for _ in range(3):
        add(attack_password_spraying(users, attack_id))
    for _ in range(4):
        add(attack_port_scan(attack_id))
    for i in range(3):
        add(attack_suspicious_admin_login(users, attack_id, daytime=(i == 2)))

    # stealthy attacks
    for _ in range(3):
        add(attack_slow_brute_force(users, attack_id, random.randint(15, 25), random.randint(12, 18), "slow"))
    add(attack_slow_brute_force(users, attack_id, 10, 90, "very_slow"))
    for _ in range(2):
        add(attack_slow_spraying(users, attack_id))
    for _ in range(2):
        add(attack_slow_port_scan(attack_id))

    write_csv(DATA_DIR / "auth_logs.csv",
              ["timestamp", "username", "role", "source_ip", "country", "success"], auth)
    write_csv(DATA_DIR / "network_logs.csv",
              ["timestamp", "source_ip", "dest_ip", "dest_port", "protocol", "action"], network)

    truth.sort(key=lambda r: r[4])
    with open(DATA_DIR / "ground_truth.csv", "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["attack_id", "attack_type", "style", "source_ip", "start", "end"])
        for t in truth:
            writer.writerow([t[0], t[1], t[2], t[3],
                             t[4].strftime("%Y-%m-%d %H:%M:%S"), t[5].strftime("%Y-%m-%d %H:%M:%S")])

    print(f"auth_logs.csv:    {len(auth):>6} rows")
    print(f"network_logs.csv: {len(network):>6} rows")
    print(f"ground_truth.csv: {len(truth):>6} planted attacks")


if __name__ == "__main__":
    main()
