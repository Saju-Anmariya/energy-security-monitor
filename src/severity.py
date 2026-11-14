"""
Energy Security Monitor - Phase 3: severity scoring, MITRE ATT&CK mapping, SQLite storage.

Takes the alerts from detect.py and adds:
  - a severity score (0-100) and level: low / medium / high / critical
  - the MITRE ATT&CK technique and tactic
  - a recommended action
  - a flag for alerts that must be assessed for NIS2 incident reporting
Then stores everything in a SQLite database (data/monitor.db).

Run:  python src/severity.py
"""

import sqlite3
from pathlib import Path

import pandas as pd

from detect import PROFILES, load_logs, run_all_rules

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
DB_PATH = DATA_DIR / "monitor.db"

# ---------- knowledge about each attack type ----------
# base score = how dangerous this kind of event is on its own
ATTACK_INFO = {
    "port_scan": {
        "base": 30,
        "mitre_id": "T1595",
        "mitre_name": "Active Scanning",
        "tactic": "Reconnaissance",
        "action": "Block the source IP at the firewall and check whether the scanned server exposes unneeded ports.",
    },
    "brute_force": {
        "base": 45,
        "mitre_id": "T1110.001",
        "mitre_name": "Brute Force: Password Guessing",
        "tactic": "Credential Access",
        "action": "Block the source IP, check the targeted account for a successful login, and enforce MFA.",
    },
    "password_spraying": {
        "base": 55,
        "mitre_id": "T1110.003",
        "mitre_name": "Brute Force: Password Spraying",
        "tactic": "Credential Access",
        "action": "Block the source IP, review all targeted accounts, and reset weak passwords.",
    },
    "suspicious_admin_login": {
        "base": 85,
        "mitre_id": "T1078",
        "mitre_name": "Valid Accounts",
        "tactic": "Initial Access",
        "action": "Treat as possible account takeover: disable the admin session, reset credentials, review admin actions.",
    },
}

# ---------- scoring modifiers ----------
TRUSTED_COUNTRIES = PROFILES["tuned"]["trusted_countries"]


def score_alert(alert, auth):
    """Return (score, list_of_reasons). Every point has a written reason."""
    info = ATTACK_INFO[alert["alert_type"]]
    score = info["base"]
    reasons = [f"base {info['base']} for {alert['alert_type']}"]
    kind = alert["alert_type"]
    evidence = alert["evidence"]

    if kind == "port_scan" and evidence >= 200:
        score += 15
        reasons.append("+15 very broad scan (200+ ports)")
    if kind == "brute_force" and evidence >= 50:
        score += 10
        reasons.append("+10 very intense attack (50+ attempts)")
    if kind == "password_spraying" and evidence >= 20:
        score += 10
        reasons.append("+10 many accounts targeted (20+)")

    if kind == "suspicious_admin_login":
        row = auth[(auth["source_ip"] == alert["source_ip"]) & (auth["timestamp"] == alert["start"])]
        if not row.empty and row.iloc[0]["country"] not in TRUSTED_COUNTRIES:
            score += 10
            reasons.append("+10 login from a non-trusted country")
        hour = alert["start"].hour
        if hour >= 22 or hour < 6:
            score += 5
            reasons.append("+5 login at night")

    # an attacker who succeeds after failing is the worst case
    later_success = auth[(auth["source_ip"] == alert["source_ip"]) &
                         (auth["success"] == 1) &
                         (auth["timestamp"] >= alert["start"]) &
                         (kind != "suspicious_admin_login")]
    if not later_success.empty:
        score += 30
        reasons.append("+30 same IP logged in successfully afterwards")

    return min(score, 100), reasons


def level_from_score(score):
    if score >= 80:
        return "critical"
    if score >= 60:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def enrich(alerts, auth):
    rows = []
    for _, a in alerts.iterrows():
        score, reasons = score_alert(a, auth)
        level = level_from_score(score)
        info = ATTACK_INFO[a["alert_type"]]
        rows.append({
            **a.to_dict(),
            "severity_score": score,
            "severity": level,
            "mitre_id": info["mitre_id"],
            "mitre_name": info["mitre_name"],
            "tactic": info["tactic"],
            "recommended_action": info["action"],
            "score_reasons": "; ".join(reasons),
            "nis2_assess": 1 if level in ("high", "critical") else 0,
        })
    return pd.DataFrame(rows).sort_values(["severity_score", "start"], ascending=[False, True]).reset_index(drop=True)


def save_to_db(df, path=DB_PATH):
    """Rewrite the alerts table (a fresh run replaces the old one)."""
    out = df.copy()
    out["start"] = out["start"].dt.strftime("%Y-%m-%d %H:%M:%S")
    out["end"] = out["end"].dt.strftime("%Y-%m-%d %H:%M:%S")
    with sqlite3.connect(path) as conn:
        conn.execute("DROP TABLE IF EXISTS alerts")
        conn.execute("""
            CREATE TABLE alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                alert_type TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                start TEXT NOT NULL,
                "end" TEXT NOT NULL,
                evidence INTEGER NOT NULL,
                severity_score INTEGER NOT NULL,
                severity TEXT NOT NULL,
                mitre_id TEXT NOT NULL,
                mitre_name TEXT NOT NULL,
                tactic TEXT NOT NULL,
                recommended_action TEXT NOT NULL,
                score_reasons TEXT NOT NULL,
                nis2_assess INTEGER NOT NULL
            )
        """)
        out.to_sql("alerts", conn, if_exists="append", index=False)


def main():
    auth, network, truth = load_logs()
    alerts = run_all_rules(auth, network, PROFILES["tuned"])
    enriched = enrich(alerts, auth)
    save_to_db(enriched)

    print(f"{len(enriched)} alerts saved to {DB_PATH.name}\n")

    print("Alerts by severity:")
    order = ["critical", "high", "medium", "low"]
    counts = enriched["severity"].value_counts()
    for level in order:
        print(f"  {level:<9} {counts.get(level, 0)}")

    print("\nTop 5 alerts:")
    cols = ["severity", "severity_score", "alert_type", "source_ip", "mitre_id"]
    print(enriched[cols].head(5).to_string(index=False))

    print(f"\nAlerts to assess for NIS2 reporting: {int(enriched['nis2_assess'].sum())}")

    print("\nExample - why the top alert got its score:")
    top = enriched.iloc[0]
    print(f"  {top['alert_type']} from {top['source_ip']}: {top['score_reasons']}")


if __name__ == "__main__":
    main()
