"""
Energy Security Monitor - Phase 2: detection rules + evaluation.

Reads the simulated logs, applies four detection rules, and compares the
alerts with ground_truth.csv to measure how well the detector works.

Run:  python src/detect.py              (tuned rules)
      python src/detect.py --baseline   (first version of the rules)
"""

import sys
from collections import Counter
from pathlib import Path

import pandas as pd

DATA_DIR = Path(__file__).resolve().parent.parent / "data"

# ---------- settings of the rules ----------
# "baseline" = first version of the rules (simple thresholds, no exceptions)
# "tuned"    = improved version after we studied the false alarms and misses
PROFILES = {
    "baseline": {
        "brute_force": (20, pd.Timedelta(minutes=5)),     # (failed logins, time window)
        "spraying":    (10, pd.Timedelta(minutes=30)),    # (different accounts, time window)
        "port_scan":   (50, pd.Timedelta(minutes=2)),     # (different ports, time window)
        "trusted_countries": {"DE"},
        "night_login_needs_external_ip": False,
        "approved_scanners": set(),
    },
    "tuned": {
        "brute_force": (12, pd.Timedelta(minutes=20)),    # catches slower attacks
        "spraying":    (10, pd.Timedelta(hours=3)),
        "port_scan":   (50, pd.Timedelta(minutes=10)),
        "trusted_countries": {"DE", "AT", "FR", "NL", "CH"},   # business-trip countries
        "night_login_needs_external_ip": True,            # on-call work from the office is normal
        "approved_scanners": {"10.0.99.10"},              # IT vulnerability scanner
    },
}

NIGHT_START_HOUR = 22           # admin logins from 22:00 ...
NIGHT_END_HOUR = 6              # ... until 06:00 are unusual


def load_logs():
    auth = pd.read_csv(DATA_DIR / "auth_logs.csv", parse_dates=["timestamp"])
    network = pd.read_csv(DATA_DIR / "network_logs.csv", parse_dates=["timestamp"])
    truth = pd.read_csv(DATA_DIR / "ground_truth.csv", parse_dates=["start", "end"])
    return auth, network, truth


def sliding_window_alerts(df, group_cols, value_col, window, threshold, alert_type):
    """
    Generic 'burst' detector used by three rules.

    For each group (for example one source_ip), walk through the events in time
    order and check whether, inside any time window, the number of DISTINCT
    values in `value_col` reaches the threshold. If yes -> one alert.
    """
    alerts = []
    for group_key, g in df.groupby(group_cols):
        g = g.sort_values("timestamp")
        times = g["timestamp"].tolist()
        values = g[value_col].tolist()

        counter = Counter()
        left = 0
        alert_start = None
        alert_end = None
        peak = 0

        for right in range(len(times)):
            counter[values[right]] += 1
            # move the left edge until the window is short enough
            while times[right] - times[left] > window:
                counter[values[left]] -= 1
                if counter[values[left]] == 0:
                    del counter[values[left]]
                left += 1

            if len(counter) >= threshold:
                if alert_start is None:
                    alert_start = times[left]
                alert_end = times[right]
                peak = max(peak, len(counter))

        if alert_start is not None:
            key = group_key if isinstance(group_key, tuple) else (group_key,)
            alerts.append({
                "alert_type": alert_type,
                "source_ip": key[0],
                "start": alert_start,
                "end": alert_end,
                "evidence": peak,
            })
    return alerts


def detect_brute_force(auth, cfg):
    failed = auth[auth["success"] == 0].copy()
    # every failed attempt counts as its own event
    failed["attempt_id"] = range(len(failed))
    threshold, window = cfg["brute_force"]
    return sliding_window_alerts(
        failed, ["source_ip", "username"], "attempt_id",
        window, threshold, "brute_force")


def detect_password_spraying(auth, cfg):
    failed = auth[auth["success"] == 0]
    threshold, window = cfg["spraying"]
    return sliding_window_alerts(
        failed, ["source_ip"], "username",
        window, threshold, "password_spraying")


def detect_port_scan(network, cfg):
    # ignore traffic from approved internal scanners
    network = network[~network["source_ip"].isin(cfg["approved_scanners"])]
    threshold, window = cfg["port_scan"]
    return sliding_window_alerts(
        network, ["source_ip", "dest_ip"], "dest_port",
        window, threshold, "port_scan")


def detect_suspicious_admin_login(auth, cfg):
    ok = auth[(auth["success"] == 1) & (auth["role"] == "admin")]
    hour = ok["timestamp"].dt.hour
    at_night = (hour >= NIGHT_START_HOUR) | (hour < NIGHT_END_HOUR)
    if cfg["night_login_needs_external_ip"]:
        at_night = at_night & ~ok["source_ip"].str.startswith("10.")
    from_abroad = ~ok["country"].isin(cfg["trusted_countries"])
    suspicious = ok[at_night | from_abroad]
    return [{
        "alert_type": "suspicious_admin_login",
        "source_ip": row["source_ip"],
        "start": row["timestamp"],
        "end": row["timestamp"],
        "evidence": 1,
    } for _, row in suspicious.iterrows()]


def run_all_rules(auth, network, cfg):
    alerts = []
    alerts += detect_brute_force(auth, cfg)
    alerts += detect_password_spraying(auth, cfg)
    alerts += detect_port_scan(network, cfg)
    alerts += detect_suspicious_admin_login(auth, cfg)
    return pd.DataFrame(alerts).sort_values("start").reset_index(drop=True)


def evaluate(alerts, truth):
    """
    An alert is correct (true positive) if there is a planted attack with the
    same type AND the same source IP.
    """
    truth_keys = set(zip(truth["attack_type"], truth["source_ip"]))
    alert_keys = set(zip(alerts["alert_type"], alerts["source_ip"]))

    found = truth_keys & alert_keys
    missed = truth_keys - alert_keys
    false_alarms = alert_keys - truth_keys

    detection_rate = len(found) / len(truth_keys) * 100
    precision = len(found) / len(alert_keys) * 100 if alert_keys else 0

    print("=== Detection results ===")
    print(f"Planted attacks:   {len(truth_keys)}")
    print(f"Alerts raised:     {len(alert_keys)}")
    print(f"Attacks found:     {len(found)}  (detection rate {detection_rate:.0f}%)")
    print(f"Attacks missed:    {len(missed)}")
    print(f"False alarms:      {len(false_alarms)}  (precision {precision:.0f}%)")

    print("\nBy attack type:")
    for attack_type in sorted(truth["attack_type"].unique()):
        planted = {k for k in truth_keys if k[0] == attack_type}
        hit = {k for k in found if k[0] == attack_type}
        print(f"  {attack_type:<24} {len(hit)}/{len(planted)} found")

    print("\nBy attack style:")
    for style in ["obvious", "slow", "very_slow"]:
        rows = truth[truth["style"] == style]
        keys = set(zip(rows["attack_type"], rows["source_ip"]))
        if keys:
            print(f"  {style:<24} {len(keys & found)}/{len(keys)} found")

    if missed:
        print("\nMissed:", sorted(missed))
    if false_alarms:
        print("False alarms:", sorted(false_alarms))


def main():
    profile = "baseline" if "--baseline" in sys.argv else "tuned"
    cfg = PROFILES[profile]
    auth, network, truth = load_logs()
    alerts = run_all_rules(auth, network, cfg)

    print(f"Rule set: {profile}")
    print(f"{len(alerts)} alerts raised\n")
    print(alerts.to_string(index=False))
    print()
    evaluate(alerts, truth)

    alerts.to_csv(DATA_DIR / "alerts.csv", index=False)


if __name__ == "__main__":
    main()
