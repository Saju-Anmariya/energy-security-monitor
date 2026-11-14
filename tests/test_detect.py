import pandas as pd

from detect import (PROFILES, detect_brute_force, detect_password_spraying,
                    detect_port_scan, detect_suspicious_admin_login,
                    sliding_window_alerts)
from helpers import T0, auth_df, failed_logins, network_df

TUNED = PROFILES["tuned"]
BASELINE = PROFILES["baseline"]


# ---------- brute force ----------

def test_brute_force_is_detected():
    auth = auth_df(failed_logins("1.2.3.4", ["user05"], count=30, seconds_apart=5))
    alerts = detect_brute_force(auth, TUNED)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "brute_force"
    assert alerts[0]["source_ip"] == "1.2.3.4"


def test_forgetful_employee_is_not_flagged():
    # 8 typos in a row is normal, below the threshold of 12
    auth = auth_df(failed_logins("10.0.1.5", ["user07"], count=8, seconds_apart=30))
    assert detect_brute_force(auth, TUNED) == []


def test_slow_brute_force_needs_the_tuned_window():
    # 15 failures spread over 15 minutes: missed by baseline (5 min window), caught by tuned
    auth = auth_df(failed_logins("1.2.3.4", ["user05"], count=15, seconds_apart=60))
    assert detect_brute_force(auth, BASELINE) == []
    assert len(detect_brute_force(auth, TUNED)) == 1


def test_successful_logins_are_ignored_by_brute_force():
    rows = [(T0 + pd.Timedelta(seconds=i), "user05", "employee", "1.2.3.4", "DE", 1) for i in range(50)]
    assert detect_brute_force(auth_df(rows), TUNED) == []


# ---------- password spraying ----------

def test_password_spraying_is_detected():
    users = [f"user{i:02d}" for i in range(1, 16)]
    auth = auth_df(failed_logins("5.6.7.8", users, count=15, seconds_apart=120))
    alerts = detect_password_spraying(auth, TUNED)
    assert len(alerts) == 1
    assert alerts[0]["evidence"] >= 10


def test_many_failures_on_one_account_are_not_spraying():
    auth = auth_df(failed_logins("5.6.7.8", ["user01"], count=40, seconds_apart=10))
    assert detect_password_spraying(auth, TUNED) == []


# ---------- port scan ----------

def _scan_rows(ip, ports, seconds_apart):
    return [(T0 + pd.Timedelta(seconds=i * seconds_apart), ip, "10.0.10.5", p)
            for i, p in enumerate(ports)]


def test_port_scan_is_detected():
    net = network_df(_scan_rows("9.9.9.9", range(1, 101), seconds_apart=1))
    alerts = detect_port_scan(net, TUNED)
    assert len(alerts) == 1
    assert alerts[0]["source_ip"] == "9.9.9.9"


def test_normal_traffic_to_few_ports_is_not_a_scan():
    net = network_df(_scan_rows("10.0.1.5", [443, 80, 22] * 30, seconds_apart=2))
    assert detect_port_scan(net, TUNED) == []


def test_approved_scanner_is_ignored_in_tuned_but_not_in_baseline():
    net = network_df(_scan_rows("10.0.99.10", range(1, 301), seconds_apart=0.1))
    assert len(detect_port_scan(net, BASELINE)) == 1
    assert detect_port_scan(net, TUNED) == []


# ---------- suspicious admin logins ----------

def admin_login(hour, ip, country, role="admin"):
    ts = pd.Timestamp(f"2026-11-02 {hour:02d}:30:00")
    return auth_df([(ts, "user01", role, ip, country, 1)])


def test_night_login_from_abroad_is_flagged():
    assert len(detect_suspicious_admin_login(admin_login(3, "45.1.1.1", "RU"), TUNED)) == 1


def test_daytime_login_from_untrusted_country_is_flagged():
    assert len(detect_suspicious_admin_login(admin_login(11, "45.1.1.1", "CN"), TUNED)) == 1


def test_trusted_country_in_daytime_is_not_flagged():
    assert detect_suspicious_admin_login(admin_login(11, "45.1.1.1", "FR"), TUNED) == []


def test_oncall_night_login_from_office_network():
    office_night = admin_login(23, "10.0.0.7", "DE")
    assert len(detect_suspicious_admin_login(office_night, BASELINE)) == 1   # false alarm before tuning
    assert detect_suspicious_admin_login(office_night, TUNED) == []          # fixed by tuning


def test_normal_employee_night_login_is_ignored():
    assert detect_suspicious_admin_login(admin_login(3, "45.1.1.1", "RU", role="employee"), TUNED) == []


# ---------- the generic window function ----------

def test_events_outside_the_window_do_not_add_up():
    # 12 failures but two hours apart: never 12 inside one 20-minute window
    auth = auth_df(failed_logins("1.2.3.4", ["user05"], count=12, seconds_apart=7200))
    assert detect_brute_force(auth, TUNED) == []


def test_sliding_window_counts_distinct_values():
    df = pd.DataFrame({"timestamp": [T0 + pd.Timedelta(seconds=i) for i in range(10)],
                       "ip": ["a"] * 10, "port": [1, 1, 1, 2, 2, 2, 3, 3, 3, 3]})
    alerts = sliding_window_alerts(df, ["ip"], "port", pd.Timedelta(minutes=1), 3, "test")
    assert len(alerts) == 1 and alerts[0]["evidence"] == 3
    assert sliding_window_alerts(df, ["ip"], "port", pd.Timedelta(minutes=1), 4, "test") == []
