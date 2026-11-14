"""Small helpers that build fake log data for the tests."""

import pandas as pd

T0 = pd.Timestamp("2026-11-02 10:00:00")


def auth_df(rows):
    """rows: list of (timestamp, username, role, source_ip, country, success)."""
    return pd.DataFrame(rows, columns=["timestamp", "username", "role", "source_ip", "country", "success"])


def network_df(rows):
    """rows: list of (timestamp, source_ip, dest_ip, dest_port)."""
    df = pd.DataFrame(rows, columns=["timestamp", "source_ip", "dest_ip", "dest_port"])
    df["protocol"] = "TCP"
    df["action"] = "blocked"
    return df


def failed_logins(ip, users, count, seconds_apart, start=T0):
    """`count` failed logins from one IP, cycling through the given usernames."""
    return [(start + pd.Timedelta(seconds=i * seconds_apart), users[i % len(users)],
             "employee", ip, "RU", 0) for i in range(count)]
