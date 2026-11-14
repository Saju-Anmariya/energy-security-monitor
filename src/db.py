"""
Energy Security Monitor - Phase 4: database access shared by the dashboard and the API.

All queries use parameters (the ? marks) and never build SQL from user text,
which protects against SQL injection.
"""

import sqlite3
from pathlib import Path

import pandas as pd

DB_PATH = Path(__file__).resolve().parent.parent / "data" / "monitor.db"

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


def connect(db_path=None):
    """Open the database READ-ONLY: the dashboard and API can never change data."""
    db_path = Path(db_path or DB_PATH)
    if not db_path.exists():
        raise FileNotFoundError(
            f"{db_path} not found. Run 'python src/severity.py' first to create it.")
    return sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)


def get_alerts(db_path=None, severity=None, alert_type=None, limit=1000):
    """Return alerts as a DataFrame, newest severity first. Filters are optional lists."""
    query = "SELECT * FROM alerts WHERE 1=1"
    params = []
    if severity:
        query += f" AND severity IN ({','.join('?' * len(severity))})"
        params += list(severity)
    if alert_type:
        query += f" AND alert_type IN ({','.join('?' * len(alert_type))})"
        params += list(alert_type)
    query += " ORDER BY severity_score DESC, start ASC LIMIT ?"
    params.append(int(limit))
    with connect(db_path) as conn:
        return pd.read_sql_query(query, conn, params=params)


def get_alert(alert_id, db_path=None):
    with connect(db_path) as conn:
        df = pd.read_sql_query("SELECT * FROM alerts WHERE id = ?", conn, params=[int(alert_id)])
    return None if df.empty else df.iloc[0].to_dict()


def summary(db_path=None):
    """Counts for the top of the dashboard."""
    df = get_alerts(db_path)
    by_severity = df["severity"].value_counts().to_dict()
    return {
        "total": int(len(df)),
        "by_severity": {level: int(by_severity.get(level, 0)) for level in SEVERITY_ORDER},
        "nis2_assess": int(df["nis2_assess"].sum()),
    }


def alerts_per_day(df):
    """Table for the 'alerts over time' chart: one row per day, one column per attack type."""
    if df.empty:
        return pd.DataFrame()
    days = pd.to_datetime(df["start"]).dt.strftime("%Y-%m-%d")
    return df.groupby([days, "alert_type"]).size().unstack(fill_value=0)


def alerts_by_severity(df):
    counts = df["severity"].value_counts()
    return pd.Series({level: int(counts.get(level, 0)) for level in SEVERITY_ORDER}, name="alerts")


def top_source_ips(df, n=10):
    """Highest-scoring source IPs (one row per IP)."""
    if df.empty:
        return pd.Series(dtype=int)
    return (df.groupby("source_ip")["severity_score"].max()
              .sort_values(ascending=False).head(n))
