import sqlite3

import pandas as pd
import pytest

import db
from helpers import auth_df
from severity import enrich, save_to_db


@pytest.fixture
def database(tmp_path):
    """A small throw-away database with four alerts."""
    night = pd.Timestamp("2026-11-02 03:00:00")
    auth = auth_df([(night, "user01", "admin", "45.1.1.1", "RU", 1)])
    alerts = pd.DataFrame([
        {"alert_type": "suspicious_admin_login", "source_ip": "45.1.1.1", "start": night, "end": night, "evidence": 1},
        {"alert_type": "brute_force", "source_ip": "1.1.1.1", "start": night, "end": night, "evidence": 60},
        {"alert_type": "port_scan", "source_ip": "2.2.2.2", "start": night, "end": night, "evidence": 60},
        {"alert_type": "port_scan", "source_ip": "3.3.3.3", "start": night, "end": night, "evidence": 300},
    ])
    path = tmp_path / "test.db"
    save_to_db(enrich(alerts, auth), path)
    return path


def test_get_alerts_returns_everything_sorted_by_score(database):
    df = db.get_alerts(database)
    assert len(df) == 4
    assert df["severity_score"].is_monotonic_decreasing


def test_filter_by_severity_and_type(database):
    assert set(db.get_alerts(database, severity=["critical"])["alert_type"]) == {"suspicious_admin_login"}
    assert len(db.get_alerts(database, alert_type=["port_scan"])) == 2


def test_limit(database):
    assert len(db.get_alerts(database, limit=2)) == 2


def test_sql_injection_text_is_treated_as_plain_text(database):
    assert db.get_alerts(database, alert_type=["x'; DROP TABLE alerts;--"]).empty
    assert len(db.get_alerts(database)) == 4          # the table is still there


def test_get_alert_by_id(database):
    assert db.get_alert(1, database)["alert_type"] == "suspicious_admin_login"
    assert db.get_alert(9999, database) is None


def test_summary(database):
    summary = db.summary(database)
    assert summary["total"] == 4
    assert summary["by_severity"]["critical"] == 1
    assert summary["nis2_assess"] == 1


def test_database_is_read_only(database):
    with db.connect(database) as conn:
        with pytest.raises(sqlite3.OperationalError):
            conn.execute("DELETE FROM alerts")


def test_missing_database_gives_a_clear_error(tmp_path):
    with pytest.raises(FileNotFoundError):
        db.get_alerts(tmp_path / "does_not_exist.db")


def test_chart_tables(database):
    df = db.get_alerts(database)
    assert db.alerts_by_severity(df).to_dict() == {"critical": 1, "high": 0, "medium": 2, "low": 1}
    assert db.alerts_per_day(df).loc["2026-11-02"].sum() == 4
    assert db.top_source_ips(df, 1).index[0] == "45.1.1.1"
