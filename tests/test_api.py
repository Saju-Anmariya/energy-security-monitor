import pandas as pd
import pytest
from fastapi.testclient import TestClient

import api
import db
from helpers import auth_df
from severity import enrich, save_to_db


@pytest.fixture
def client(tmp_path, monkeypatch):
    night = pd.Timestamp("2026-11-02 03:00:00")
    auth = auth_df([(night, "user01", "admin", "45.1.1.1", "RU", 1)])
    alerts = pd.DataFrame([
        {"alert_type": "suspicious_admin_login", "source_ip": "45.1.1.1", "start": night, "end": night, "evidence": 1},
        {"alert_type": "port_scan", "source_ip": "2.2.2.2", "start": night, "end": night, "evidence": 60},
    ])
    path = tmp_path / "test.db"
    save_to_db(enrich(alerts, auth), path)
    monkeypatch.setattr(db, "DB_PATH", path)
    return TestClient(api.app)


def test_health(client):
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_security_headers_are_sent(client):
    headers = client.get("/health").headers
    assert headers["x-content-type-options"] == "nosniff"
    assert headers["x-frame-options"] == "DENY"
    assert headers["cache-control"] == "no-store"


def test_security_headers_are_also_sent_on_errors(client):
    response = client.get("/alerts/9999")
    assert response.status_code == 404
    assert response.headers["x-content-type-options"] == "nosniff"


def test_list_alerts(client):
    response = client.get("/alerts")
    assert response.status_code == 200
    assert len(response.json()) == 2


def test_filter_by_severity(client):
    data = client.get("/alerts", params={"severity": "critical"}).json()
    assert len(data) == 1 and data[0]["alert_type"] == "suspicious_admin_login"


def test_invalid_severity_is_rejected(client):
    assert client.get("/alerts", params={"severity": "banana"}).status_code == 422


def test_invalid_limit_is_rejected(client):
    assert client.get("/alerts", params={"limit": 0}).status_code == 422
    assert client.get("/alerts", params={"limit": 100000}).status_code == 422


def test_sql_injection_in_filter_is_rejected(client):
    response = client.get("/alerts", params={"alert_type": "x'; DROP TABLE alerts;--"})
    assert response.status_code == 422


def test_get_single_alert(client):
    assert client.get("/alerts/1").json()["alert_type"] == "suspicious_admin_login"


def test_unknown_alert_gives_404(client):
    assert client.get("/alerts/9999").status_code == 404


def test_non_numeric_id_is_rejected(client):
    assert client.get("/alerts/abc").status_code == 422


def test_summary(client):
    assert client.get("/summary").json()["total"] == 2


def test_missing_database_gives_503(tmp_path, monkeypatch):
    monkeypatch.setattr(db, "DB_PATH", tmp_path / "missing.db")
    assert TestClient(api.app).get("/alerts").status_code == 503
