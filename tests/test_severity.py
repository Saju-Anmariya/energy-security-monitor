import pandas as pd

from helpers import T0, auth_df
from severity import enrich, level_from_score, score_alert

EMPTY_AUTH = auth_df([])


def make_alert(alert_type, evidence=1, ip="1.2.3.4", start=T0):
    return {"alert_type": alert_type, "source_ip": ip, "start": start, "end": start, "evidence": evidence}


def test_level_boundaries():
    assert level_from_score(0) == "low"
    assert level_from_score(39) == "low"
    assert level_from_score(40) == "medium"
    assert level_from_score(59) == "medium"
    assert level_from_score(60) == "high"
    assert level_from_score(79) == "high"
    assert level_from_score(80) == "critical"
    assert level_from_score(100) == "critical"


def test_base_scores_rank_the_attack_types():
    scores = {t: score_alert(make_alert(t), EMPTY_AUTH)[0]
              for t in ["port_scan", "brute_force", "password_spraying"]}
    assert scores["port_scan"] < scores["brute_force"] < scores["password_spraying"]


def test_broad_port_scan_scores_higher():
    small = score_alert(make_alert("port_scan", evidence=60), EMPTY_AUTH)[0]
    broad = score_alert(make_alert("port_scan", evidence=300), EMPTY_AUTH)[0]
    assert broad == small + 15


def test_intense_brute_force_scores_higher():
    assert (score_alert(make_alert("brute_force", evidence=100), EMPTY_AUTH)[0]
            == score_alert(make_alert("brute_force", evidence=15), EMPTY_AUTH)[0] + 10)


def test_admin_login_at_night_from_untrusted_country_is_capped_at_100():
    night = pd.Timestamp("2026-11-02 03:00:00")
    auth = auth_df([(night, "user01", "admin", "45.1.1.1", "RU", 1)])
    score, reasons = score_alert(make_alert("suspicious_admin_login", ip="45.1.1.1", start=night), auth)
    assert score == 100            # 85 + 10 + 5 = 100
    assert any("night" in r for r in reasons)
    assert any("non-trusted" in r for r in reasons)


def test_every_point_has_a_reason():
    score, reasons = score_alert(make_alert("port_scan", evidence=300), EMPTY_AUTH)
    assert len(reasons) == 2       # base + broad scan
    assert reasons[0].startswith("base")


def test_later_successful_login_adds_30():
    later = T0 + pd.Timedelta(minutes=10)
    auth = auth_df([(later, "user05", "employee", "1.2.3.4", "RU", 1)])
    with_success = score_alert(make_alert("brute_force"), auth)[0]
    without = score_alert(make_alert("brute_force"), EMPTY_AUTH)[0]
    assert with_success == without + 30


def test_enrich_adds_columns_and_nis2_flag():
    night = pd.Timestamp("2026-11-02 03:00:00")
    auth = auth_df([(night, "user01", "admin", "45.1.1.1", "RU", 1)])
    alerts = pd.DataFrame([
        make_alert("suspicious_admin_login", ip="45.1.1.1", start=night),
        make_alert("port_scan", evidence=60),
    ])
    result = enrich(alerts, auth)
    for column in ["severity_score", "severity", "mitre_id", "tactic", "recommended_action", "nis2_assess"]:
        assert column in result.columns
    assert result.iloc[0]["severity"] == "critical"          # sorted by score, highest first
    assert result.iloc[0]["nis2_assess"] == 1
    assert result.iloc[1]["nis2_assess"] == 0
