"""
Energy Security Monitor - Phase 5: incident report generator.

Reads the alerts from the database and writes a security-team style report
(Markdown) with an executive summary, priority incidents and the NIS2 reporting
timeline for every incident that must be assessed.

Run:  python src/report.py        ->  reports/incident_report.md
"""

from pathlib import Path

import pandas as pd

import db
from detect import PROFILES, load_logs, run_all_rules

REPORT_DIR = Path(__file__).resolve().parent.parent / "reports"
REPORT_PATH = REPORT_DIR / "incident_report.md"

FMT = "%Y-%m-%d %H:%M"


def md_table(df, columns, headers):
    """Build a Markdown table from a DataFrame."""
    lines = ["| " + " | ".join(headers) + " |",
             "|" + "|".join("---" for _ in headers) + "|"]
    for _, row in df.iterrows():
        lines.append("| " + " | ".join(str(row[c]) for c in columns) + " |")
    return "\n".join(lines)


def nis2_deadlines(awareness):
    """
    NIS2 timeline for a significant incident (counted from the time the
    organisation becomes aware of it):
      - early warning:          within 24 hours
      - incident notification:  within 72 hours
      - final report:           within one month after the incident notification
    """
    early = awareness + pd.Timedelta(hours=24)
    notification = awareness + pd.Timedelta(hours=72)
    final = notification + pd.DateOffset(months=1)
    return early, notification, final


def detection_quality(alerts):
    """Detection rate and false alarms against the planted attacks (simulation only)."""
    _, _, truth = load_logs()
    truth_keys = set(zip(truth["attack_type"], truth["source_ip"]))
    alert_keys = set(zip(alerts["alert_type"], alerts["source_ip"]))
    found = truth_keys & alert_keys
    return {
        "planted": len(truth_keys),
        "found": len(found),
        "missed": len(truth_keys - alert_keys),
        "false_alarms": len(alert_keys - truth_keys),
        "rate": len(found) / len(truth_keys) * 100,
    }


def build_report():
    alerts = db.get_alerts()
    alerts["start_ts"] = pd.to_datetime(alerts["start"])
    alerts["end_ts"] = pd.to_datetime(alerts["end"])
    summary = db.summary()
    by_sev = summary["by_severity"]

    period_from = alerts["start_ts"].min().strftime("%Y-%m-%d")
    period_to = alerts["end_ts"].max().strftime("%Y-%m-%d")

    auth, net, _ = load_logs()
    quality = detection_quality(run_all_rules(auth, net, PROFILES["tuned"]))

    out = []
    out.append("# Security Incident Report - Energy Security Monitor")
    out.append(f"**Period:** {period_from} to {period_to}  \n"
               f"**Data:** simulated logs (no real company or person)  \n"
               f"**Prepared by:** Energy Security Monitor (automated)\n")

    # ---------- 1 executive summary ----------
    out.append("## 1. Executive summary")
    out.append(
        f"In the period, the monitor raised **{summary['total']} alerts**: "
        f"{by_sev['critical']} critical, {by_sev['high']} high, "
        f"{by_sev['medium']} medium and {by_sev['low']} low. "
        f"**{summary['nis2_assess']} incidents** must be assessed for NIS2 reporting.\n")
    critical = alerts[alerts["severity"] == "critical"]
    if not critical.empty:
        out.append(
            f"The most serious finding: **{len(critical)} suspicious successful logins to "
            "administrator accounts** (night time or from non-trusted countries). "
            "These indicate possible account takeover and need immediate action.\n")
    type_counts = alerts["alert_type"].value_counts()
    out.append("Alerts by attack type: " +
               ", ".join(f"{t.replace('_', ' ')} ({n})" for t, n in type_counts.items()) + ".\n")

    # ---------- 2 priority incidents ----------
    out.append("## 2. Priority incidents (critical and high)")
    priority = alerts[alerts["nis2_assess"] == 1].copy()
    priority["time"] = priority["start_ts"].dt.strftime(FMT)
    priority["score"] = priority["severity_score"].astype(str) + "/100"
    priority["technique"] = priority["mitre_id"] + " " + priority["mitre_name"]
    out.append(md_table(priority,
                        ["id", "severity", "score", "alert_type", "source_ip", "time", "technique"],
                        ["ID", "Severity", "Score", "Type", "Source IP", "Time", "MITRE ATT&CK"]))
    out.append("")
    for _, a in priority.iterrows():
        out.append(f"**Incident #{a['id']} - {a['alert_type'].replace('_', ' ')} from {a['source_ip']}**  \n"
                   f"Why this score: {a['score_reasons']}  \n"
                   f"Recommended action: {a['recommended_action']}\n")

    # ---------- 3 NIS2 timeline ----------
    out.append("## 3. NIS2 reporting timeline")
    out.append("Under NIS2, significant incidents must be reported in three steps, counted from "
               "the time the organisation becomes aware of the incident: an **early warning within "
               "24 hours**, an **incident notification within 72 hours**, and a **final report "
               "within one month after the notification**. Awareness time here is the time of the "
               "last alert event. Whether an incident is *significant* is decided by the responsible "
               "security team; the monitor only marks the candidates.\n")
    rows = []
    for _, a in priority.iterrows():
        early, notification, final = nis2_deadlines(a["end_ts"])
        rows.append({
            "id": a["id"],
            "aware": a["end_ts"].strftime(FMT),
            "early": early.strftime(FMT),
            "notification": notification.strftime(FMT),
            "final": final.strftime("%Y-%m-%d"),
        })
    out.append(md_table(pd.DataFrame(rows),
                        ["id", "aware", "early", "notification", "final"],
                        ["Incident", "Aware at", "Early warning by", "Notification by", "Final report by"]))
    out.append("")

    # ---------- 4 other alerts ----------
    out.append("## 4. Other alerts (medium and low)")
    other = alerts[alerts["nis2_assess"] == 0].copy()
    other["time"] = other["start_ts"].dt.strftime(FMT)
    other["technique"] = other["mitre_id"] + " " + other["mitre_name"]
    out.append(md_table(other,
                        ["id", "severity", "alert_type", "source_ip", "time", "technique"],
                        ["ID", "Severity", "Type", "Source IP", "Time", "MITRE ATT&CK"]))
    out.append("")

    # ---------- 5 recommendations ----------
    out.append("## 5. Recommendations")
    ips = sorted(alerts["source_ip"].unique())
    out.append(f"1. **Block {len(ips)} source IPs** at the firewall (list in `data/alerts.csv`).")
    actions = alerts.drop_duplicates("alert_type")[["alert_type", "recommended_action"]]
    for i, (_, a) in enumerate(actions.iterrows(), start=2):
        out.append(f"{i}. **{a['alert_type'].replace('_', ' ').capitalize()}:** {a['recommended_action']}")
    out.append("")

    # ---------- 6 detection quality ----------
    out.append("## 6. Detection quality and limits")
    out.append(
        f"On the simulated test data, the rules found **{quality['found']} of {quality['planted']} "
        f"planted attacks ({quality['rate']:.0f}%)** with **{quality['false_alarms']} false alarms**. "
        f"{quality['missed']} attack was missed: a very slow brute-force attack (10 failed logins "
        "over 90 minutes). Lowering the threshold to catch it would trigger false alarms for "
        "employees who simply forgot their password.\n")
    out.append("The rules were tuned on the same simulated data they are tested on, so results on "
               "real traffic would be lower.\n")
    return "\n".join(out)


def main():
    REPORT_DIR.mkdir(exist_ok=True)
    text = build_report()
    REPORT_PATH.write_text(text, encoding="utf-8")
    print(f"Report written to {REPORT_PATH}")
    print(f"{len(text.splitlines())} lines")


if __name__ == "__main__":
    main()
