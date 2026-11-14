"""
Energy Security Monitor - Phase 4: Streamlit dashboard.

Run:  streamlit run src/dashboard.py
"""

import altair as alt
import streamlit as st

import db

st.set_page_config(page_title="Energy Security Monitor", page_icon="🛡️", layout="wide")

st.title("🛡️ Energy Security Monitor")
st.caption("Detection of attacks on energy IT infrastructure. All data is simulated.")

# ---------- load data ----------
try:
    all_alerts = db.get_alerts()
except FileNotFoundError as error:
    st.error(str(error))
    st.stop()

# ---------- sidebar filters ----------
st.sidebar.header("Filters")
severity_filter = st.sidebar.multiselect("Severity", db.SEVERITY_ORDER, default=db.SEVERITY_ORDER)
type_options = sorted(all_alerts["alert_type"].unique())
type_filter = st.sidebar.multiselect("Attack type", type_options, default=type_options)

alerts = db.get_alerts(severity=severity_filter, alert_type=type_filter)

# ---------- key numbers ----------
total = len(alerts)
critical = int((alerts["severity"] == "critical").sum())
high = int((alerts["severity"] == "high").sum())
nis2 = int(alerts["nis2_assess"].sum())

col1, col2, col3, col4 = st.columns(4)
col1.metric("Alerts", total)
col2.metric("Critical", critical)
col3.metric("High", high)
col4.metric("To assess for NIS2 reporting", nis2)

if alerts.empty:
    st.info("No alerts match the current filters.")
    st.stop()

# ---------- charts ----------
left, right = st.columns(2)

SEVERITY_COLORS = ["#b71c1c", "#e65100", "#f9a825", "#2e7d32"]   # critical, high, medium, low

with left:
    st.subheader("Alerts by severity")
    severity_df = db.alerts_by_severity(alerts).reset_index()
    severity_df.columns = ["severity", "alerts"]
    severity_chart = alt.Chart(severity_df).mark_bar().encode(
        x=alt.X("severity:N", sort=db.SEVERITY_ORDER, title=None, axis=alt.Axis(labelAngle=0)),
        y=alt.Y("alerts:Q", title="Alerts"),
        color=alt.Color("severity:N",
                        scale=alt.Scale(domain=db.SEVERITY_ORDER, range=SEVERITY_COLORS),
                        legend=None),
        tooltip=["severity", "alerts"],
    )
    st.altair_chart(severity_chart)

with right:
    st.subheader("Alerts per day")
    st.bar_chart(db.alerts_per_day(alerts))

st.subheader("Top source IPs (highest severity score)")
top_df = db.top_source_ips(alerts).reset_index()
top_chart = alt.Chart(top_df).mark_bar().encode(
    y=alt.Y("source_ip:N", sort="-x", title=None),
    x=alt.X("severity_score:Q", title="Severity score", scale=alt.Scale(domain=[0, 100])),
    tooltip=["source_ip", "severity_score"],
)
st.altair_chart(top_chart)

# ---------- alert table ----------
st.subheader("All alerts")
table_columns = ["id", "severity", "severity_score", "alert_type", "source_ip",
                 "start", "evidence", "mitre_id", "tactic"]
st.dataframe(alerts[table_columns], hide_index=True)

# ---------- alert details ----------
st.subheader("Alert details")
selected_id = st.selectbox(
    "Choose an alert",
    alerts["id"],
    format_func=lambda i: (
        f"#{i}  {alerts.loc[alerts['id'] == i, 'severity'].iloc[0].upper()}  "
        f"{alerts.loc[alerts['id'] == i, 'alert_type'].iloc[0]}  "
        f"{alerts.loc[alerts['id'] == i, 'source_ip'].iloc[0]}"
    ),
)
alert = db.get_alert(selected_id)

detail_left, detail_right = st.columns(2)
with detail_left:
    st.markdown(f"**Severity:** {alert['severity']} ({alert['severity_score']}/100)")
    st.markdown(f"**Source IP:** `{alert['source_ip']}`")
    st.markdown(f"**Time:** {alert['start']} → {alert['end']}")
    st.markdown(f"**MITRE ATT&CK:** {alert['mitre_id']} {alert['mitre_name']} ({alert['tactic']})")
    st.markdown(f"**Why this score:** {alert['score_reasons']}")
with detail_right:
    st.markdown("**Recommended action**")
    st.info(alert["recommended_action"])
    if alert["nis2_assess"]:
        st.warning("Assess whether this incident must be reported under NIS2.")
