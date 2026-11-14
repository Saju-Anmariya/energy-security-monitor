# Security Incident Report - Energy Security Monitor
**Period:** 2026-11-01 to 2026-11-07  
**Data:** simulated logs (no real company or person)  
**Prepared by:** Energy Security Monitor (automated)

## 1. Executive summary
In the period, the monitor raised **21 alerts**: 3 critical, 1 high, 14 medium and 3 low. **4 incidents** must be assessed for NIS2 reporting.

The most serious finding: **3 suspicious successful logins to administrator accounts** (night time or from non-trusted countries). These indicate possible account takeover and need immediate action.

Alerts by attack type: brute force (7), port scan (6), password spraying (5), suspicious admin login (3).

## 2. Priority incidents (critical and high)
| ID | Severity | Score | Type | Source IP | Time | MITRE ATT&CK |
|---|---|---|---|---|---|---|
| 1 | critical | 100/100 | suspicious_admin_login | 185.65.100.173 | 2026-11-02 02:10 | T1078 Valid Accounts |
| 2 | critical | 100/100 | suspicious_admin_login | 91.155.192.214 | 2026-11-05 03:25 | T1078 Valid Accounts |
| 3 | critical | 95/100 | suspicious_admin_login | 103.63.252.174 | 2026-11-04 15:43 | T1078 Valid Accounts |
| 4 | high | 65/100 | password_spraying | 91.133.183.67 | 2026-11-01 12:48 | T1110.003 Brute Force: Password Spraying |

**Incident #1 - suspicious admin login from 185.65.100.173**  
Why this score: base 85 for suspicious_admin_login; +10 login from a non-trusted country; +5 login at night  
Recommended action: Treat as possible account takeover: disable the admin session, reset credentials, review admin actions.

**Incident #2 - suspicious admin login from 91.155.192.214**  
Why this score: base 85 for suspicious_admin_login; +10 login from a non-trusted country; +5 login at night  
Recommended action: Treat as possible account takeover: disable the admin session, reset credentials, review admin actions.

**Incident #3 - suspicious admin login from 103.63.252.174**  
Why this score: base 85 for suspicious_admin_login; +10 login from a non-trusted country  
Recommended action: Treat as possible account takeover: disable the admin session, reset credentials, review admin actions.

**Incident #4 - password spraying from 91.133.183.67**  
Why this score: base 55 for password_spraying; +10 many accounts targeted (20+)  
Recommended action: Block the source IP, review all targeted accounts, and reset weak passwords.

## 3. NIS2 reporting timeline
Under NIS2, significant incidents must be reported in three steps, counted from the time the organisation becomes aware of the incident: an **early warning within 24 hours**, an **incident notification within 72 hours**, and a **final report within one month after the notification**. Awareness time here is the time of the last alert event. Whether an incident is *significant* is decided by the responsible security team; the monitor only marks the candidates.

| Incident | Aware at | Early warning by | Notification by | Final report by |
|---|---|---|---|---|
| 1 | 2026-11-02 02:10 | 2026-11-03 02:10 | 2026-11-05 02:10 | 2026-12-05 |
| 2 | 2026-11-05 03:25 | 2026-11-06 03:25 | 2026-11-08 03:25 | 2026-12-08 |
| 3 | 2026-11-04 15:43 | 2026-11-05 15:43 | 2026-11-07 15:43 | 2026-12-07 |
| 4 | 2026-11-01 13:08 | 2026-11-02 13:08 | 2026-11-04 13:08 | 2026-12-04 |

## 4. Other alerts (medium and low)
| ID | Severity | Type | Source IP | Time | MITRE ATT&CK |
|---|---|---|---|---|---|
| 5 | medium | brute_force | 45.61.149.36 | 2026-11-02 21:37 | T1110.001 Brute Force: Password Guessing |
| 6 | medium | password_spraying | 194.27.200.136 | 2026-11-02 21:42 | T1110.003 Brute Force: Password Spraying |
| 7 | medium | password_spraying | 91.129.71.131 | 2026-11-04 12:11 | T1110.003 Brute Force: Password Spraying |
| 8 | medium | brute_force | 103.14.140.223 | 2026-11-04 15:30 | T1110.001 Brute Force: Password Guessing |
| 9 | medium | brute_force | 185.64.110.105 | 2026-11-04 18:55 | T1110.001 Brute Force: Password Guessing |
| 10 | medium | password_spraying | 194.161.177.18 | 2026-11-05 10:46 | T1110.003 Brute Force: Password Spraying |
| 11 | medium | password_spraying | 194.92.74.200 | 2026-11-06 19:49 | T1110.003 Brute Force: Password Spraying |
| 12 | medium | brute_force | 194.126.203.146 | 2026-11-07 14:51 | T1110.001 Brute Force: Password Guessing |
| 13 | medium | port_scan | 45.146.4.154 | 2026-11-01 15:15 | T1595 Active Scanning |
| 14 | medium | brute_force | 103.162.214.18 | 2026-11-02 11:18 | T1110.001 Brute Force: Password Guessing |
| 15 | medium | brute_force | 194.116.91.251 | 2026-11-02 18:42 | T1110.001 Brute Force: Password Guessing |
| 16 | medium | port_scan | 91.239.19.82 | 2026-11-03 23:09 | T1595 Active Scanning |
| 17 | medium | port_scan | 103.123.36.210 | 2026-11-06 09:33 | T1595 Active Scanning |
| 18 | medium | brute_force | 194.57.59.20 | 2026-11-07 13:03 | T1110.001 Brute Force: Password Guessing |
| 19 | low | port_scan | 185.107.202.84 | 2026-11-01 05:42 | T1595 Active Scanning |
| 20 | low | port_scan | 185.87.195.214 | 2026-11-05 20:41 | T1595 Active Scanning |
| 21 | low | port_scan | 185.210.73.114 | 2026-11-07 09:06 | T1595 Active Scanning |

## 5. Recommendations
1. **Block 21 source IPs** at the firewall (list in `data/alerts.csv`).
2. **Suspicious admin login:** Treat as possible account takeover: disable the admin session, reset credentials, review admin actions.
3. **Password spraying:** Block the source IP, review all targeted accounts, and reset weak passwords.
4. **Brute force:** Block the source IP, check the targeted account for a successful login, and enforce MFA.
5. **Port scan:** Block the source IP at the firewall and check whether the scanned server exposes unneeded ports.

## 6. Detection quality and limits
On the simulated test data, the rules found **21 of 22 planted attacks (95%)** with **0 false alarms**. 1 attack was missed: a very slow brute-force attack (10 failed logins over 90 minutes). Lowering the threshold to catch it would trigger false alarms for employees who simply forgot their password.

The rules were tuned on the same simulated data they are tested on, so results on real traffic would be lower.
