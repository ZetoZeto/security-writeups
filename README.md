# 🛡️ Security Lab Write-ups

Hands-on offensive-security lab work — penetration-test reports and methodology notes
produced while training on intentionally vulnerable machines (TryHackMe, Hack The Box) and
preparing the **Microsoft SC-200** certification.

> **Author:** Philippe Luu — 2nd-year Computer Engineering student (CESI)
> **Looking for:** an international offensive-security internship (red / purple team).
> This repository documents my practical lab work; it complements my main portfolio.

---

## 👤 Profile in one line

**Purple-team oriented.** Professional **blue-team** experience with enterprise endpoint
security (Microsoft Intune, Defender for Endpoint, Microsoft Sentinel), now building a
solid **offensive** skill set — web application exploitation, network recon, privilege
escalation and reporting. I approach every attack thinking about the detection and
remediation on the other side.

---

## 🧭 What's in this repository

| Folder | Content |
|---|---|
| [`reports/`](reports/) | Full penetration-test reports (executive summary, findings, CVSS, remediation) |
| [`methodology/`](methodology/) | Reusable checklists and playbooks I follow during an engagement |

### Featured reports
- **[Recruit — Web application penetration test](reports/recruit-web-app-pentest.md)**
  Unauthenticated to full database compromise: information disclosure → LFI / source
  disclosure → SQL injection (UNION). 7 findings, ranked by CVSS.
- **[Support — Broken access control chain](reports/support-idor-lfi-chain.md)**
  Weak login → forgeable authorization cookie → IDOR → LFI source disclosure of admin
  credentials.
- **[Blue — MS17-010 / EternalBlue](reports/blue-eternalblue.md)**
  Legacy SMBv1 remote code execution leading to SYSTEM, with detection & hardening notes.

---

## 🧰 Skills overview

| Area | Level |
|---|---|
| Endpoint security / EDR (Defender, Intune) | 🟢 Professional experience |
| Networking, packet capture & analysis | 🟢 Strong |
| Linux & system security | 🟢 Strong |
| SIEM / log analysis (Splunk, KQL / Sentinel) | 🟡 Solid, growing |
| Web application exploitation (SQLi, XSS, LFI, IDOR, file upload → RCE) | 🟡 Hands-on, active |
| Reconnaissance & enumeration | 🟡 Hands-on |
| Exploitation frameworks (Metasploit, Burp Suite, ffuf) | 🟡 Hands-on |
| Privilege escalation (Linux / Windows) | 🟡 Learning |
| Active Directory attack paths | 🔵 Studying |

_Tooling:_ Nmap · Burp Suite · ffuf / Gobuster · Metasploit · Hydra · sqlmap ·
John the Ripper / Hashcat · Wireshark / tcpdump · Impacket · Splunk · KQL.

---

## 🎓 Certifications in progress

- **Microsoft SC-200** — Security Operations Analyst (KQL, Defender XDR, Microsoft Sentinel).

---

## ⚖️ Scope & ethics

Every engagement documented here was performed against **authorized, intentionally
vulnerable training environments** (TryHackMe / Hack The Box). No real-world system was
ever targeted. Lab-specific credentials, IP addresses and capture-the-flag values have
been redacted or genericized — the focus is on **methodology, reasoning and remediation**,
not on spoiling the labs.

---

_This repository documents personal lab training and is shared for educational and
recruitment purposes._
