# Penetration Test Report — "Blue" (MS17-010 / EternalBlue)

| | |
|---|---|
| **Target** | Windows 7 Professional SP1 (x64) — `TARGET` |
| **Type** | Network penetration test — black box |
| **Environment** | TryHackMe lab (authorized, intentionally vulnerable) |
| **Date** | 2026-06-10 |
| **Version** | v1.0 |

---

## 1. Executive summary

A single unpatched, internet-era vulnerability in the SMBv1 service (**MS17-010**, the
"EternalBlue" family) allowed **unauthenticated remote code execution** on the host,
yielding the highest privilege level on Windows (`NT AUTHORITY\SYSTEM`). No credentials were
required.

**Business impact:** complete compromise of the machine — full read/write access to all
data, credential harvesting, and a foothold for lateral movement across the network.

**Remediation priority:** apply the MS17-010 patch, **disable SMBv1**, and segment legacy
hosts. This is the same vulnerability class weaponized by the 2017 WannaCry / NotPetya
outbreaks.

---

## 2. Findings summary

| # | Vulnerability | Severity | CVSS |
|---|---|---|---|
| F1 | MS17-010 — SMBv1 remote code execution (EternalBlue) | **Critical** | 9.8 |
| F2 | SMB message signing disabled | **Medium** | 5.3 |
| F3 | Unsupported / legacy OS (Windows 7 SP1) exposed on the network | **Medium** | 5.9 |

---

## 3. Detailed findings

### F1 — MS17-010 SMBv1 remote code execution (EternalBlue)
**Severity: Critical (CVSS 9.8 — AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)**

**Description**
The host exposes SMBv1 (port 445) and is vulnerable to MS17-010, a memory-corruption flaw in
the way SMBv1 handles specially crafted requests. It permits arbitrary code execution
remotely, without authentication.

**Impact**
Full remote code execution as `NT AUTHORITY\SYSTEM` — the highest local privilege. From
there: dump credentials, create accounts, install persistence, and pivot to other hosts.

**Exploitation steps**
1. Recon — `nmap -sC -sV`: SMB open on 445, OS fingerprinted as Windows 7 SP1; host scripts
   flag message signing as disabled.
2. Confirm the vulnerability with the MS17-010 scanner:
   ```
   auxiliary/scanner/smb/smb_ms17_010  →  "Host is likely VULNERABLE to MS17-010!
   Windows 7 Professional 7601 Service Pack 1 x64 (64-bit)"
   ```
3. Exploit MS17-010 → obtain a shell, then upgrade to a Meterpreter session
   (`shell_to_meterpreter`).
4. Migrate into a stable process (the exploit is memory-intrusive; migrating avoids losing
   the session if the initial process dies).
5. Verify privileges (`getuid` → `NT AUTHORITY\SYSTEM`) and collect objectives.

> **Operator note:** EternalBlue corrupts kernel pool memory and can be unstable — if the
> first attempt fails, re-running against a freshly rebooted target is expected behavior.

**Recommendation**
- Apply the **MS17-010** security update immediately.
- **Disable SMBv1** entirely (it is deprecated and should not exist on modern networks).
- Retire or isolate the unsupported OS; place legacy systems behind strict segmentation with
  SMB blocked at the network boundary.

**Detection (blue-team notes)**
- Network: unusual SMBv1 traffic and known EternalBlue signatures (IDS/IPS).
- Endpoint: unexpected `SYSTEM`-level process creation and process migration
  (Sysmon Event ID 8 — CreateRemoteThread; ID 10 — process access to `lsass`).
- A modern EDR (e.g. Microsoft Defender for Endpoint) flags both the exploit behavior and the
  post-exploitation credential access.

---

### F2 — SMB message signing disabled
**Severity: Medium (CVSS 5.3)**

**Description**
`smb-security-mode` reports message signing as *disabled (dangerous, but default)* on the
SMBv1 service.

**Impact**
Absence of signing enables SMB relay and man-in-the-middle attacks against SMB
authentication, facilitating lateral movement in a broader network.

**Recommendation**
Require SMB signing via Group Policy, alongside disabling SMBv1.

---

### F3 — Legacy, unsupported operating system exposed
**Severity: Medium (CVSS 5.9)**

**Description**
The host runs Windows 7 SP1, out of mainstream support and no longer receiving security
updates by default.

**Impact**
An unsupported OS accumulates unpatched vulnerabilities over time; MS17-010 is one symptom of
a broader exposure.

**Recommendation**
Upgrade to a supported OS; where legacy applications force otherwise, isolate the host,
minimize its exposed services, and compensate with strict network controls and enhanced
monitoring.

---

## 4. Appendix — Exposed surface (initial scan)

| Port | Service | Notes |
|---|---|---|
| 135/tcp | msrpc | Microsoft Windows RPC |
| 139/tcp | netbios-ssn | |
| 445/tcp | microsoft-ds | Windows 7 Pro SP1 — **MS17-010 vulnerable** |
| 3389/tcp | ms-wbt-server | RDP |
| 49152–49160/tcp | msrpc | Dynamic RPC |

**Methodology:** reconnaissance (Nmap service + OS detection, SMB host scripts) →
vulnerability confirmation (MS17-010 scanner) → exploitation (EternalBlue → SYSTEM) →
post-exploitation (session stabilization via process migration). The engagement doubles as a
reminder of why SMBv1 must not survive on any modern network.

---

*Report produced for training purposes (authorized lab).*
