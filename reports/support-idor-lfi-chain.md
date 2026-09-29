# Penetration Test Report - "Support" Web Application

| | |
|---|---|
| **Target** | Support portal - `support.thm` (`TARGET`) |
| **Type** | Web application penetration test - grey box (network access, no account provided) |
| **Environment** | TryHackMe lab (authorized, intentionally vulnerable) |
| **Date** | 2026-08-04 |
| **Version** | v1.0 |

---

## 1. Executive summary

Starting from an anonymous position, the assessment chained **four independent weaknesses**
to move from "no account" to **full administrator compromise**. A weak login password was
brute-forced; a client-side "authorization" cookie was forged to gain an internal role; an
IDOR then revealed the administrator account; and a source-disclosure flaw leaked the
application's master password in clear text.

**Business impact:** an unauthenticated attacker could escalate to an administrator role and
read the application's configuration secrets, including a master password reusable across the
portal.

**Remediation priorities:** (1) enforce server-side authorization (never trust a client
cookie for access decisions), (2) fix the file-read / source-disclosure flaw, (3) remove
clear-text secrets and rotate them, (4) add rate limiting on login.

---

## 2. Findings summary

| # | Vulnerability | Severity | CVSS |
|---|---|---|---|
| F1 | Broken access control - forgeable authorization cookie (`isITUser`) | **High** | 8.1 |
| F2 | IDOR on `GET /user/{id}` → administrator account disclosure | **High** | 7.5 |
| F3 | Local file read / source disclosure via `?skin=../config` | **High** | 7.5 |
| F4 | Weak password + no rate limiting on login | **Medium** | 6.5 |

---

## 3. Detailed findings

### F1 - Broken access control: forgeable authorization cookie
**Severity: High (CVSS 8.1)**

**Description**
After authenticating as a standard user, the session sets a cookie
`isITUser=68934a3e9455fa72420237eb05902327`. That value is simply `md5("false")`. The
application makes its role decision client-side, trusting a cookie the user fully controls.

**Impact**
Replacing the cookie with `md5("true")` (`b326b5062b2f0e69046810717534cb09`) elevates the
session to an internal "IT User" role, unlocking the **Admin Panel** and the internal API -
a horizontal-to-vertical privilege escalation performed entirely from the browser.

**Exploitation steps**
1. Log in as a standard user; observe the `isITUser` cookie.
2. Recognize the value as `md5("false")`.
3. Compute `md5("true")` and replace the cookie value.
4. Refresh → the Admin Panel and API become accessible.

**Recommendation**
Never store authorization state in a client-controlled cookie. Derive roles **server-side**
from the authenticated session and re-check them on every privileged request. If a role must
be transmitted, use a signed, tamper-evident token (e.g. a server-side session record).

---

### F2 - IDOR on `GET /user/{id}` → administrator disclosure
**Severity: High (CVSS 7.5)**

**Description**
The internal API endpoint `GET /user/{id}` returns any user's record by sequential
identifier, with no authorization check that the caller may view that record.

**Impact**
Enumerating identifiers exposes every account, including a hidden administrator
(`specialadmin@support.thm`, `admin: true`). This directly identifies the account to target
for full compromise.

**Exploitation steps**
1. Observe the request for the current user: `GET /user/3` → `{ "email": "...", "admin": false }`.
2. Replay in Burp Repeater against other identifiers:
   - `GET /user/1` → `specialadmin@support.thm` (`admin: true`) - **administrator**.
   - `GET /user/2` → `IT@support.thm` (`admin: false`).

**Recommendation**
Enforce object-level authorization on every request: verify the authenticated user is
permitted to access the requested resource. Prefer non-sequential identifiers (UUIDs) as
defense in depth, but authorization - not obscurity - is the fix.

---

### F3 - Local file read / source disclosure via `?skin=../config`
**Severity: High (CVSS 7.5)**

**Description**
The dashboard theme selector loads a file from a user-supplied name
(`dashboard.php?skin=red`), automatically appending `.php`. The loader **reads and echoes**
the file's raw contents rather than executing it, so a path-traversal value discloses the
source of arbitrary `.php` files.

**Impact**
`dashboard.php?skin=../config` leaks the source of `config.php`, exposing a master password
in clear text (`$MASTER_PASSWORD = '[redacted]';`). Combined with F2's administrator email,
this yields working administrator credentials.

**Exploitation steps**
1. Note the theme selector: `dashboard.php?skin=red` → loads `red.php`.
2. Traverse out of the skins directory: `dashboard.php?skin=../config`.
3. The response embeds the raw source of `config.php`, revealing `$MASTER_PASSWORD`.

> **Note on the technique:** because the loader *echoes* the file instead of `include()`-ing
> it, a plain traversal is enough to disclose source - no `php://filter` wrapper is needed.
> A theme/skin selector that renders a `.php` file as text is, in itself, a source-disclosure
> primitive.

**Recommendation**
Do not build file paths from user input. Use an allowlist of valid skin names mapped
server-side to fixed paths, resolve and confirm the canonical path stays within the intended
directory, and keep configuration/secret files outside any user-reachable loader.

---

### F4 - Weak password and no rate limiting on login
**Severity: Medium (CVSS 6.5)**

**Description**
The login form enforces no rate limiting, and a valid account used a weak, wordlist-present
password, allowing an online brute-force to succeed quickly.

**Impact**
Initial foothold: recovering a valid account's password is the entry point that makes the
subsequent chain (F1 → F2 → F3) reachable.

**Exploitation steps**
```bash
ffuf -w /usr/share/wordlists/SecLists/Passwords/Common-Credentials/10-million-password-list-top-1000.txt \
  -X POST -d "email=help@support.thm&password=FUZZ" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -u http://TARGET/ -fr "Invalid credentials"
```
→ valid credential pair recovered (`help@support.thm : [redacted]`).

**Recommendation**
Add rate limiting and temporary lockout after repeated failures, enforce a strong password
policy, and monitor authentication-failure spikes (SIEM / SOC alerting).

---

## 4. Attack chain

```
Brute-force login (F4)  →  standard user session
        │
        ▼
Forge isITUser = md5("true")  (F1)  →  IT User role  →  Admin Panel + internal API
        │
        ▼
IDOR GET /user/1  (F2)  →  administrator account (specialadmin@support.thm)
        │
        ▼
LFI ?skin=../config  (F3)  →  config.php source  →  master password  →  admin access
```

---

## 5. Appendix - Exposed surface (initial scan)

| Port | Service | Version |
|---|---|---|
| 22/tcp | SSH | OpenSSH 9.6p1 |
| 80/tcp | HTTP | Apache httpd 2.4.58 (PHP 8.3) |

**Methodology:** reconnaissance (Nmap, directory brute force) → initial access (login brute
force) → privilege escalation (cookie tampering) → account discovery (IDOR) → secret
disclosure (LFI source read). A key lesson from this engagement: **let the evidence dictate
the vulnerability class** - the API here was read-only, and the exploitable path was reading
data (IDOR + source disclosure), not modifying it.

---

*Report produced for training purposes (authorized lab). Credentials and secrets have been
redacted.*
