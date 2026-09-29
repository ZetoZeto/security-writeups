# Web Application Testing - Playbook

A structured checklist I run during a web engagement. The goal is to rely on **process, not
memory**: work down the list, map every input to the vulnerability classes it could carry,
then chain the findings.

---

## Phase 0 - Scoping (never skipped)
- [ ] Record **my IP** vs **target IP** at the top of the notes.
- [ ] `nmap -sV -sC -oN scan.txt <TARGET>` → ports / services / versions.
- [ ] `curl -I http://<TARGET>` → server (Apache / nginx / IIS), stack (PHP?), missing
  security headers = leads.
- [ ] Service version → `searchsploit` (one CVE can be the whole box).

## Phase 1 - Passive reconnaissance (observe, break nothing)
- [ ] **Browse as a human:** list every feature → login, search, upload, profile, password
  reset, **API**, admin panel.
- [ ] **Burp as proxy** → the **Site map** fills itself (referenced paths, AJAX, JS).
- [ ] **`sitemap.xml` / `robots.txt`** → hidden directories the site announces itself.
- [ ] **Read the source and the `.js` files:** comments, endpoints, client-side secrets.
- [ ] **DevTools ▸ Network:** what the app actually sends (params, cookies, tokens).
- [ ] **Footer / links:** an "Access API" or "docs" link is an invitation to enumerate.

## Phase 2 - Active reconnaissance (force enumeration)
- [ ] **Directory brute force, escalating:** `gobuster` / `ffuf` small → medium,
  `-x php,txt,zip,bak,js,log`.
- [ ] **vhosts / subdomains** where relevant.
- [ ] **Map every data entry point:** each GET/POST param, each field, each `id=`, each
  custom header.

## Phase 3 - For each input, map vulnerability → test
> Reflex: *what goes in, where does it go, who controls it?*

| Signal | Vulnerability to test | First move |
|---|---|---|
| numeric `?id=` | **IDOR** | increment/decrement, test server-side authorization |
| field reflected on screen | **XSS** | baseline `test` → read raw HTML → identify context → break out |
| login / **search bar** / filter | **SQLi** | inject `'` → read the raw error → error / UNION / blind |
| file upload | **extension bypass** | incomplete blocklist → `.phtml` / `.phar` |
| password reset | **token** | shown in the response? guessable? |
| `?url=` / `?file=` / "fetch" | **SSRF / LFI** | `file:///etc/passwd`, `php://filter` to read `.php` source |
| `?skin=` / `?page=` / `?template=` / `?lang=` | **LFI / source disclosure** | `../` to escape the directory; distinguish *execute* vs *read* |
| missing header (CSP/HSTS…) | defensive lead | note it for the report |

## Phase 4 - Exploit → chain
- [ ] One link unlocks the next (e.g. LFI → read `config.php` → credentials → login → SQLi →
  dump admin).
- [ ] **LFI is a READ primitive**, not RCE. Reading `index.php` / `config.php` / `api.php`
  source is where secrets sleep.
- [ ] Document as you go: **finding / impact / remediation** (report format, not a narrative
  log).

---

## Pre-flight checklist before every injection
Small, high-frequency mistakes that cost the most time:

1. **Baseline before injecting.** Valid input first → observe normal behavior → then break.
   Never fire blind.
2. **Read the full raw response** (in Repeater, not the browser; no `grep` that hides). The
   error message tells you what to do next.
3. **Encoding / separator characters** - a special character changes meaning per layer:
   - missing space (`OR1=1` ❌ → `OR 1=1`), raw space in URL → `%20`
   - `&` in a GET → `%26`
   - quote-inside-quote → **hex `0x...`** (`0x3a`=`:`, `0x2f`=`/`)
   - MySQL comment `--` → **space required after** (`-- ` or `#`)
   - `file://` + absolute path = **three slashes** (`file:///etc/passwd`)
   - `_` / `%` wildcards under `LIKE` ≠ literal under `=`
4. **Count:** balanced parentheses, UNION **column count** (`ORDER BY` or `UNION SELECT NULL,…`
   first).
5. **Isolate the known-good:** if it breaks, reduce to the minimal working payload, then add
   back piece by piece.
6. **Don't mix contexts:** `">` = HTML breakout (XSS); `'` = SQL breakout. Two sinks, two
   attacks.
7. **Re-verify live IP / credentials** after a target restart, and read them from the actual
   source file rather than copying an example.
8. **Let the evidence dictate the vulnerability class.** If every write test returns 200 with
   an *unchanged* object, the endpoint is **read-only** - pivot to reading (IDOR / source
   disclosure) instead of forcing a write hypothesis imported from another target.
9. **A feature is only meaningful in its access context.** A harmless unauthenticated
   parameter can become vulnerable **once logged in**. Re-test each input **after every state
   change** (login, role cookie, 2FA). Map the attack surface **per privilege level**, not
   once.

---

## Reusable template - UNION-based SQLi
```sql
-- 1. count the columns
' ORDER BY 1--                     (increment until error)
' UNION SELECT NULL,NULL,NULL,NULL--
-- 2. find the columns VISIBLE on screen
' UNION SELECT 1,2,3,4--
-- 3. list databases → tables → columns
' UNION SELECT 1,2,3,GROUP_CONCAT(schema_name) FROM information_schema.schemata--
' UNION SELECT 1,2,3,GROUP_CONCAT(table_name)  FROM information_schema.tables  WHERE table_schema=0x...--
' UNION SELECT 1,2,3,GROUP_CONCAT(column_name) FROM information_schema.columns WHERE table_schema=0x... AND table_name=0x...--
-- 4. dump
' UNION SELECT 1,2,3,GROUP_CONCAT(username,0x3a,password) FROM users--
```
> `table_schema` = **database**, `table_name` = **table** (don't swap). `GROUP_CONCAT`
> concatenates into **one** column, so it goes into one of the N visible columns.
