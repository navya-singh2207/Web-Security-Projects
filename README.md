# Web Security Lab Browser

Hands-on teaching environment for CSET365 Labs 03–07. Each page exposes a vulnerable **Low** mode and hardened **Medium/High** modes so you can demonstrate exploits, mitigations, and layered defenses in a single browser-based experience.

## Features

- **Lab 03 – Brute Force & Rate Limiting**: Classic DVWA-style login on Low, session/IP throttling + captcha on Medium/High.
- **Lab 04 – Reflected XSS**: Direct reflection vs escaped output with nonce-based CSP.
- **Lab 05 – Stored XSS**: Raw comment wall vs escaped/sanitized output with CSP.
- **Lab 06 – DOM XSS**: `innerHTML` sink vs `textContent` + Trusted Types + CSP.
- **Lab 07 – CSRF**: Tokenless password change vs synchronizer token, SameSite cookies, and Origin/Referer validation.
- Global security level switch so you can flip between configurations live.

## Getting Started

```bash
cd "/Users/navyasingh/Desktop/web sec p"
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
flask --app app run --debug
```

Visit `http://localhost:5000` to launch the lab browser. Use the security-level dropdown in the header to toggle Low/Medium/High defenses.

## Recommended Use

1. Start at the dashboard to select a lab.
2. Set the level to **Low** to demonstrate the vulnerability (brute force, reflected/stored XSS, DOM sinks, CSRF).
3. Switch to **Medium** and **High** to show incremental mitigations (rate limiting, escaping, sanitization, CSP, Trusted Types, CSRF tokens).
4. Use provided payload hints (e.g., `"><script>alert(1)</script>` or `<script>alert('stored')</script>`) and PoC snippets to illustrate attacks quickly.

## Notes

- State (comments, login attempt counters, mock password) is kept in-memory for simplicity; restart the server to reset.
- CSP headers and SameSite policies vary automatically with the selected level.
- The project is intentionally small and framework-free on the frontend so students can inspect the HTML/JS sinks easily.

