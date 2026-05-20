 
# 🛡 VulnScan — Web Vulnerability Scanner

> **Educational Penetration Testing Toolkit** — Client-side vulnerability assessment engine with a gold/red/black cyberpunk aesthetic.

![VulnScan Screenshot](https://img.shields.io/badge/Version-2.4.1-gold?style=for-the-badge&labelColor=111)
![License](https://img.shields.io/badge/License-MIT-red?style=for-the-badge&labelColor=111)
![GitHub Pages](https://img.shields.io/badge/GitHub%20Pages-Ready-green?style=for-the-badge&labelColor=111)

---

## 🚀 Live Demo

**→ [Launch VulnScan on GitHub Pages](https://yesiamvishal.github.io/vuln-scanner/)**

---

## 📋 Features

| Module | Description |
|--------|-------------|
| **Port Scanner** | Simulates scanning of 20+ common ports with risk assessment |
| **HTTP Header Audit** | Checks for missing security headers (CSP, HSTS, X-Frame-Options) |
| **SSL/TLS Audit** | Detects weak cipher suites, deprecated TLS versions, Heartbleed |
| **CVE Lookup** | Correlates software versions against a curated CVE knowledge base |
| **DNS Reconnaissance** | Subdomain enumeration, A/MX record discovery, zone transfer check |
| **WAF Detection** | Identifies presence of Web Application Firewalls |

### Key Capabilities
- 🔴 **Real-time terminal output** — Live scan log with color-coded severity levels
- 📊 **Vulnerability Report** — Filterable findings table with CVSS scores
- 🗺 **Port Map Visualization** — Color-coded port status grid
- 📤 **Export** — Download reports as JSON or standalone HTML
- 🎨 **Gold/Red/Black theme** — Professional cyberpunk aesthetic

---

## 🖥 Screenshots

```
[VULNSCAN]  Scanner  |  Report  |  About        ● SYSTEM ONLINE

DETECT.
ANALYZE.
DEFEND.

[>] Starting module: Port Scanner
[OPEN] 80/tcp    HTTP   — Unencrypted web traffic
[OPEN] 443/tcp   HTTPS  — Encrypted web - check TLS config
[OPEN] 3306/tcp  MySQL  — should never be public
[!!!]  CRITICAL: MySQL port exposed externally
[+] Port scan complete. 3 open ports.
```

---

## 📁 Project Structure

```
vuln-scanner/
├── index.html          # Main application
├── css/
│   └── style.css       # Gold/Red/Black theme, animations
├── js/
│   ├── cve-db.js       # CVE knowledge base (20+ vulnerabilities)
│   ├── scanner.js      # Scanner engine (6 modules)
│   ├── report.js       # Report generator + HTML/JSON export
│   └── app.js          # UI controller
└── README.md
```

---

 

 

---

## ⚙ Scan Profiles

| Profile | Ports | Depth |
|---------|-------|-------|
| **Quick Scan** | 10 common ports | Fast, covers critical vectors |
| **Full Audit** | 25+ ports | Comprehensive assessment |
| **Stealth Mode** | Randomized | Mimics low-and-slow techniques |

---

## 🧠 CVE Database Highlights

The built-in CVE knowledge base covers:

| CVE | Name | CVSS |
|-----|------|------|
| CVE-2021-44228 | Log4Shell RCE | 10.0 |
| CVE-2014-0160 | Heartbleed | 9.8 |
| CVE-2019-0708 | BlueKeep RDP | 9.8 |
| CVE-2022-22965 | Spring4Shell | 9.8 |
| CVE-2020-1472 | Zerologon | 10.0 |
| CVE-2017-5638 | Apache Struts2 | 10.0 |
| + 15 more... | | |

---

## ⚠ Legal Disclaimer

> This tool is designed **exclusively for educational purposes**, Capture The Flag (CTF) competitions, and **authorized** penetration testing engagements.
>
> **Scanning systems without explicit written authorization is illegal** under the Computer Fraud and Abuse Act (CFAA) and equivalent laws worldwide.
>
> The authors and contributors assume **no liability** for misuse of this software. Always practice ethical hacking responsibly.

---

## 📚 Learning Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [NVD CVE Database](https://nvd.nist.gov/)
- [PortSwigger Web Security Academy](https://portswigger.net/web-security)
- [HackTheBox](https://www.hackthebox.com/)
- [TryHackMe](https://tryhackme.com/)

---

## 📄 License

MIT License — free for educational use.

---

*Built with HTML · CSS · Vanilla JS · No dependencies · 100% client-side*
