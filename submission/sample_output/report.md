# Automated Reconnaissance Report
**Target:** google.com
**Mode:** domain
**Timestamp:** 2026-05-12 10:15:03

## Summary of Findings
| Category | Observation |
| :--- | :--- |
| **Registrar** | MarkMonitor Inc. |
| **Creation Date** | 1997-09-15 |
| **Domain Expiry** | 2028-09-14 |
| **Server Header** | `gws` (Google Web Server) |

## DNS Records Found
```text
google.com.     300 IN  A   142.250.190.46
google.com.     300 IN  MX  10 smtp.google.com.
google.com.     300 IN  TXT "v=spf1 include:_spf.google.com ~all"
google.com.     300 IN  NS  ns1.google.com.

```

## Security Headers Audit

*Analysis of HTTP response headers to identify missing protections:*

* ✅ **Strict-Transport-Security (HSTS):** Present (`max-age=31536000`)
* ✅ **X-Frame-Options:** Present (`SAMEORIGIN`)
* ❌ **Content-Security-Policy (CSP):** **MISSING** - Target may be vulnerable to unauthorized resource loading or XSS chaining.
