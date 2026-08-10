# CDNHostFinder v1.0

**Passive CDN Infrastructure Discovery Tool for Termux**

Detects domains hosted behind **Cloudflare**, **Amazon CloudFront / AWS**, and **Microsoft Azure** using only passive, publicly available information.

---

## Features

- 🔍 **Passive Discovery** – crt.sh Certificate Transparency logs + DNS wordlist
- 🧠 **Multi-Signal Detection** – CNAME, HTTP headers, TLS issuer, ASN/Org
- 🖥️ **Live Terminal UI** – Real-time counter + categorized results
- 💾 **Auto-Save** – Results incrementally saved to `results.txt`
- 🛡️ **Rate-Limited** – Respects targets, stays within free API limits
- 📱 **Termux Optimized** – No root required, works on Android

---

## Supported Providers

| Provider | Detection Signals |
|----------|------------------|
| **Cloudflare** | CNAME `*.cloudflare.net`, `cf-ray` header, AS13335, TLS issuer |
| **AWS CloudFront** | CNAME `*.cloudfront.net`, `x-amz-cf-id` header, AS16509 |
| **Azure** | CNAME `*.azureedge.net`, `x-azure-ref` header, AS8075 |

---

## Installation (Termux)

