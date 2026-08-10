#!/usr/bin/env python3
"""
CDNHostFinder v1.0 – Passive CDN Infrastructure Discovery Tool
─────────────────────────────────────────────────────────────
Detects domains behind Cloudflare, AWS CloudFront, and Microsoft Azure
using passive DNS, HTTP headers, TLS certificates, and ASN data.

Author: Nothing is impossible (Silent Hackers Team)
Telegram: @only_possible | @silent_ai_official
"""

import sys
import os
import time
import json
import ssl
import socket
import signal
import threading
import argparse
from datetime import datetime
from collections import defaultdict
from typing import Optional, Set, Dict, List, Tuple

# ─── Third-party imports ───────────────────────────────────────────
try:
    import dns.resolver
    import dns.exception
except ImportError:
    print("[!] 'dnspython' not found. Run: pip install dnspython")
    sys.exit(1)

try:
    import requests
    from requests.adapters import HTTPAdapter
    from urllib3.util.retry import Retry
except ImportError:
    print("[!] 'requests' not found. Run: pip install requests")
    sys.exit(1)


# ╔══════════════════════════════════════════════════════════════════╗
# ║                        CONFIGURATION                            ║
# ╚══════════════════════════════════════════════════════════════════╝

class Config:
    """Central configuration constants."""
    # Rate limits (seconds between operations)
    RATE_DNS = 0.1
    RATE_HTTP = 0.3
    RATE_API = 1.5
    RATE_CRTSH = 2.0

    # Timeouts
    DNS_TIMEOUT = 5
    HTTP_TIMEOUT = 6
    TLS_TIMEOUT = 4

    # crt.sh refresh interval (seconds)
    CRTSH_REFRESH = 120

    # Maximum subdomains to discover (safety limit)
    MAX_TARGETS = 10000

    # Common subdomains wordlist
    COMMON_SUBDOMAINS = [
        "www", "mail", "pk",  "mail","ftp", "localhost", "webmail", "smtp", "pop", "ns1", "ns2",
        "webdisk", "cpanel", "whm", "autodiscover", "autoconfig", "m", "imap",
        "test", "dev", "staging", "api", "cdn", "static", "media", "images",
        "img", "video", "videos", "files", "download", "downloads", "docs",
        "blog", "shop", "store", "secure", "ssl", "vpn", "remote", "portal",
        "admin", "administrator", "login", "signin", "auth", "sso", "id",
        "my", "account", "accounts", "dashboard", "app", "apps", "mobil",
        "mobile", "ios", "android", "gateway", "gw", "api2", "api3",
        "api-dev", "api-staging", "api-sandbox", "sandbox", "dev2", "test2",
        "uat", "qa", "demo", "beta", "alpha", "internal", "intranet", "extranet",
        "partner", "partners", "reseller", "affiliate", "affiliates", "client",
        "clients", "customer", "customers", "billing", "payments", "invoice",
        "support", "help", "helpdesk", "status", "monitor", "monitoring",
        "metrics", "logs", "log", "syslog", "events", "event", "analytics",
        "track", "tracking", "pixel", "cdn2", "cdn3", "static2", "static3",
        "media2", "media3", "assets", "assets2", "origin", "origin2",
        "edge", "edges", "cache", "cached", "proxy", "lb", "loadbalancer",
        "cluster", "node1", "node2", "node3", "server1", "server2",
        "web1", "web2", "web3", "app1", "app2", "app3", "db", "db1",
        "sql", "mysql", "mssql", "oracle", "redis", "mongo", "elastic",
        "search", "solr", "kibana", "grafana", "jenkins", "git", "gitlab",
        "github", "bitbucket", "svn", "jira", "confluence", "wiki",
        "docs2", "documentation", "swagger", "api-docs", "redoc",
        "mail2", "mail3", "relay", "smtp2", "imap2", "pop3", "exchange",
        "lync", "skype", "teams", "meet", "zoom", "webex", "conference",
        "chat", "irc", "jabber", "xmpp", "matrix", "riot", "slack",
        "discord", "telegram", "whatsapp", "signal", "wire",
    ]


# ╔══════════════════════════════════════════════════════════════════╗
# ║                      TERMINAL COLORS                            ║
# ╚══════════════════════════════════════════════════════════════════╝

class Colors:
    """ANSI escape codes for terminal styling."""
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    RED = "\033[91m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    BLUE = "\033[94m"
    MAGENTA = "\033[95m"
    CYAN = "\033[96m"
    WHITE = "\033[97m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"

    @staticmethod
    def disable():
        """Turn off all colors (for non-TTY output)."""
        for attr in dir(Colors):
            if not attr.startswith("_") and attr.isupper():
                setattr(Colors, attr, "")

# Disable colors if output is not a terminal
if not sys.stdout.isatty():
    Colors.disable()


# ╔══════════════════════════════════════════════════════════════════╗
# ║                       RATE LIMITER                              ║
# ╚══════════════════════════════════════════════════════════════════╝

class RateLimiter:
    """Token-bucket style rate limiter."""
    def __init__(self):
        self._last: Dict[str, float] = defaultdict(float)

    def wait(self, key: str, delay: float):
        """Ensure at least `delay` seconds since last `key` call."""
        now = time.monotonic()
        elapsed = now - self._last[key]
        if elapsed < delay:
            time.sleep(delay - elapsed)
        self._last[key] = time.monotonic()


# ╔══════════════════════════════════════════════════════════════════╗
# ║                       DNS ENGINE                                ║
# ╚══════════════════════════════════════════════════════════════════╝

class DNSEngine:
    """Resolves DNS records using dnspython."""
    def __init__(self, rate_limiter: RateLimiter):
        self.rl = rate_limiter
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = Config.DNS_TIMEOUT
        self.resolver.lifetime = Config.DNS_TIMEOUT
        self.resolver.nameservers = ['8.8.8.8', '1.1.1.1']  # Google + Cloudflare

    def resolve_a(self, domain: str) -> List[str]:
        """Return list of A record IPs."""
        self.rl.wait("dns", Config.RATE_DNS)
        try:
            answers = self.resolver.resolve(domain, 'A')
            return [str(r) for r in answers]
        except (dns.exception.DNSException, OSError):
            return []

    def resolve_aaaa(self, domain: str) -> List[str]:
        """Return list of AAAA record IPs."""
        self.rl.wait("dns", Config.RATE_DNS)
        try:
            answers = self.resolver.resolve(domain, 'AAAA')
            return [str(r) for r in answers]
        except (dns.exception.DNSException, OSError):
            return []

    def resolve_cname(self, domain: str) -> Optional[str]:
        """Return CNAME target or None."""
        self.rl.wait("dns", Config.RATE_DNS)
        try:
            answers = self.resolver.resolve(domain, 'CNAME')
            cname = str(answers[0].target).rstrip('.')
            return cname.lower()
        except (dns.exception.DNSException, OSError):
            return None

    def resolve_ns(self, domain: str) -> List[str]:
        """Return list of NS records."""
        self.rl.wait("dns", Config.RATE_DNS)
        try:
            answers = self.resolver.resolve(domain, 'NS')
            return [str(r.target).rstrip('.').lower() for r in answers]
        except (dns.exception.DNSException, OSError):
            return []


# ╔══════════════════════════════════════════════════════════════════╗
# ║                     HTTP INSPECTOR                              ║
# ╚══════════════════════════════════════════════════════════════════╝

class HTTPInspector:
    """Checks HTTP/HTTPS status and headers."""
    def __init__(self, rate_limiter: RateLimiter):
        self.rl = rate_limiter
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; CDNHostFinder/1.0)"
        })
        # Retry logic
        retry = Retry(total=2, backoff_factor=0.5, status_forcelist=[429, 502, 503, 504])
        adapter = HTTPAdapter(max_retries=retry)
        self.session.mount("http://", adapter)
        self.session.mount("https://", adapter)

    def _fetch(self, url: str, timeout: int = Config.HTTP_TIMEOUT) -> Tuple[Optional[int], Dict[str, str]]:
        """Perform GET request; returns (status_code, headers_dict)."""
        self.rl.wait("http", Config.RATE_HTTP)
        try:
            resp = self.session.get(url, timeout=timeout, allow_redirects=True, verify=False)
            return resp.status_code, dict(resp.headers)
        except requests.RequestException:
            return None, {}

    def check_http(self, domain: str) -> Tuple[Optional[int], Dict[str, str]]:
        """Check HTTP (port 80)."""
        return self._fetch(f"http://{domain}")

    def check_https(self, domain: str) -> Tuple[Optional[int], Dict[str, str]]:
        """Check HTTPS (port 443)."""
        return self._fetch(f"https://{domain}")

    def get_tls_cert(self, domain: str) -> Tuple[Optional[str], List[str]]:
        """Retrieve TLS certificate issuer organization and SAN list."""
        self.rl.wait("http", Config.RATE_HTTP)
        issuer_org = None
        san_list: List[str] = []
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=Config.TLS_TIMEOUT) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as tls:
                    cert = tls.getpeercert()
                    # Extract issuer organization
                    issuer = dict(x[0] for x in cert.get("issuer", []))
                    issuer_org = issuer.get("organizationName", None)
                    if issuer_org:
                        issuer_org = issuer_org.lower()
                    # Extract Subject Alternative Names
                    for field, value in cert.get("subjectAltName", []):
                        if field == "DNS":
                            san_list.append(value.lower())
        except (ssl.SSLError, socket.error, OSError, ConnectionRefusedError, TimeoutError):
            pass
        return issuer_org, san_list


# ╔══════════════════════════════════════════════════════════════════╗
# ║                       ASN LOOKUP                                ║
# ╚══════════════════════════════════════════════════════════════════╝

class ASNLookup:
    """Resolves IP to ASN + Organization using ip-api.com."""
    def __init__(self, rate_limiter: RateLimiter):
        self.rl = rate_limiter
        self.cache: Dict[str, Tuple[str, str]] = {}
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CDNHostFinder/1.0"})

    def lookup(self, ip: str) -> Tuple[str, str]:
        """Return (ASN, organization) for given IP. Cached."""
        if ip in self.cache:
            return self.cache[ip]
        self.rl.wait("api", Config.RATE_API)
        try:
            resp = self.session.get(
                f"http://ip-api.com/json/{ip}",
                params={"fields": "as,org"},
                timeout=10
            )
            if resp.status_code == 200:
                data = resp.json()
                asn = data.get("as", "").split()[0] if "as" in data else "N/A"
                org = data.get("org", "Unknown").lower()
                result = (asn, org)
                self.cache[ip] = result
                return result
        except requests.RequestException:
            pass
        return ("N/A", "unknown")


# ╔══════════════════════════════════════════════════════════════════╗
# ║                   PROVIDER DETECTOR                             ║
# ╚══════════════════════════════════════════════════════════════════╝

class ProviderDetector:
    """Multi-signal CDN/hosting provider identification."""

    CLOUDFLARE = "Cloudflare"
    AWS = "Amazon CloudFront / AWS"
    AZURE = "Microsoft Azure"

    # ── Cloudflare signals ──
    CF_CNAME_PATTERNS = [
        ".cloudflare.net", ".cdn.cloudflare.net",
        ".cloudflare-dns.com", ".cloudflare-eth.",
    ]
    CF_HEADER_KEYS = ["cf-ray", "cf-cache-status", "cf-connecting-ip", "cf-ipcountry"]
    CF_TLS_KW = ["cloudflare"]
    CF_ASN_LIST = ["AS13335"]
    CF_NS_PATTERNS = [".ns.cloudflare.com"]
    CF_SERVER_KW = ["cloudflare"]

    # ── AWS CloudFront signals ──
    AWS_CNAME_PATTERNS = [
        ".cloudfront.net", ".amazonaws.com", ".awsglobalaccelerator.com",
        ".s3.amazonaws.com", ".s3-website", ".elasticbeanstalk.com",
    ]
    AWS_HEADER_KEYS = ["x-amz-cf-id", "x-amz-cf-pop", "x-amz-request-id",
                        "x-amz-id-2", "x-amz-version-id"]
    AWS_TLS_KW = ["amazon"]
    AWS_ASN_LIST = ["AS16509", "AS14618"]
    AWS_SERVER_KW = ["cloudfront", "amazons3", "awselb"]

    # ── Azure signals ──
    AZURE_CNAME_PATTERNS = [
        ".azureedge.net", ".cloudapp.net", ".azurewebsites.net",
        ".trafficmanager.net", ".azurefd.net", ".blob.core.windows.net",
        ".vo.msecnd.net", ".azure-api.net", ".azurecontainer.io",
    ]
    AZURE_HEADER_KEYS = ["x-azure-ref", "x-ms-request-id", "x-ms-version",
                           "x-ms-lease-status", "x-azure-socketio"]
    AZURE_TLS_KW = ["microsoft", "azure"]
    AZURE_ASN_LIST = ["AS8075", "AS8068", "AS8069", "AS3598"]
    AZURE_SERVER_KW = ["azure", "microsoft-iis", "windows-azure"]

    def detect(self,
               domain: str,
               ips: List[str],
               cname: Optional[str],
               ns_records: List[str],
               http_headers: Dict[str, str],
               https_headers: Dict[str, str],
               tls_issuer: Optional[str],
               asn: str,
               org: str) -> Optional[str]:
        """
        Determine which provider (if any) hosts this domain.
        Returns provider name or None.
        """
        all_headers = {**http_headers, **https_headers}
        headers_lower = {k.lower(): v for k, v in all_headers.items()}
        cname_lower = (cname or "").lower()
        ns_lower = [n.lower() for n in ns_records]
        issuer_lower = (tls_issuer or "").lower()
        org_lower = org.lower()

        scores: Dict[str, int] = {self.CLOUDFLARE: 0, self.AWS: 0, self.AZURE: 0}

        # ── Cloudflare scoring ──
        for pattern in self.CF_CNAME_PATTERNS:
            if pattern in cname_lower:
                scores[self.CLOUDFLARE] += 45
                break
        for hk in self.CF_HEADER_KEYS:
            if hk in headers_lower:
                scores[self.CLOUDFLARE] += 35
                break
        if asn in self.CF_ASN_LIST:
            scores[self.CLOUDFLARE] += 30
        for kw in self.CF_TLS_KW:
            if kw in issuer_lower:
                scores[self.CLOUDFLARE] += 25
                break
        for pat in self.CF_NS_PATTERNS:
            if any(pat in ns for ns in ns_lower):
                scores[self.CLOUDFLARE] += 15
                break
        for kw in self.CF_SERVER_KW:
            if kw in headers_lower.get("server", ""):
                scores[self.CLOUDFLARE] += 10
                break

        # ── AWS scoring ──
        for pattern in self.AWS_CNAME_PATTERNS:
            if pattern in cname_lower:
                scores[self.AWS] += 45
                break
        for hk in self.AWS_HEADER_KEYS:
            if hk in headers_lower:
                scores[self.AWS] += 35
                break
        if asn in self.AWS_ASN_LIST:
            scores[self.AWS] += 30
        for kw in self.AWS_TLS_KW:
            if kw in issuer_lower:
                scores[self.AWS] += 25
                break
        for kw in self.AWS_SERVER_KW:
            if kw in headers_lower.get("server", ""):
                scores[self.AWS] += 10
                break

        # ── Azure scoring ──
        for pattern in self.AZURE_CNAME_PATTERNS:
            if pattern in cname_lower:
                scores[self.AZURE] += 45
                break
        for hk in self.AZURE_HEADER_KEYS:
            if hk in headers_lower:
                scores[self.AZURE] += 35
                break
        if asn in self.AZURE_ASN_LIST:
            scores[self.AZURE] += 30
        for kw in self.AZURE_TLS_KW:
            if kw in issuer_lower:
                scores[self.AZURE] += 25
                break
        for kw in self.AZURE_SERVER_KW:
            if kw in headers_lower.get("server", ""):
                scores[self.AZURE] += 10
                break

        # ── Determine winner ──
        best_provider = max(scores, key=scores.get)
        if scores[best_provider] >= 40:
            return best_provider
        return None


# ╔══════════════════════════════════════════════════════════════════╗
# ║                  SUBDOMAIN ENUMERATOR                           ║
# ╚══════════════════════════════════════════════════════════════════╝

class SubdomainEnumerator:
    """Discovers subdomains via crt.sh and wordlist bruteforce."""
    def __init__(self, rate_limiter: RateLimiter, dns_engine: DNSEngine):
        self.rl = rate_limiter
        self.dns = dns_engine
        self.session = requests.Session()
        self.session.headers.update({"User-Agent": "CDNHostFinder/1.0"})
        self._crt_last_fetch: float = 0
        self._crt_known: Set[str] = set()

    def crtsh_fetch(self, domain: str) -> Set[str]:
        """Query crt.sh Certificate Transparency logs for subdomains."""
        self.rl.wait("crtsh", Config.RATE_CRTSH)
        subdomains: Set[str] = set()
        base = domain.lower().rstrip('.')
        try:
            url = f"https://crt.sh/?q=%25.{base}&output=json"
            resp = self.session.get(url, timeout=30)
            if resp.status_code == 200:
                data = resp.json()
                for entry in data:
                    name = entry.get("name_value", "").lower()
                    # crt.sh can return multiple names separated by newlines
                    for name_part in name.split("\n"):
                        name_part = name_part.strip().rstrip('.')
                        if name_part.endswith(f".{base}") and name_part != base:
                            # Remove wildcard prefix
                            if name_part.startswith("*."):
                                name_part = name_part[2:]
                            if name_part and name_part != base:
                                subdomains.add(name_part)
        except (requests.RequestException, json.JSONDecodeError, ValueError) as e:
            pass
        return subdomains

    def wordlist_bruteforce(self, domain: str) -> Set[str]:
        """Attempt to resolve common subdomains via DNS."""
        subdomains: Set[str] = set()
        base = domain.lower().rstrip('.')
        for prefix in Config.COMMON_SUBDOMAINS:
            candidate = f"{prefix}.{base}"
            ips = self.dns.resolve_a(candidate)
            if ips:
                subdomains.add(candidate)
        return subdomains


# ╔══════════════════════════════════════════════════════════════════╗
# ║                     RESULT MANAGER                              ║
# ╚══════════════════════════════════════════════════════════════════╝

class ResultManager:
    """Thread-safe storage for discovered hosts."""
    def __init__(self, output_file: str = "results.txt"):
        self.lock = threading.Lock()
        self.cloudflare: Set[str] = set()
        self.aws: Set[str] = set()
        self.azure: Set[str] = set()
        self.total_checked: int = 0
        self.output_file = output_file
        # Initialize results file
        with open(self.output_file, "w", encoding="utf-8") as f:
            f.write(f"# CDNHostFinder Results\n")
            f.write(f"# Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("#" + "=" * 59 + "\n\n")

    def add(self, domain: str, provider: str):
        """Add a domain to the appropriate provider set."""
        with self.lock:
            if provider == "Cloudflare":
                if domain not in self.cloudflare:
                    self.cloudflare.add(domain)
                    self._append_to_file(domain, "Cloudflare")
            elif provider == "Amazon CloudFront / AWS":
                if domain not in self.aws:
                    self.aws.add(domain)
                    self._append_to_file(domain, "Amazon CloudFront / AWS")
            elif provider == "Microsoft Azure":
                if domain not in self.azure:
                    self.azure.add(domain)
                    self._append_to_file(domain, "Microsoft Azure")

    def _append_to_file(self, domain: str, provider: str):
        """Immediately save single result to results.txt."""
        try:
            with open(self.output_file, "a", encoding="utf-8") as f:
                f.write(f"[{provider}] {domain}\n")
        except OSError:
            pass

    def increment_checked(self):
        with self.lock:
            self.total_checked += 1

    def get_counts(self) -> Tuple[int, int, int, int]:
        with self.lock:
            return (
                self.total_checked,
                len(self.cloudflare),
                len(self.aws),
                len(self.azure),
            )

    def get_all(self) -> Dict[str, List[str]]:
        with self.lock:
            return {
                "Cloudflare": sorted(self.cloudflare),
                "Amazon CloudFront / AWS": sorted(self.aws),
                "Microsoft Azure": sorted(self.azure),
            }


# ╔══════════════════════════════════════════════════════════════════╗
# ║                      DISPLAY ENGINE                             ║
# ╚══════════════════════════════════════════════════════════════════╝

class DisplayEngine:
    """Renders live terminal UI with ANSI escape codes."""

    SEP = "━" * 30

    def __init__(self, target_domain: str):
        self.target = target_domain
        self.running = True
        self._lock = threading.Lock()

    def stop(self):
        self.running = False

    def render(self, result_manager: ResultManager):
        """Main render loop – clears screen and redraws."""
        while self.running:
            counts = result_manager.get_counts()
            all_data = result_manager.get_all()
            self._draw(counts, all_data)
            time.sleep(0.5)

    def _draw(self, counts: Tuple[int, int, int, int],
              data: Dict[str, List[str]]):
        """Draw the full terminal UI."""
        checked, cf_count, aws_count, azure_count = counts

        # Clear screen and move cursor to home
        sys.stdout.write("\033[2J\033[H")
        sys.stdout.flush()

        # Header
        print(f"{Colors.CYAN}{Colors.BOLD}╔{'═'*58}╗{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}║{'CDN HOST FINDER v1.0':^58}║{Colors.RESET}")
        print(f"{Colors.CYAN}{Colors.BOLD}║{'Silent Hackers Team | @silent_ai_official':^58}║{Colors.RESET}")
        print(f"{Colors.CYAN}╠{'═'*58}╣{Colors.RESET}")
        print(f"{Colors.CYAN}║{Colors.RESET} Target: {Colors.YELLOW}{self.target:<48}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}╠{'═'*58}╣{Colors.RESET}")

        # Counters
        checked_str = f"Checked: {checked:,}"
        cf_str = f"CF: {cf_count:,}"
        aws_str = f"AWS: {aws_count:,}"
        azure_str = f"Azure: {azure_count:,}"
        print(f"{Colors.CYAN}║{Colors.RESET} {Colors.BOLD}{checked_str:<20}{Colors.RESET} {Colors.GREEN}{cf_str:<15}{Colors.RESET} "
              f"{Colors.YELLOW}{aws_str:<15}{Colors.RESET} {Colors.BLUE}{azure_str:<10}{Colors.CYAN}║{Colors.RESET}")
        print(f"{Colors.CYAN}╠{'═'*58}╣{Colors.RESET}")

        # Results sections
        self._print_section("Cloudflare", data.get("Cloudflare", []), Colors.GREEN)
        self._print_section("Amazon CloudFront / AWS", data.get("Amazon CloudFront / AWS", []), Colors.YELLOW)
        self._print_section("Microsoft Azure", data.get("Microsoft Azure", []), Colors.BLUE)

        # Footer
        print(f"{Colors.CYAN}╚{'═'*58}╝{Colors.RESET}")
        print(f"\n{Colors.DIM}[Ctrl+C] Stop & save  |  Results → results.txt{Colors.RESET}")

    def _print_section(self, title: str, domains: List[str], color: str):
        """Print a provider section."""
        print(f"{color}{self.SEP}{Colors.RESET}")
        print(f"{color}{Colors.BOLD}{title}{Colors.RESET}")
        print(f"{color}{self.SEP}{Colors.RESET}")
        if domains:
            for d in domains:
                print(f"  {d}")
        else:
            print(f"  {Colors.DIM}(no hosts discovered yet){Colors.RESET}")
        print()


# ╔══════════════════════════════════════════════════════════════════╗
# ║                     MAIN ORCHESTRATOR                           ║
# ╚══════════════════════════════════════════════════════════════════╝

class CDNHostFinder:
    """Main orchestrator for the CDN host discovery tool."""

    def __init__(self, domain: str):
        self.base_domain = domain.lower().rstrip('.')
        self.rate_limiter = RateLimiter()
        self.dns = DNSEngine(self.rate_limiter)
        self.http = HTTPInspector(self.rate_limiter)
        self.asn = ASNLookup(self.rate_limiter)
        self.detector = ProviderDetector()
        self.enumerator = SubdomainEnumerator(self.rate_limiter, self.dns)
        self.results = ResultManager()
        self.display = DisplayEngine(self.base_domain)
        self.shutdown_flag = threading.Event()

        # State
        self.target_queue: List[str] = [self.base_domain]
        self.seen_targets: Set[str] = {self.base_domain}
        self.last_crtsh_fetch: float = 0

    def validate_domain(self) -> bool:
        """Basic domain validation."""
        domain = self.base_domain
        # Must contain a dot and be at least 4 chars (e.g., a.co)
        if "." not in domain or len(domain) < 4:
            return False
        # Reject obviously invalid chars
        invalid = set("!@#$%^&*()+=[]{}|;:'\",<>/?\\`~ ")
        if any(c in invalid for c in domain):
            return False
        # DNS sanity check – try to resolve
        ips = self.dns.resolve_a(domain)
        cname = self.dns.resolve_cname(domain)
        if not ips and not cname:
            print(f"{Colors.YELLOW}[!] Warning: Could not resolve '{domain}' via DNS.{Colors.RESET}")
            print(f"{Colors.YELLOW}[!] Continuing anyway (may be behind proxy/CDN)...{Colors.RESET}")
            time.sleep(2)
        return True

    def discover_subdomains(self) -> List[str]:
        """Fetch subdomains from passive sources. Returns new targets."""
        new_targets: Set[str] = set()

        # crt.sh (periodic refresh)
        if time.monotonic() - self.last_crtsh_fetch > Config.CRTSH_REFRESH:
            crt_subs = self.enumerator.crtsh_fetch(self.base_domain)
            for sub in crt_subs:
                if sub not in self.seen_targets:
                    new_targets.add(sub)
            self.last_crtsh_fetch = time.monotonic()

        # Wordlist bruteforce (only on first pass)
        if len(self.seen_targets) <= len(Config.COMMON_SUBDOMAINS) + 5:
            wl_subs = self.enumerator.wordlist_bruteforce(self.base_domain)
            for sub in wl_subs:
                if sub not in self.seen_targets:
                    new_targets.add(sub)

        return list(new_targets)

    def analyze_host(self, host: str):
        """Deep-inspect a single host for CDN provider signals."""
        self.results.increment_checked()

        # DNS resolution
        ips = self.dns.resolve_a(host)
        ips += self.dns.resolve_aaaa(host)
        cname = self.dns.resolve_cname(host)
        ns_records = self.dns.resolve_ns(host)

        if not ips and not cname:
            return  # Dead domain, skip

        # HTTP/HTTPS
        http_status, http_headers = self.http.check_http(host)
        https_status, https_headers = self.http.check_https(host)

        # TLS certificate
        tls_issuer, tls_sans = self.http.get_tls_cert(host)

        # ASN lookup (use first resolved IP)
        asn = "N/A"
        org = "unknown"
        for ip in ips:
            asn, org = self.asn.lookup(ip)
            if asn != "N/A":
                break

        # Provider detection
        provider = self.detector.detect(
            domain=host,
            ips=ips,
            cname=cname,
            ns_records=ns_records,
            http_headers=http_headers,
            https_headers=https_headers,
            tls_issuer=tls_issuer,
            asn=asn,
            org=org,
        )

        if provider:
            self.results.add(host, provider)

        # Harvest new subdomains from TLS SAN and CNAME chains
        for san in tls_sans:
            if san.endswith(f".{self.base_domain}") and san not in self.seen_targets:
                self.target_queue.append(san)
                self.seen_targets.add(san)
        if cname and cname.endswith(f".{self.base_domain}") and cname not in self.seen_targets:
            self.target_queue.append(cname)
            self.seen_targets.add(cname)

    def run(self):
        """Main discovery loop."""
        # Validate domain
        if not self.validate_domain():
            print(f"{Colors.RED}[!] Invalid domain: {self.base_domain}{Colors.RESET}")
            sys.exit(1)

        # Start display thread
        display_thread = threading.Thread(target=self.display.render, args=(self.results,), daemon=True)
        display_thread.start()

        print(f"\n{Colors.GREEN}[+] Starting continuous discovery on: {self.base_domain}{Colors.RESET}")
        print(f"{Colors.DIM}[+] Passive sources: crt.sh (Certificate Transparency) + DNS wordlist{Colors.RESET}")
        print(f"{Colors.DIM}[+] Rate limits: DNS={Config.RATE_DNS}s, HTTP={Config.RATE_HTTP}s, API={Config.RATE_API}s{Colors.RESET}")
        print(f"{Colors.DIM}[+] Press Ctrl+C to stop and save results.{Colors.RESET}\n")
        time.sleep(1)

        try:
            while not self.shutdown_flag.is_set():
                # Discover new subdomains from passive sources
                new_targets = self.discover_subdomains()
                for t in new_targets:
                    if len(self.seen_targets) >= Config.MAX_TARGETS:
                        break
                    if t not in self.seen_targets:
                        self.target_queue.append(t)
                        self.seen_targets.add(t)

                # Process queue
                if not self.target_queue:
                    # Wait for crt.sh refresh interval
                    time.sleep(Config.CRTSH_REFRESH)
                    continue

                host = self.target_queue.pop(0)
                try:
                    self.analyze_host(host)
                except Exception as e:
                    # Silently skip failed hosts
                    pass

                # Small delay between hosts to be gentle
                time.sleep(0.05)

                # Safety – if queue empty and we've already fetched crt.sh, wait
                if not self.target_queue and len(self.seen_targets) > Config.MAX_TARGETS:
                    print(f"\n{Colors.YELLOW}[!] Reached target limit ({Config.MAX_TARGETS}).{Colors.RESET}")
                    break

        except KeyboardInterrupt:
            pass
        finally:
            self.shutdown_flag.set()
            self.display.stop()

            # Final summary
            self._print_final_summary()

    def _print_final_summary(self):
        """Print final summary after Ctrl+C."""
        checked, cf, aws, azure = self.results.get_counts()
        all_data = self.results.get_all()

        print(f"\n\n{Colors.CYAN}{'═'*58}{Colors.RESET}")
        print(f"{Colors.BOLD}{Colors.CYAN}  FINAL SUMMARY{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*58}{Colors.RESET}")
        print(f"  Target:      {Colors.YELLOW}{self.base_domain}{Colors.RESET}")
        print(f"  Checked:     {Colors.BOLD}{checked:,}{Colors.RESET} hosts")
        print(f"  Cloudflare:  {Colors.GREEN}{cf:,}{Colors.RESET}")
        print(f"  AWS/CF:      {Colors.YELLOW}{aws:,}{Colors.RESET}")
        print(f"  Azure:       {Colors.BLUE}{azure:,}{Colors.RESET}")
        print(f"{Colors.CYAN}{'─'*58}{Colors.RESET}")
        print(f"  Results saved to: {Colors.BOLD}results.txt{Colors.RESET}")
        print(f"{Colors.CYAN}{'═'*58}{Colors.RESET}\n")

        # Print provider sections in final output
        for provider, domains in all_data.items():
            if domains:
                color = {"Cloudflare": Colors.GREEN,
                         "Amazon CloudFront / AWS": Colors.YELLOW,
                         "Microsoft Azure": Colors.BLUE}.get(provider, Colors.RESET)
                print(f"{color}{'━'*30}{Colors.RESET}")
                print(f"{color}{Colors.BOLD}{provider}{Colors.RESET}")
                print(f"{color}{'━'*30}{Colors.RESET}")
                for d in domains:
                    print(f"  {d}")
                print()


# ╔══════════════════════════════════════════════════════════════════╗
# ║                         ENTRY POINT                             ║
# ╚══════════════════════════════════════════════════════════════════╝

def main():
    parser = argparse.ArgumentParser(
        description="CDNHostFinder – Passive CDN Infrastructure Discovery Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 hostfinder.py
  python3 hostfinder.py --domain example.com

Provider Detection:
  • Cloudflare – CNAME, cf-ray header, AS13335, TLS issuer
  • Amazon CloudFront / AWS – CNAME, x-amz-cf-id header, AS16509
  • Microsoft Azure – CNAME, x-azure-ref header, AS8075

Passive Sources:
  • crt.sh (Certificate Transparency logs)
  • DNS wordlist resolution (common subdomains)
  • ip-api.com (ASN/Organization lookup)
        """
    )
    parser.add_argument(
        "-d", "--domain",
        type=str,
        help="Target domain to scan (interactive prompt if not provided)"
    )
    parser.add_argument(
        "--no-color",
        action="store_true",
        help="Disable colored output"
    )
    args = parser.parse_args()

    if args.no_color:
        Colors.disable()

    # Suppress SSL warnings for HTTPS checks
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Banner
    print(f"{Colors.CYAN}{Colors.BOLD}")
    print("╔══════════════════════════════════════════════════════════╗")
    print("║        CDN HOST FINDER v1.0                             ║")
    print("║        Passive CDN Infrastructure Discovery             ║")
    print("║        Silent Hackers Team | @silent_ai_official        ║")
    print("╚══════════════════════════════════════════════════════════╝")
    print(f"{Colors.RESET}")
    print(f"{Colors.DIM}Target providers: Cloudflare | AWS CloudFront | Microsoft Azure{Colors.RESET}")
    print(f"{Colors.DIM}Passive sources:  crt.sh | DNS | ip-api.com{Colors.RESET}")
    print()

    # Get domain
    if args.domain:
        domain = args.domain.strip()
    else:
        try:
            domain = input(f"{Colors.GREEN}[?] Enter target domain: {Colors.RESET}").strip()
        except (EOFError, KeyboardInterrupt):
            print(f"\n{Colors.YELLOW}[!] Cancelled.{Colors.RESET}")
            sys.exit(0)

    if not domain:
        print(f"{Colors.RED}[!] No domain provided. Exiting.{Colors.RESET}")
        sys.exit(1)

    # Run finder
    finder = CDNHostFinder(domain)
    finder.run()


if __name__ == "__main__":
    main()
