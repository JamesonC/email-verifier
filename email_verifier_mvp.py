#!/usr/bin/env python3
"""
Email Verifier (async) — MX lookup + SMTP RCPT probe + catch-all detection with retries and resume support.

INPUT  CSV columns:  hs_object_id,email
OUTPUT CSV columns: hs_object_id,email,deliverability_status,reasons,domain,provider_response

QUICK START
    pip install dnspython==2.*
    python email_verifier_mvp.py --in contacts_in.csv --out contacts_out.csv \
        --helo-domain yourcompany.com --mail-from bounce@yourcompany.com \
        --rate 40 --concurrency 8 --progress-every 1000

DIRECT RUN EXAMPLE
    python email_verifier_mvp.py --in contacts_in.csv --out contacts_out.csv \
        --helo-domain sockclub.com --mail-from bounce@sockclub.com \
        --rate 40 --per-domain-rate 5 --concurrency 6 --progress-every 1000 \
        --resume --summary contacts_out.summary.json --summary-top-domains 20


KEY FLAGS
    --rate / --per-domain-rate      Global per-minute RCPT limit and optional per-domain cap.
    --concurrency                   Number of parallel workers (default 4).
    --pool-per-host                 Max pooled SMTP sessions per MX (default = concurrency).
    --timeout                       SMTP socket timeout in seconds (default 12).
    --dns-attempts / --dns-backoff  DNS retry count and base backoff seconds.
    --smtp-attempts / --smtp-backoff SMTP retry count and base backoff seconds for RCPT probes.
    --progress-every                Emit progress totals every N rows (0 disables logging).
    --resume                        Append to an existing output CSV, skipping rows already written.

Notes & Caveats:
- Many providers (Google/Microsoft) often accept RCPT even for bad users (catch-all or anti-harvesting),
  or defer rejection after DATA. Treat such domains as "catchall" or "unknown".
- Probing too fast can trigger throttling or blocks. Use rate + per-domain controls and consider jittering.
- Never use a null sender for some MTAs; others prefer <>. The default uses a benign MAIL FROM, configurable.
- This script does NOT send an email (no DATA). It stops after RCPT TO.
- Results are best-effort. Combine with internal bounce/quarantine data where possible.
- Resume mode expects the existing CSV to be intact with the original header.
"""

import argparse
import asyncio
import csv
import random
import re
import smtplib
import socket
import ssl
import threading
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from email.utils import parseaddr
import os
import json
from typing import Optional, Tuple

try:
    import dns.resolver
    import dns.exception
except ImportError as e:
    raise SystemExit("Missing dependency dnspython. Install with: pip install dnspython") from e

EMAIL_REGEX = re.compile(
    # Simple, pragmatic pattern; we still also use parseaddr
    r"^[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}$",
    re.IGNORECASE,
)

# Map common SMTP codes to human-friendly interpretation
HARD_FAIL = {550, 551, 553, 554, 521}
SOFT_FAIL = {421, 450, 451, 452, 447}
AMBIGUOUS = {252, 551}  # 551 can be user not local; relay, so ambiguous

MAX_DNS_ATTEMPTS = 3
MAX_SMTP_ATTEMPTS = 3
DNS_BACKOFF_BASE = 0.5
SMTP_BACKOFF_BASE = 0.75
SMTP_RETRYABLE_EXCEPTIONS = (
    socket.timeout,
    ConnectionResetError,
    smtplib.SMTPServerDisconnected,
    smtplib.SMTPConnectError,
    smtplib.SMTPHeloError,
    smtplib.SMTPRecipientsRefused,
)

ROLE_ACCOUNTS = {
    "admin",
    "billing",
    "contact",
    "customerservice",
    "enquiries",
    "help",
    "hello",
    "info",
    "marketing",
    "newsletter",
    "noreply",
    "press",
    "privacy",
    "sales",
    "support",
    "team",
}

DEFAULT_DISPOSABLE_DOMAINS = {
    "mailinator.com",
    "10minutemail.com",
    "guerrillamail.com",
    "tempmail.com",
    "trashmail.com",
    "yopmail.com",
    "dispostable.com",
    "getnada.com",
}

@dataclass
class VerifyResult:
    status: str            # valid | invalid | risky_catchall | unknown | no_mx | bad_syntax
    reasons: str
    provider_response: str = ""


@dataclass
class Counters:
    total: int = 0
    valid: int = 0
    invalid: int = 0
    risky: int = 0
    unknown: int = 0
    nomx: int = 0
    bad: int = 0

    def add(self, status: str) -> None:
        self.total += 1
        if status == "valid":
            self.valid += 1
        elif status == "invalid":
            self.invalid += 1
        elif status in {"risky_catchall", "risky_role_account", "risky_disposable"}:
            self.risky += 1
        elif status == "no_mx":
            self.nomx += 1
        elif status == "bad_syntax":
            self.bad += 1
        else:
            self.unknown += 1


@dataclass
class SMTPProbeOutcome:
    code: int
    message: str
    attempts: int
    history: list[str]


class SMTPProbeRetryError(Exception):
    def __init__(self, exc: Exception, attempts: int, history: list[str]) -> None:
        super().__init__(str(exc))
        self.exc = exc
        self.attempts = attempts
        self.history = history


@dataclass
class ResumeState:
    enabled: bool
    processed_keys: set[tuple[str, str]]
    counters: Counters
    processed_rows: int
    heuristic_counts: dict[str, int]
    domain_failures: dict[str, int]


class AsyncRateLimiter:
    """Sliding-window rate limiter for global and per-domain control."""

    def __init__(self, global_rate: int, per_domain_rate: Optional[int], period: float = 60.0) -> None:
        self.global_rate = max(0, global_rate)
        self.per_domain_rate = max(0, per_domain_rate or 0)
        self.period = period
        self._global_lock = asyncio.Lock()
        self._global_events: deque[float] = deque()
        self._domain_events: dict[str, deque[float]] = defaultdict(deque)
        self._domain_locks: dict[str, asyncio.Lock] = {}

    async def acquire(self, domain: str) -> None:
        if self.global_rate:
            await self._acquire(self._global_lock, self._global_events, self.global_rate)
        if domain and self.per_domain_rate:
            lock = self._domain_locks.setdefault(domain, asyncio.Lock())
            events = self._domain_events[domain]
            await self._acquire(lock, events, self.per_domain_rate)

    async def _acquire(self, lock: asyncio.Lock, events: deque[float], rate: int) -> None:
        while True:
            async with lock:
                now = time.monotonic()
                self._trim(events, now)
                if len(events) < rate:
                    events.append(now)
                    return
                wait_time = self.period - (now - events[0])
            await asyncio.sleep(max(wait_time, 0.05))

    def _trim(self, events: deque[float], now: float) -> None:
        threshold = now - self.period
        while events and events[0] <= threshold:
            events.popleft()


class SMTPConnection:
    """Thin wrapper around smtplib.SMTP with reusable RCPT probe support."""

    def __init__(self, host: str, helo_domain: str, timeout: int, use_starttls: bool = True) -> None:
        self.host = host
        self.helo_domain = helo_domain
        self.timeout = timeout
        self.use_starttls = use_starttls
        self.closed = False
        self._context = ssl.create_default_context()
        self.server = self._connect()

    def _connect(self) -> smtplib.SMTP:
        server = smtplib.SMTP(self.host, 25, timeout=self.timeout)
        server.set_debuglevel(0)
        try:
            server.ehlo(self.helo_domain)
        except Exception:
            server.helo(self.helo_domain)
        if self.use_starttls:
            try:
                if server.has_extn("starttls"):
                    server.starttls(context=self._context)
                    server.ehlo(self.helo_domain)
            except Exception:
                # Leave the connection in plaintext if STARTTLS fails
                pass
        return server

    def probe(self, mail_from: str, rcpt_to: str) -> Tuple[int, str]:
        if self.closed:
            raise smtplib.SMTPServerDisconnected("SMTP connection already closed")

        try:
            mail_code, mail_msg = self.server.mail(mail_from)
            if mail_code >= 400:
                # Reset transaction before returning
                try:
                    self.server.rset()
                except Exception:
                    pass
                message = (mail_msg or b"").decode(errors="ignore")
                return mail_code, message

            code, msg = self.server.rcpt(rcpt_to)
            message = (msg or b"").decode(errors="ignore")
            try:
                self.server.rset()
            except Exception:
                # Some servers may not allow RSET here; ignore
                pass
            return code, message
        except Exception:
            self.close()
            raise

    def close(self) -> None:
        if self.closed:
            return
        self.closed = True
        try:
            self.server.quit()
        except Exception:
            try:
                self.server.close()
            except Exception:
                pass


class SMTPConnectionPool:
    """Thread-safe SMTP connection pool keyed by MX host."""

    def __init__(
        self,
        helo_domain: str,
        timeout: int,
        use_starttls: bool = True,
        max_per_host: int = 4,
    ) -> None:
        self.helo_domain = helo_domain
        self.timeout = timeout
        self.use_starttls = use_starttls
        self.max_per_host = max(1, max_per_host)
        self._lock = threading.Lock()
        self._available: dict[str, deque[SMTPConnection]] = defaultdict(deque)
        self._in_use: dict[str, int] = defaultdict(int)

    def acquire(self, host: str) -> SMTPConnection:
        while True:
            with self._lock:
                queue = self._available.get(host)
                if queue:
                    conn = queue.popleft()
                    self._in_use[host] += 1
                    if conn.closed:
                        self._in_use[host] -= 1
                        continue
                    return conn

                current = self._in_use.get(host, 0)
                if current < self.max_per_host:
                    self._in_use[host] = current + 1
                    create_new = True
                else:
                    create_new = False

            if create_new:
                try:
                    return SMTPConnection(host, self.helo_domain, self.timeout, self.use_starttls)
                except Exception:
                    with self._lock:
                        self._in_use[host] -= 1
                    raise

            time.sleep(0.05)

    def release(self, host: str, conn: SMTPConnection, keep: bool = True) -> None:
        with self._lock:
            self._in_use[host] = max(self._in_use.get(host, 1) - 1, 0)
            if keep and not conn.closed:
                self._available[host].append(conn)
            else:
                conn.close()
            if not self._available[host] and self._in_use[host] == 0:
                self._available.pop(host, None)
                self._in_use.pop(host, None)

    def probe(self, host: str, mail_from: str, rcpt_to: str) -> Tuple[int, str]:
        conn = self.acquire(host)
        try:
            return conn.probe(mail_from, rcpt_to)
        finally:
            self.release(host, conn, keep=not conn.closed)

    def close_all(self) -> None:
        with self._lock:
            for queue in self._available.values():
                while queue:
                    conn = queue.popleft()
                    conn.close()
            self._available.clear()
            # Connections in use should be zero here; clear counters for cleanliness
            self._in_use.clear()

def normalize_email(addr: str) -> str:
    addr = (addr or "").strip()
    name, email = parseaddr(addr)
    return email.lower()

def is_syntax_valid(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))


def load_disposable_domains(path: Optional[str]) -> set[str]:
    if not path:
        return set(DEFAULT_DISPOSABLE_DOMAINS)

    domains: set[str] = set(DEFAULT_DISPOSABLE_DOMAINS)
    try:
        with open(path, encoding="utf-8") as fh:
            for line in fh:
                domain = line.strip().lower()
                if not domain or domain.startswith("#"):
                    continue
                domains.add(domain)
    except FileNotFoundError:
        raise SystemExit(f"Disposable domain file not found: {path}")
    return domains


def detect_heuristics(local_part: str, domain: str, disposable_domains: set[str]) -> set[str]:
    flags: set[str] = set()
    if local_part in ROLE_ACCOUNTS:
        flags.add("role_account")
    if domain and domain in disposable_domains:
        flags.add("disposable_domain")
    return flags


def mx_lookup(domain: str, attempts: int, backoff_base: float) -> list[Tuple[int, str]]:
    last_exc: Optional[Exception] = None
    for attempt in range(1, attempts + 1):
        try:
            answers = dns.resolver.resolve(
                domain,
                "MX",
                lifetime=10.0,
                raise_on_no_answer=False,
            )
            mx_records = []
            if answers.rrset is None:
                return mx_records
            for rdata in answers:
                mx_records.append((int(rdata.preference), str(rdata.exchange).rstrip(".")))
            return sorted(mx_records, key=lambda x: x[0])
        except dns.resolver.NXDOMAIN:
            raise
        except (dns.resolver.Timeout, dns.exception.Timeout, dns.resolver.NoNameservers, dns.resolver.LifetimeTimeout) as exc:
            last_exc = exc
        except dns.exception.DNSException as exc:
            last_exc = exc

        if attempt < attempts:
            delay = backoff_base * (2 ** (attempt - 1)) + random.uniform(0, backoff_base)
            time.sleep(delay)
        else:
            if last_exc is not None:
                raise last_exc
    return []


def classify_dns_exception(exc: Exception) -> Tuple[str, str]:
    if isinstance(exc, dns.resolver.NXDOMAIN):
        return "no_mx", "dns_nxdomain"
    if isinstance(exc, dns.resolver.NoAnswer):
        return "no_mx", "dns_no_answer"
    if isinstance(exc, dns.resolver.NoNameservers):
        return "unknown", "dns_nonameservers"
    if isinstance(exc, (dns.resolver.Timeout, dns.exception.Timeout, dns.resolver.LifetimeTimeout)):
        return "unknown", "dns_timeout"
    return "unknown", f"dns_error:{exc.__class__.__name__}"

def load_resume_state(out_path: str, resume_flag: bool) -> ResumeState:
    counters = Counters()
    if not resume_flag or not os.path.exists(out_path):
        return ResumeState(False, set(), counters, 0, defaultdict(int), defaultdict(int))

    processed_keys: set[tuple[str, str]] = set()
    processed_rows = 0
    heuristic_counts: dict[str, int] = defaultdict(int)
    domain_failures: dict[str, int] = defaultdict(int)

    try:
        with open(out_path, newline="", encoding="utf-8") as f_out:
            reader = csv.DictReader(f_out)
            for row in reader:
                processed_rows += 1
                hsid = (row.get("hs_object_id") or "").strip()
                email = normalize_email(row.get("email") or "")
                processed_keys.add((hsid, email))
                status = (row.get("deliverability_status") or "").strip()
                counters.add(status)
                reasons = (row.get("reasons") or "").split(";")
                for reason in reasons:
                    if reason.startswith("heuristic:"):
                        heuristic_counts[reason[len("heuristic:"):]] += 1
                if status in {"invalid", "no_mx", "unknown"}:
                    domain = (row.get("domain") or "").strip().lower()
                    if domain:
                        domain_failures[domain] += 1
    except FileNotFoundError:
        return ResumeState(False, set(), Counters(), 0, defaultdict(int), defaultdict(int))

    return ResumeState(True, processed_keys, counters, processed_rows, heuristic_counts, domain_failures)


def smtp_probe(
    mx_host: str,
    helo_domain: str,
    mail_from: str,
    rcpt_to: str,
    timeout=12,
    use_starttls=True,
    connection_pool: Optional[SMTPConnectionPool] = None,
) -> Tuple[int, str]:
    """Connect to MX, run (EHLO/HELO), optional STARTTLS, then MAIL FROM/RCPT TO. Return (code, message)."""
    if connection_pool is not None:
        return connection_pool.probe(mx_host, mail_from, rcpt_to)

    code = -1
    message = ""
    context = ssl.create_default_context()
    with smtplib.SMTP(mx_host, 25, timeout=timeout) as server:
        server.set_debuglevel(0)
        # Some servers want EHLO; if it fails, fallback to HELO
        try:
            code, msg = server.ehlo(helo_domain)
        except Exception:
            code, msg = server.helo(helo_domain)
        # Upgrade to TLS if offered
        if use_starttls:
            try:
                if server.has_extn("starttls"):
                    code, msg = server.starttls(context=context)
                    code, msg = server.ehlo(helo_domain)
            except Exception:
                # If TLS fails, keep going unencrypted
                pass
        # Use a benign sender; many servers treat <> specially; use configured MAIL FROM
        code, msg = server.mail(mail_from)
        code, msg = server.rcpt(rcpt_to)
        message = (msg or b"").decode(errors="ignore")
    return code, message


def smtp_probe_with_retry(
    mx_host: str,
    helo_domain: str,
    mail_from: str,
    rcpt_to: str,
    connection_pool: Optional[SMTPConnectionPool],
    timeout: int,
    attempts: int = MAX_SMTP_ATTEMPTS,
    backoff_base: float = SMTP_BACKOFF_BASE,
) -> SMTPProbeOutcome:
    history: list[str] = []
    last_exc: Optional[Exception] = None

    for attempt in range(1, max(1, attempts) + 1):
        try:
            code, msg = smtp_probe(
                mx_host,
                helo_domain,
                mail_from,
                rcpt_to,
                timeout=timeout,
                connection_pool=connection_pool,
            )

            if code in SOFT_FAIL and attempt < attempts:
                history.append(f"soft_fail:{code}")
                delay = backoff_base * (2 ** (attempt - 1)) + random.uniform(0, backoff_base)
                time.sleep(delay)
                continue

            return SMTPProbeOutcome(code=code, message=msg, attempts=attempt, history=history)
        except SMTP_RETRYABLE_EXCEPTIONS as exc:
            last_exc = exc
            history.append(f"exception:{exc.__class__.__name__}")
            if attempt >= attempts:
                raise SMTPProbeRetryError(exc, attempt, history) from exc
            delay = backoff_base * (2 ** (attempt - 1)) + random.uniform(0, backoff_base)
            time.sleep(delay)

    if last_exc is not None:
        raise SMTPProbeRetryError(last_exc, max(1, attempts), history) from last_exc

    raise SMTPProbeRetryError(RuntimeError("smtp_retry_failed"), max(1, attempts), history)

def random_local_part() -> str:
    return "no_such_user_" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(20))

def verify_single(
    email: str,
    helo_domain: str,
    mail_from: str,
    domain_cache: dict,
    ca_cache: dict,
    connection_pool: Optional[SMTPConnectionPool],
    timeout: int,
    dns_attempts: int,
    dns_backoff: float,
    smtp_attempts: int,
    smtp_backoff: float,
) -> VerifyResult:
    email = normalize_email(email)
    if not email or not is_syntax_valid(email):
        return VerifyResult("bad_syntax", "failed_regex_or_empty")

    local, _, domain = email.partition("@")
    # MX cache
    if domain not in domain_cache:
        try:
            mx_list = mx_lookup(domain, attempts=dns_attempts, backoff_base=dns_backoff)
            domain_cache[domain] = mx_list
        except Exception as e:
            status, reason = classify_dns_exception(e)
            return VerifyResult(status, reason)

    mx_list = domain_cache[domain]
    if not mx_list:
        return VerifyResult("no_mx", "no_mx_records_found")

    # Catch‑all cache (per domain)
    if domain not in ca_cache:
        test_addr = f"{random_local_part()}@{domain}"
        ca_status = "unknown"
        for _, mx in mx_list[:2]:  # try top 1-2 MX hosts
            try:
                outcome = smtp_probe_with_retry(
                    mx,
                    helo_domain,
                    mail_from,
                    test_addr,
                    connection_pool=connection_pool,
                    timeout=timeout,
                    attempts=smtp_attempts,
                    backoff_base=smtp_backoff,
                )
                code, msg = outcome.code, outcome.message
                if code in HARD_FAIL:
                    ca_status = "not_catchall"
                    break
                elif code in SOFT_FAIL or code in AMBIGUOUS or 200 <= code < 300:
                    # If accepted or ambiguous, lean to catch‑all (not definitive)
                    ca_status = "catchall_suspected"
                    # don't break immediately; try another MX for confirmation
            except SMTPProbeRetryError:
                # transient or refused even after retries; keep trying others
                continue
            except Exception:
                continue
        ca_cache[domain] = ca_status

    # Now probe the actual recipient
    last_code, last_msg = -1, ""
    verdict = "unknown"
    reasons = []

    # If domain looks catch‑all, we may still attempt RCPT; result may still be 250
    for _, mx in mx_list[:2]:
        try:
            outcome = smtp_probe_with_retry(
                mx,
                helo_domain,
                mail_from,
                email,
                connection_pool=connection_pool,
                timeout=timeout,
                attempts=smtp_attempts,
                backoff_base=smtp_backoff,
            )
            code, msg = outcome.code, outcome.message
            last_code, last_msg = code, msg
            if outcome.history:
                reasons.extend(f"smtp_retry:{entry}" for entry in outcome.history)
            if outcome.attempts > 1:
                reasons.append(f"smtp_attempts:{outcome.attempts}")
            if code in HARD_FAIL:
                verdict = "invalid"
                reasons.append(f"smtp_hard_fail:{code}")
                break
            elif 200 <= code < 300:
                verdict = "valid"
                reasons.append(f"smtp_ok:{code}")
                # Don't break yet; if catch‑all suspected, we'll mark risky below
                break
            elif code in SOFT_FAIL:
                verdict = "unknown"
                reasons.append(f"smtp_soft_fail:{code}")
                # try next MX
            elif code in AMBIGUOUS:
                verdict = "unknown"
                reasons.append(f"smtp_ambiguous:{code}")
            else:
                reasons.append(f"smtp_other:{code}")
        except SMTPProbeRetryError as e:
            reasons.extend(f"smtp_retry:{entry}" for entry in e.history)
            reasons.append(f"smtp_retry_error:{e.exc.__class__.__name__}")
            reasons.append(f"smtp_retry_attempts:{e.attempts}")
            continue
        except Exception as e:
            reasons.append(f"error:{e.__class__.__name__}")
            continue

    # Catch‑all post‑processing
    ca_flag = ca_cache.get(domain)
    if verdict == "valid" and ca_flag == "catchall_suspected":
        verdict = "risky_catchall"
        reasons.append("domain_catchall_suspected")

    return VerifyResult(verdict, ";".join(reasons), f"{last_code} {last_msg}".strip())


async def worker(
    worker_id: int,
    row_queue: "asyncio.Queue[Optional[tuple[int, dict[str, str]]]]",
    result_queue: "asyncio.Queue[tuple[int, dict[str, str], VerifyResult]]",
    args,
    rate_limiter: AsyncRateLimiter,
    domain_cache: dict,
    catchall_cache: dict,
    connection_pool: SMTPConnectionPool,
    executor: ThreadPoolExecutor,
    dns_attempts: int,
    dns_backoff: float,
    smtp_attempts: int,
    smtp_backoff: float,
) -> None:
    loop = asyncio.get_running_loop()
    while True:
        item = await row_queue.get()
        if item is None:
            row_queue.task_done()
            break

        idx, row = item
        hsid = (row.get("hs_object_id") or "").strip()
        email = normalize_email(row.get("email") or row.get("Email") or "")
        domain = email.split("@")[-1] if "@" in email else ""
        local = email.split("@")[0] if "@" in email else ""

        heuristics = detect_heuristics(local, domain, args.disposable_domains)

        await rate_limiter.acquire(domain)

        result = await loop.run_in_executor(
            executor,
            verify_single,
            email,
            args.helo_domain,
            args.mail_from,
            domain_cache,
            catchall_cache,
            connection_pool,
            args.timeout,
            dns_attempts,
            dns_backoff,
            smtp_attempts,
            smtp_backoff,
        )

        # Enrich result with heuristic flags while preserving underlying verdict
        updated_result = result
        if heuristics:
            reason_list = [r for r in result.reasons.split(";") if r]
            for flag in sorted(heuristics):
                reason_list.append(f"heuristic:{flag}")

            base_status = result.status
            override_status = base_status
            if "disposable_domain" in heuristics and base_status not in {"invalid", "bad_syntax", "no_mx"}:
                reason_list.append(f"base_status:{base_status}")
                override_status = "risky_disposable"
            elif "role_account" in heuristics and base_status not in {"invalid", "bad_syntax", "no_mx"}:
                reason_list.append(f"base_status:{base_status}")
                override_status = "risky_role_account"

            updated_result = VerifyResult(
                override_status,
                ";".join(reason_list),
                result.provider_response,
            )

        await result_queue.put((idx, {
            "hs_object_id": hsid,
            "email": email,
            "domain": domain,
        }, updated_result))

        row_queue.task_done()


async def writer_loop(
    result_queue: "asyncio.Queue[tuple[int, dict[str, str], VerifyResult]]",
    writer: csv.DictWriter,
    counters: Counters,
    progress_interval: int,
    summary_state: dict,
) -> None:
    next_index = 0
    pending: dict[int, tuple[dict[str, str], VerifyResult]] = {}

    while True:
        item = await result_queue.get()
        if item is None:
            result_queue.task_done()
            break

        idx, row_meta, result = item
        pending[idx] = (row_meta, result)

        while next_index in pending:
            row_meta, result = pending.pop(next_index)
            status = result.status
            counters.add(status)
            writer.writerow({
                "hs_object_id": row_meta["hs_object_id"],
                "email": row_meta["email"],
                "deliverability_status": status,
                "reasons": result.reasons,
                "domain": row_meta["domain"],
                "provider_response": result.provider_response,
            })
            if progress_interval and counters.total % progress_interval == 0:
                print(
                    f"[progress] processed={counters.total} valid={counters.valid} invalid={counters.invalid} "
                    f"risky={counters.risky} unknown={counters.unknown} no_mx={counters.nomx} bad_syntax={counters.bad}",
                    flush=True,
                )
            # Update summary data
            if status in {"invalid", "no_mx", "unknown"}:
                domain = row_meta["domain"].lower()
                if domain:
                    summary_state["domain_failures"][domain] = summary_state["domain_failures"].get(domain, 0) + 1
            if result.reasons:
                for reason in result.reasons.split(";"):
                    if reason.startswith("heuristic:"):
                        flag = reason[len("heuristic:"):]
                        summary_state["heuristics"][flag] = summary_state["heuristics"].get(flag, 0) + 1
            next_index += 1

        result_queue.task_done()

    # Flush any stragglers if the sentinel arrives before they were written
    for idx in sorted(pending.keys()):
        row_meta, result = pending[idx]
        status = result.status
        counters.add(status)
        writer.writerow({
            "hs_object_id": row_meta["hs_object_id"],
            "email": row_meta["email"],
            "deliverability_status": status,
            "reasons": result.reasons,
            "domain": row_meta["domain"],
            "provider_response": result.provider_response,
        })
        if progress_interval and counters.total % progress_interval == 0:
            print(
                f"[progress] processed={counters.total} valid={counters.valid} invalid={counters.invalid} "
                f"risky={counters.risky} unknown={counters.unknown} no_mx={counters.nomx} bad_syntax={counters.bad}",
                flush=True,
            )
        if status in {"invalid", "no_mx", "unknown"}:
            domain = row_meta["domain"].lower()
            if domain:
                summary_state["domain_failures"][domain] = summary_state["domain_failures"].get(domain, 0) + 1
        if result.reasons:
            for reason in result.reasons.split(";"):
                if reason.startswith("heuristic:"):
                    flag = reason[len("heuristic:"):]
                    summary_state["heuristics"][flag] = summary_state["heuristics"].get(flag, 0) + 1


async def process_rows(
    args,
    reader: csv.DictReader,
    writer: csv.DictWriter,
    counters: Counters,
    resume_state: ResumeState,
) -> None:
    rate_per_min = max(1, args.rate)
    per_domain_rate = args.per_domain_rate
    if per_domain_rate is None:
        per_domain_rate = max(1, rate_per_min // 5) if rate_per_min >= 5 else 1

    rate_limiter = AsyncRateLimiter(rate_per_min, per_domain_rate)
    domain_cache: dict[str, list[Tuple[int, str]]] = {}
    catchall_cache: dict[str, str] = {}

    concurrency = max(1, args.concurrency)
    dns_attempts = max(1, args.dns_attempts)
    dns_backoff = max(0.0, args.dns_backoff)
    smtp_attempts = max(1, args.smtp_attempts)
    smtp_backoff = max(0.0, args.smtp_backoff)
    progress_interval = max(0, args.progress_every)

    row_queue: asyncio.Queue[Optional[tuple[int, dict[str, str]]]] = asyncio.Queue(maxsize=concurrency * 4)
    result_queue: asyncio.Queue[tuple[int, dict[str, str], VerifyResult]] = asyncio.Queue(maxsize=concurrency * 4)

    connection_pool = SMTPConnectionPool(
        args.helo_domain,
        args.timeout,
        use_starttls=True,
        max_per_host=max(1, args.pool_per_host or concurrency),
    )

    try:
        summary_state = {
            "heuristics": dict(resume_state.heuristic_counts),
            "domain_failures": dict(resume_state.domain_failures),
        }
        with ThreadPoolExecutor(max_workers=concurrency) as executor:
            workers = [
                asyncio.create_task(
                    worker(
                        i,
                        row_queue,
                        result_queue,
                        args,
                        rate_limiter,
                        domain_cache,
                        catchall_cache,
                        connection_pool,
                        executor,
                        dns_attempts,
                        dns_backoff,
                        smtp_attempts,
                        smtp_backoff,
                    )
                )
                for i in range(concurrency)
            ]

        writer_task = asyncio.create_task(
            writer_loop(result_queue, writer, counters, progress_interval, summary_state)
        )

        skipped_existing = 0
        queued = 0
        for row in reader:
            hsid_raw = (row.get("hs_object_id") or "").strip()
            email_norm = normalize_email(row.get("email") or row.get("Email") or "")
            key = (hsid_raw, email_norm)
            if resume_state.enabled and key in resume_state.processed_keys:
                skipped_existing += 1
                continue
            await row_queue.put((queued, row))
            queued += 1

        if resume_state.enabled and resume_state.processed_rows:
            print(
                f"[resume] existing rows found: {resume_state.processed_rows}, skipped during enqueue: {skipped_existing}",
                flush=True,
            )
        elif skipped_existing:
            print(
                f"[resume] skipped {skipped_existing} rows (already processed)",
                flush=True,
            )

        if queued == 0:
            print("[resume] no new rows to process", flush=True)

        for _ in workers:
            await row_queue.put(None)

        await asyncio.gather(*workers)
        await result_queue.put(None)
        await writer_task
    finally:
        connection_pool.close_all()
        args.summary_state = summary_state

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_csv", required=True, help="Input CSV with columns hs_object_id,email")
    ap.add_argument("--out", dest="out_csv", required=True, help="Output CSV path")
    ap.add_argument("--helo-domain", required=True, help="Your HELO/EHLO domain (e.g., yourcompany.com)")
    ap.add_argument("--mail-from", default="bounce@localhost", help="MAIL FROM address used in probe")
    ap.add_argument("--rate", type=int, default=12, help="Max RCPT probes per minute (default=12)")
    ap.add_argument("--timeout", type=int, default=12, help="Seconds SMTP timeout per connection")
    ap.add_argument("--concurrency", type=int, default=4, help="Number of concurrent verification workers")
    ap.add_argument("--per-domain-rate", type=int, default=None, help="Max RCPT probes per minute per domain (default=derived from --rate)")
    ap.add_argument("--dns-attempts", dest="dns_attempts", type=int, default=MAX_DNS_ATTEMPTS, help="Max DNS lookup attempts per domain")
    ap.add_argument("--dns-backoff", type=float, default=DNS_BACKOFF_BASE, help="Base seconds for DNS retry backoff")
    ap.add_argument("--smtp-attempts", type=int, default=MAX_SMTP_ATTEMPTS, help="Max SMTP RCPT attempts per MX host")
    ap.add_argument("--smtp-backoff", type=float, default=SMTP_BACKOFF_BASE, help="Base seconds for SMTP retry backoff")
    ap.add_argument("--progress-every", type=int, default=500, help="Print progress every N processed rows (0 to disable)")
    ap.add_argument("--pool-per-host", type=int, default=None, help="Max pooled SMTP connections per MX host (default=concurrency)")
    ap.add_argument("--disposable-domain-file", type=str, default=None, help="Optional newline-delimited disposable domain list")
    ap.add_argument("--resume", action="store_true", help="Resume from existing output file, skipping rows already processed")
    ap.add_argument("--summary", type=str, default=None, help="Path for JSON summary (defaults to <out>.summary.json)")
    ap.add_argument("--summary-top-domains", type=int, default=15, help="Number of top failing domains to include in summary")
    args = ap.parse_args()

    args.disposable_domains = load_disposable_domains(args.disposable_domain_file)

    counters = asyncio.run(run_async(args))

    print(
        "Done. Total={total} valid={valid} invalid={invalid} risky_catchall={risky} "
        "no_mx={nomx} bad_syntax={bad} unknown={unknown}".format(
            total=counters.total,
            valid=counters.valid,
            invalid=counters.invalid,
            risky=counters.risky,
            nomx=counters.nomx,
            bad=counters.bad,
            unknown=counters.unknown,
        )
    )


async def run_async(args) -> Counters:
    resume_state = load_resume_state(args.out_csv, args.resume)
    counters = resume_state.counters

    mode = "a" if resume_state.enabled and resume_state.processed_rows > 0 else "w"

    with open(args.in_csv, newline="", encoding="utf-8") as f_in, open(args.out_csv, mode, newline="", encoding="utf-8") as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = [
            "hs_object_id",
            "email",
            "deliverability_status",
            "reasons",
            "domain",
            "provider_response",
        ]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        if mode == "w":
            writer.writeheader()
        elif resume_state.processed_rows == 0:
            # Existing file without data; ensure header present
            writer.writeheader()

        await process_rows(args, reader, writer, counters, resume_state)

    # After processing, produce summary report
    summary_path = args.summary or f"{args.out_csv}.summary.json"
    summary_payload = {
        "input": os.path.abspath(args.in_csv),
        "output": os.path.abspath(args.out_csv),
        "summary": {
            "total": counters.total,
            "valid": counters.valid,
            "invalid": counters.invalid,
            "risky": counters.risky,
            "no_mx": counters.nomx,
            "bad_syntax": counters.bad,
            "unknown": counters.unknown,
        },
        "heuristics": dict(args.summary_state.get("heuristics", {})),
        "top_domain_failures": sorted(
            args.summary_state.get("domain_failures", {}).items(),
            key=lambda x: x[1],
            reverse=True,
        )[: args.summary_top_domains],
    }

    try:
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary_payload, fh, indent=2)
        print(f"[summary] wrote {summary_path}")
    except Exception as exc:
        print(f"[summary] failed to write summary: {exc}")

    return counters

if __name__ == "__main__":
    main()
