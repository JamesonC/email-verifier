#!/usr/bin/env python3
"""
Email Verifier (MVP) — MX lookup + SMTP RCPT probe + catch‑all detection.
Reads a CSV with columns: hs_object_id,email
Writes a CSV with columns: hs_object_id,email,deliverability_status,reasons,domain,provider_response

USAGE:
  pip install dnspython==2.*
  python email_verifier_mvp.py --in contacts_in.csv --out contacts_out.csv \
      --helo-domain yourcompany.com --mail-from bounce@yourcompany.com --rate 10

Notes & Caveats:
- Many providers (Google/Microsoft) often accept RCPT during SMTP even for bad users (catch‑all or anti‑harvesting), or defer rejection after DATA. Treat such domains as "catchall" or "unknown".
- Probing too fast can trigger throttling or blocks. Use --rate to limit RCPTs per minute.
- Never use a null sender for some MTAs; others prefer <>. The default uses a benign MAIL FROM, configurable.
- This script does NOT send an email (no DATA). It stops after RCPT TO.
- Results are best‑effort and not perfect. Consider combining with your internal (bounce/quarantine) data.
"""

import argparse
import asyncio
import csv
import random
import re
import smtplib
import socket
import ssl
import time
from collections import defaultdict, deque
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass
from email.utils import parseaddr
from typing import Optional, Tuple

try:
    import dns.resolver
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
        elif status == "risky_catchall":
            self.risky += 1
        elif status == "no_mx":
            self.nomx += 1
        elif status == "bad_syntax":
            self.bad += 1
        else:
            self.unknown += 1


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

def normalize_email(addr: str) -> str:
    addr = (addr or "").strip()
    name, email = parseaddr(addr)
    return email.lower()

def is_syntax_valid(email: str) -> bool:
    return bool(EMAIL_REGEX.match(email))

def mx_lookup(domain: str) -> list[Tuple[int, str]]:
    answers = dns.resolver.resolve(domain, "MX")
    mx_records = []
    for rdata in answers:
        mx_records.append((int(rdata.preference), str(rdata.exchange).rstrip(".")))
    return sorted(mx_records, key=lambda x: x[0])

def smtp_probe(mx_host: str, helo_domain: str, mail_from: str, rcpt_to: str, timeout=12, use_starttls=True) -> Tuple[int, str]:
    """Connect to MX, run (EHLO/HELO), optional STARTTLS, then MAIL FROM/RCPT TO. Return (code, message)."""
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

def random_local_part() -> str:
    return "no_such_user_" + "".join(random.choice("abcdefghijklmnopqrstuvwxyz0123456789") for _ in range(20))

def verify_single(email: str, helo_domain: str, mail_from: str, domain_cache: dict, ca_cache: dict, timeout: int) -> VerifyResult:
    email = normalize_email(email)
    if not email or not is_syntax_valid(email):
        return VerifyResult("bad_syntax", "failed_regex_or_empty")

    local, _, domain = email.partition("@")
    # MX cache
    if domain not in domain_cache:
        try:
            mx_list = mx_lookup(domain)
            domain_cache[domain] = mx_list
        except Exception as e:
            return VerifyResult("no_mx", f"mx_lookup_error:{e.__class__.__name__}")

    mx_list = domain_cache[domain]
    if not mx_list:
        return VerifyResult("no_mx", "no_mx_records_found")

    # Catch‑all cache (per domain)
    if domain not in ca_cache:
        test_addr = f"{random_local_part()}@{domain}"
        ca_status = "unknown"
        for _, mx in mx_list[:2]:  # try top 1-2 MX hosts
            try:
                code, msg = smtp_probe(mx, helo_domain, mail_from, test_addr, timeout=timeout)
                if code in HARD_FAIL:
                    ca_status = "not_catchall"
                    break
                elif code in SOFT_FAIL or code in AMBIGUOUS or 200 <= code < 300:
                    # If accepted or ambiguous, lean to catch‑all (not definitive)
                    ca_status = "catchall_suspected"
                    # don't break immediately; try another MX for confirmation
            except (socket.timeout, smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError, smtplib.SMTPHeloError, smtplib.SMTPRecipientsRefused) as e:
                # transient or refused; keep trying others
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
            code, msg = smtp_probe(mx, helo_domain, mail_from, email, timeout=timeout)
            last_code, last_msg = code, msg
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
        except (socket.timeout, smtplib.SMTPServerDisconnected, smtplib.SMTPConnectError) as e:
            reasons.append(f"socket_or_smtp_error:{e.__class__.__name__}")
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
    executor: ThreadPoolExecutor,
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

        await rate_limiter.acquire(domain)

        result = await loop.run_in_executor(
            executor,
            verify_single,
            email,
            args.helo_domain,
            args.mail_from,
            domain_cache,
            catchall_cache,
            args.timeout,
        )

        await result_queue.put((idx, {
            "hs_object_id": hsid,
            "email": email,
            "domain": domain,
        }, result))

        row_queue.task_done()


async def writer_loop(
    result_queue: "asyncio.Queue[tuple[int, dict[str, str], VerifyResult]]",
    writer: csv.DictWriter,
    counters: Counters,
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


async def process_rows(args, reader: csv.DictReader, writer: csv.DictWriter, counters: Counters) -> None:
    rate_per_min = max(1, args.rate)
    per_domain_rate = args.per_domain_rate
    if per_domain_rate is None:
        per_domain_rate = max(1, rate_per_min // 5) if rate_per_min >= 5 else 1

    rate_limiter = AsyncRateLimiter(rate_per_min, per_domain_rate)
    domain_cache: dict[str, list[Tuple[int, str]]] = {}
    catchall_cache: dict[str, str] = {}

    concurrency = max(1, args.concurrency)
    row_queue: asyncio.Queue[Optional[tuple[int, dict[str, str]]]] = asyncio.Queue(maxsize=concurrency * 4)
    result_queue: asyncio.Queue[tuple[int, dict[str, str], VerifyResult]] = asyncio.Queue(maxsize=concurrency * 4)

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
                    executor,
                )
            )
            for i in range(concurrency)
        ]

        writer_task = asyncio.create_task(writer_loop(result_queue, writer, counters))

        idx = 0
        for row in reader:
            await row_queue.put((idx, row))
            idx += 1

        for _ in workers:
            await row_queue.put(None)

        await asyncio.gather(*workers)
        await result_queue.put(None)
        await writer_task

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
    args = ap.parse_args()

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
    counters = Counters()
    with open(args.in_csv, newline="", encoding="utf-8") as f_in, open(args.out_csv, "w", newline="", encoding="utf-8") as f_out:
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
        writer.writeheader()
        await process_rows(args, reader, writer, counters)
    return counters

if __name__ == "__main__":
    main()
