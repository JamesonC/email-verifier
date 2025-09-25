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
import csv
import random
import re
import smtplib
import socket
import ssl
import time
from collections import defaultdict
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

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--in", dest="in_csv", required=True, help="Input CSV with columns hs_object_id,email")
    ap.add_argument("--out", dest="out_csv", required=True, help="Output CSV path")
    ap.add_argument("--helo-domain", required=True, help="Your HELO/EHLO domain (e.g., yourcompany.com)")
    ap.add_argument("--mail-from", default="bounce@localhost", help="MAIL FROM address used in probe")
    ap.add_argument("--rate", type=int, default=12, help="Max RCPT probes per minute (default=12)")
    ap.add_argument("--timeout", type=int, default=12, help="Seconds SMTP timeout per connection")
    args = ap.parse_args()

    rate_per_min = max(1, args.rate)
    sleep_between = 60.0 / rate_per_min

    domain_cache: dict[str, list[Tuple[int, str]]] = {}
    catchall_cache: dict[str, str] = {}

    total = 0
    valid = invalid = risky = unknown = nomx = bad = 0

    with open(args.in_csv, newline="", encoding="utf-8") as f_in, open(args.out_csv, "w", newline="", encoding="utf-8") as f_out:
        reader = csv.DictReader(f_in)
        fieldnames = ["hs_object_id", "email", "deliverability_status", "reasons", "domain", "provider_response"]
        writer = csv.DictWriter(f_out, fieldnames=fieldnames)
        writer.writeheader()

        for row in reader:
            hsid = (row.get("hs_object_id") or "").strip()
            email = normalize_email(row.get("email") or row.get("Email") or "")
            domain = email.split("@")[-1] if "@" in email else ""

            result = verify_single(email, args.helo_domain, args.mail_from, domain_cache, catchall_cache, timeout=args.timeout)

            status = result.status
            if status == "valid":
                valid += 1
            elif status == "invalid":
                invalid += 1
            elif status == "risky_catchall":
                risky += 1
            elif status == "no_mx":
                nomx += 1
            elif status == "bad_syntax":
                bad += 1
            else:
                unknown += 1

            writer.writerow({
                "hs_object_id": hsid,
                "email": email,
                "deliverability_status": status,
                "reasons": result.reasons,
                "domain": domain,
                "provider_response": result.provider_response
            })

            total += 1
            time.sleep(sleep_between)

    print(f"Done. Total={total} valid={valid} invalid={invalid} risky_catchall={risky} no_mx={nomx} bad_syntax={bad} unknown={unknown}")

if __name__ == "__main__":
    main()
