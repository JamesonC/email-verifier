# Email Verifier (Async)

An asynchronous, best-effort email deliverability checker that performs MX lookups, optional catch-all detection, and SMTP `RCPT TO` probes without sending mail. The tool is designed to process large contact exports (e.g., 300k+ HubSpot records) while respecting rate limits and surfacing detailed provider feedback for downstream analysis.

## Key Features

- **Async worker pool** with configurable concurrency, global rate limits, and per-domain throttling.
- **Reusable SMTP connection pool** to avoid repeated TLS handshakes and reduce latency per probe.
- **DNS and SMTP retries** with exponential backoff and detailed reason codes in the output CSV.
- **Catch-all detection** that reuses the same retry/backoff policies so ambiguous domains surface as `risky_catchall` rather than `valid`.
- **Progress logging & resumability** via deterministic CSV ordering and configurable progress intervals.
- **Plain CSV in/out** so the script fits easily into CRM workflows and can be resumed by skipping already processed rows in the output file.

## Requirements

- Python 3.10+
- `dnspython` 2.x (`pip install dnspython==2.*`)

No third-party verification APIs are required; the script relies entirely on DNS and SMTP probing.

## Installation

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install dnspython==2.*
```

## Input & Output

- **Input CSV** must expose at least `hs_object_id` and `email` columns (case-insensitive).
- **Output CSV** includes: `hs_object_id,email,deliverability_status,reasons,domain,provider_response`.

Deliverability status values: `valid`, `invalid`, `risky_catchall`, `unknown`, `no_mx`, `bad_syntax`.

## Quick Start

```bash
python email_verifier_mvp.py \
  --in contacts_in.csv \
  --out contacts_out.csv \
  --helo-domain yourcompany.com \
  --mail-from bounce@yourcompany.com \
  --rate 40 \
  --concurrency 8 \
  --progress-every 1000
```

## Command Reference

| Flag | Default | Description |
| ---- | ------- | ----------- |
| `--in` | _required_ | Input CSV path containing HubSpot contact IDs and emails. |
| `--out` | _required_ | Output CSV destination. Will be overwritten. |
| `--helo-domain` | _required_ | Domain to use in `EHLO/HELO`. Use something you control. |
| `--mail-from` | `bounce@localhost` | MAIL FROM sender address presented during the SMTP probe. |
| `--rate` | `12` | Maximum RCPT probes per minute across all domains. |
| `--per-domain-rate` | derived | Optional per-domain RCPT limit. Defaults to roughly `rate / 5`. |
| `--concurrency` | `4` | Number of async worker tasks (and DNS/MX caches) operating in parallel. |
| `--pool-per-host` | `concurrency` | Maximum pooled SMTP sessions maintained per MX host. |
| `--timeout` | `12` | Socket timeout in seconds for SMTP connections. |
| `--dns-attempts` | `3` | Maximum MX lookup attempts before classifying an error. |
| `--dns-backoff` | `0.5` | Base seconds for exponential DNS retry backoff. |
| `--smtp-attempts` | `3` | Maximum RCPT probes per MX host before giving up. |
| `--smtp-backoff` | `0.75` | Base seconds for exponential SMTP retry backoff. |
| `--progress-every` | `500` | Print progress summary after every N processed rows (set `0` to disable). |

## Operational Guidance

1. **Choose realistic rates.** Start with `--rate 40 --concurrency 8` for moderate throughput (~2,400 RCPT/minute), then adjust based on provider feedback. Keep `--per-domain-rate` low for domains that throttle aggressively.
2. **Warm up gradually.** Run a small batch (1–2k contacts) and observe `[progress]` logs to ensure DNS/MX failures remain low and the SMTP servers are not rate-limiting.
3. **Resume support.** If an earlier run generated partial output, rerun the script with a filtered input CSV or deduplicate the contacts before processing. The tool writes results in input order so you can easily find the last processed row.
4. **Interpret status codes.** The `reasons` column records DNS errors (`dns_timeout`, `dns_nonameservers`), SMTP retry history (`smtp_retry:soft_fail:451`), and final verdict (`smtp_hard_fail:550`). Use this to triage unknowns vs. invalids.
5. **Respect provider policies.** Even though no email is sent (`DATA` is never issued), probing too aggressively may trigger temporary blocks. Vary `--mail-from` if you see policy-related rejections like `5.7.1`.

## Troubleshooting

- **Many `dns_timeout` reasons:** Increase `--dns-attempts` or `--dns-backoff`, or inspect your resolver’s health.
- **Frequent `smtp_retry_error:SMTPServerDisconnected`:** Lower `--rate`/`--concurrency` and consider raising `--smtp-backoff` to ease pressure on the provider.
- **Stalls or no progress output:** Ensure `--progress-every` is >0 and that stdout isn’t redirected to a file without flushing.

## Limitations

- Some providers (notably Google and Microsoft) accept RCPT for non-existent users, so the script may return `risky_catchall` even after retries.
- Disposable or role-based addresses are not filtered automatically; integrate your own heuristics before probing if needed.
- The tool does not persist intermediate checkpoints; long runs should be supervised and possibly split into multiple CSVs.

## Contributing

Pull requests are welcome. Please keep comments concise, default to ASCII, and follow the existing async architecture when adding new heuristics or logging.
