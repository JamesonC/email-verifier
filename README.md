# Email Verifier (Async)

An asynchronous, best-effort email deliverability checker that performs MX lookups, optional catch-all detection, and SMTP `RCPT TO` probes without sending mail. The tool is designed to process large contact exports (e.g., 300k+ HubSpot records) while respecting rate limits and surfacing detailed provider feedback for downstream analysis.

## Key Features

- **Async worker pool** with configurable concurrency, global rate limits, and per-domain throttling.
- **Reusable SMTP connection pool** to avoid repeated TLS handshakes and reduce latency per probe.
- **DNS and SMTP retries** with exponential backoff and detailed reason codes in the output CSV.
- **Heuristic tagging** for common role inboxes and disposable-email providers. These contacts are still probed but flagged (e.g., `heuristic:role_account`) and surfaced as `risky_role_account` / `risky_disposable` when they otherwise look valid.
- **Catch-all detection** that reuses the same retry/backoff policies so ambiguous domains surface as `risky_catchall` rather than `valid`.
- **Progress logging & resumability** via deterministic CSV ordering and configurable progress intervals.
- **Resume support** that skips previously processed rows and continues appending to the existing output file when `--resume` is enabled.
- **Post-run summary** written to JSON capturing totals, heuristic counts, and top failing domains for quick triage.
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

Deliverability status values: `valid`, `invalid`, `risky_catchall`, `risky_role_account`, `risky_disposable`, `unknown`, `no_mx`, `bad_syntax`.

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
| `--disposable-domain-file` | _optional_ | Path to newline-delimited disposable domains merged with the built-in list. |
| `--resume` | `false` | Append to an existing output file, skipping rows already processed. |
| `--summary` | `<out>.summary.json` | Custom path for the JSON summary report. |
| `--summary-top-domains` | `15` | How many failing domains to list in the summary. |

## Operational Guidance

1. **Choose realistic rates.** Start with `--rate 40 --concurrency 8` for moderate throughput (~2,400 RCPT/minute), then adjust based on provider feedback. Keep `--per-domain-rate` low for domains that throttle aggressively.
2. **Warm up gradually.** Run a small batch (1–2k contacts) and observe `[progress]` logs to ensure DNS/MX failures remain low and the SMTP servers are not rate-limiting.
3. **Resume support.** Restart a run with `--resume` to append to the existing output file; the script skips rows whose `(hs_object_id, email)` pairs already appear in the CSV and continues logging aggregate totals.
4. **Interpret status codes.** The `reasons` column records DNS errors (`dns_timeout`, `dns_nonameservers`), SMTP retry history (`smtp_retry:soft_fail:451`), heuristic flags (`heuristic:role_account`), and final verdict (`smtp_hard_fail:550`). Use this to triage unknowns vs. invalids and correlate with the JSON summary.
5. **Review the summary.** After each run, inspect `<out>.summary.json` (or your configured path) to see aggregate counts and the domains contributing most to failures; adjust rate limits or disposables accordingly.
6. **Respect provider policies.** Even though no email is sent (`DATA` is never issued), probing too aggressively may trigger temporary blocks. Vary `--mail-from` if you see policy-related rejections like `5.7.1`.

## Running from a DigitalOcean VPS (recommended)

Most residential and corporate networks block outbound SMTP (port 25), so the quickest way to perform MX/RCPT verification is from an isolated VPS where you control egress. The steps below use DigitalOcean, but any provider with open SMTP works similarly.

1. **Create the Droplet**
   - Sign in to DigitalOcean → **Create → Droplets**.
   - Image: *Ubuntu 22.04 LTS* (or latest stable).
   - Plan: the $6/month Basic (1 vCPU, 1GB RAM) is sufficient.
   - Region: choose one close to your team.
   - Authentication: upload your SSH public key (`~/.ssh/id_rsa.pub`) or let DO generate a root password (they email it).
   - Click **Create Droplet** and note the public IPv4 address once it’s ready.

2. **SSH into the Droplet**
   ```bash
   ssh root@<droplet-ip>
   ```
   If you used the emailed password, change it when prompted. Optionally create a non-root user:
   ```bash
   adduser verifier
   usermod -aG sudo verifier
   su - verifier
   ```

3. **Install prerequisites**
   ```bash
   sudo apt-get update
   sudo apt-get install -y python3 python3-venv python3-pip git
   ```

4. **Bring the project over**
   - Option A: clone from git
     ```bash
     git clone <your-repo-url>
     cd email-verifier
     ```
   - Option B: copy from your laptop
     ```bash
     scp -r /path/to/email-verifier verifier@<droplet-ip>:~/email-verifier
     cd email-verifier
     ```

5. **Set up the virtual environment**
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   pip install --upgrade pip
   pip install dnspython==2.*
   ```
   Install any extra dependencies your fork requires.

6. **Upload the input CSV (if not already)**
   ```bash
   scp contacts_in.csv verifier@<droplet-ip>:~/email-verifier/
   ```
   Confirm the file exists with `ls`.

7. **Run the verifier**
   ```bash
   python email_verifier_mvp.py \
     --in contacts_in.csv \
     --out contacts_out.csv \
     --helo-domain yourdomain.com \
     --mail-from bounce@yourdomain.com \
     --rate 40 \
     --per-domain-rate 5 \
     --concurrency 6 \
     --progress-every 1000 \
     --resume \
     --summary contacts_out.summary.json \
     --summary-top-domains 20
   ```
   Tail progress with `tail -f contacts_out.csv` or watch the `[progress]` logs.

8. **Retrieve results**
   ```bash
   scp verifier@<droplet-ip>:~/email-verifier/contacts_out.csv .
   scp verifier@<droplet-ip>:~/email-verifier/contacts_out.summary.json .
   ```

9. **Shut down (optional)**
   If you no longer need the droplet, destroy it in the DigitalOcean dashboard to avoid charges. Otherwise, keep it patched (`sudo apt-get upgrade`) and reuse it for future batches.

**Safety notes**
- Use a dedicated VPS/IP separate from production email traffic.
- Keep rate limits polite (≤40 RCPTs/min global, ≤5 per domain until you observe behavior).
- Ensure your `--helo-domain`/`--mail-from` use a domain you control with proper DNS/RDNS.
- Respect remote servers: follow deferrals, avoid hammering catch-all or tarp domains, and honor any explicit opt-out requests.

## Troubleshooting

- **Many `dns_timeout` reasons:** Increase `--dns-attempts` or `--dns-backoff`, or inspect your resolver’s health.
- **Frequent `smtp_retry_error:SMTPServerDisconnected`:** Lower `--rate`/`--concurrency` and consider raising `--smtp-backoff` to ease pressure on the provider.
- **Stalls or no progress output:** Ensure `--progress-every` is >0 and that stdout isn’t redirected to a file without flushing.

## Limitations

- Some providers (notably Google and Microsoft) accept RCPT for non-existent users, so the script may return `risky_catchall` even after retries.
- Resume relies on the output CSV remaining intact; supervise long runs and keep backups if the process may be interrupted.

## Contributing

Pull requests are welcome. Please keep comments concise, default to ASCII, and follow the existing async architecture when adding new heuristics or logging.
