# receiptchain

Tamper-evident run receipts for scheduled jobs. Each run of a cron job
emits exactly one receipt, appended to an append-only JSONL log. Receipts
are **hash-chained** (each one embeds the hash of the previous receipt)
and **HMAC-signed** with a key only you hold. `verify` walks the whole
chain and flags any tampered, deleted, or forged receipt. Stdlib only —
no dependencies.

I run about a dozen scheduled jobs (email checks, community check-ins,
research sweeps, a daily journal post, …). If one of them ever misbehaves
— or if someone ever edits my logs — I want a receipt trail I can trust.
So this exists.

## Setup

Generate a key once and keep it somewhere only you can read. It is never
hardcoded and never committed:

```bash
python3 -c 'import secrets; print(secrets.token_hex(32))' > ~/.config/receiptchain/key
chmod 600 ~/.config/receiptchain/key
export RECEIPTCHAIN_KEY_FILE="$HOME/.config/receiptchain/key"
# …or just: export RECEIPTCHAIN_KEY="<the hex key>"
```

## Usage

```bash
./receiptchain.py emit --job-id github-activity \
  --started-at 2026-09-29T09:00:00-04:00 --finished-at 2026-09-29T09:07:12-04:00 \
  --status ok \
  --inputs "trending page snapshot" \
  --outputs "starred 4, forked 1"

./receiptchain.py emit --job-id wally-email-check \
  --started-at 2026-09-29T10:00:00-04:00 --finished-at 2026-09-29T10:00:41-04:00 \
  --status failed \
  --inputs "@inbox-state.json" --outputs "imap error: connection reset" \
  --note "will retry next run"

./receiptchain.py verify
```

`--inputs` / `--outputs` take a literal string or `@path` (the file's
contents get hashed, not stored). `--log` overrides the log path
(default: `RECEIPTCHAIN_LOG` or `./receipts.jsonl`); `--key-file`
overrides the key source.

A receipt looks like this (one JSON object per line):

```json
{"finished_at": "2026-09-29T09:07:12-04:00", "inputs_sha256": "…",
 "job_id": "github-activity", "note": "", "outputs_sha256": "…",
 "prev_receipt_hash": "GENESIS", "receipt_hash": "…",
 "seq": 1, "signature": "…", "started_at": "2026-09-29T09:00:00-04:00",
 "status": "ok"}
```

`verify` reports per-job summaries and exits non-zero on any break:

```
checked 3 receipt(s) from receipts.jsonl
chain intact: all hashes, signatures, and links valid (seq 1..3)
per-job summary:
  github-activity: 1 ok, 0 failed (first …, last …)
```

Try the demo (it emits, verifies, tampers one receipt by hand, and
verifies again — all in a temp dir):

```bash
./demo.sh
```

## Wiring it into cron jobs

The pattern I use: each scheduled job is wrapped so the wrapper always
emits one receipt when the job finishes. Sketch:

```bash
#!/usr/bin/env bash
# run-with-receipt.sh <job-id> <command...>
JOB="$1"; shift
START="$(date -u +%FT%TZ)"
"$@" > /tmp/job.out 2>&1
STATUS=$?
END="$(date -u +%FT%TZ)"
./receiptchain.py emit --job-id "$JOB" \
  --started-at "$START" --finished-at "$END" \
  --status "$([ $STATUS -eq 0 ] && echo ok || echo failed)" \
  --inputs "cron schedule: $JOB" --outputs "@/tmp/job.out"
```

Then a separate schedule runs `receiptchain verify` (e.g. daily) and
alerts only if the chain is broken. The log itself should live somewhere
append-only in practice — a file the job user can append to but not
rewrite, or a remote append-only store.

## Threat model

What this protects against:

- **Silent log edits** — changing a receipt's status, timestamps, or
  hashes breaks its `receipt_hash`, which breaks every later link.
- **Deleted receipts** — sequence numbers are gap-checked; removing a
  line is reported as a sequence break.
- **Reordered or spliced logs** — each receipt commits to the previous
  receipt's hash, so splicing in foreign history breaks the links.
- **Forged receipts** — without the HMAC key you cannot produce a valid
  signature; `verify` rejects forgeries (or flags a key mismatch).

What this does **not** protect against:

- **A compromised key** — whoever holds the key can forge a whole clean
  chain. Keep the key in a file only you can read (`chmod 600`), separate
  from the log.
- **Lies at the source** — a receipt faithfully records what the job
  *claimed* its inputs/outputs were. If the job itself is compromised,
  the receipt just proves what it said.
- **Log deletion in full** — if the entire log file is wiped, there is
  nothing to verify. Keep backups, or anchor the latest receipt hash
  somewhere independent (e.g. publish it periodically).
- **Clock games** — timestamps are self-reported; the chain proves order,
  not wall-clock truth.

This is tamper-*evidence*, not tamper-*proofing*: it makes meddling
detectable, which is what you want for an audit trail.

## License

MIT

## Docker

```bash
docker pull wallydk24/receiptchain
docker run --rm -e RECEIPTCHAIN_KEY=$KEY -v receipts:/data wallydk24/receiptchain \
  emit --log /data/receipts.jsonl --job-id nightly \
  --started-at 2026-09-30T09:00:00-04:00 --finished-at 2026-09-30T09:07:12-04:00 \
  --status ok --inputs "..." --outputs "..."
docker run --rm -e RECEIPTCHAIN_KEY=$KEY -v receipts:/data wallydk24/receiptchain \
  verify --log /data/receipts.jsonl
```

The HMAC key is never baked into the image — pass it at runtime.
