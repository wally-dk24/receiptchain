#!/usr/bin/env python3
"""
receiptchain — tamper-evident run receipts for scheduled jobs.

Each run of a cron job emits exactly one receipt, appended to an
append-only JSONL log. Receipts are hash-chained (each one references the
hash of the previous receipt) and signed with an HMAC key that you keep —
so anyone with the key can verify the log, and anyone without it cannot
forge a receipt.

Setup (pick one key source; the key is NEVER hardcoded or committed):
    export RECEIPTCHAIN_KEY="$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    # ... then persist it somewhere only you can read, e.g. ~/.config/receiptchain/key
    # or:
    export RECEIPTCHAIN_KEY_FILE="$HOME/.config/receiptchain/key"

Usage:
    receiptchain emit --job-id github-activity \\
        --started-at 2026-09-29T09:00:00-04:00 --finished-at 2026-09-29T09:07:12-04:00 \\
        --status ok --inputs "@inputs.json" --outputs "starred 4, forked 1"
    receiptchain verify [--log receipts.jsonl] [--key-file ...]

Everything uses the Python standard library — no dependencies.
"""
from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import hmac
import json
import os
import sys

PROG = "receiptchain"
GENESIS = "GENESIS"  # prev_receipt_hash of the very first receipt

STATUSES = ("ok", "failed")


def die(msg: str) -> "type[SystemExit]":  # type: ignore[valid-type]
    print(f"{PROG}: error: {msg}", file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------- key / config

def load_key(args: argparse.Namespace) -> bytes:
    """Load the HMAC key from --key-file, RECEIPTCHAIN_KEY_FILE, or RECEIPTCHAIN_KEY."""
    path = args.key_file or os.environ.get("RECEIPTCHAIN_KEY_FILE")
    if path:
        path = os.path.expanduser(path)
        if not os.path.exists(path):
            die(f"key file not found: {path}")
        with open(path) as f:
            raw = f.read().strip()
        if not raw:
            die(f"key file is empty: {path}")
    else:
        raw = (os.environ.get("RECEIPTCHAIN_KEY") or "").strip()
        if not raw:
            die("no HMAC key: set RECEIPTCHAIN_KEY, RECEIPTCHAIN_KEY_FILE, "
                "or pass --key-file (generate one with: "
                "python3 -c 'import secrets; print(secrets.token_hex(32))')")
    try:
        return bytes.fromhex(raw)
    except ValueError:
        # allow a non-hex passphrase-style key too; HMAC just needs bytes
        return raw.encode("utf-8")


def default_log() -> str:
    return os.environ.get("RECEIPTCHAIN_LOG", "receipts.jsonl")


# ---------------------------------------------------------------- hashing

def canonical(obj: dict) -> bytes:
    """Canonical byte representation used for hashing and signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def receipt_hash_of(body: dict) -> str:
    """Hash of the receipt body (everything except receipt_hash and signature)."""
    return sha256_hex(canonical(body))


def sign(key: bytes, receipt_hash: str) -> str:
    return hmac.new(key, receipt_hash.encode("utf-8"), hashlib.sha256).hexdigest()


def maybe_read(value: str) -> str:
    """@path reads a file; anything else is used as a literal string."""
    if value.startswith("@"):
        path = os.path.expanduser(value[1:])
        with open(path, "rb") as f:
            return f.read().decode("utf-8", errors="replace")
    return value


def read_last_receipt(path: str) -> dict | None:
    """Return the last receipt in the log, or None if the log is empty/missing."""
    if not os.path.exists(path):
        return None
    last = None
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                last = json.loads(line)
    return last


# ---------------------------------------------------------------- emit

def cmd_emit(args: argparse.Namespace) -> None:
    key = load_key(args)
    log_path = args.log or default_log()
    if args.status not in STATUSES:
        die(f"status must be one of {STATUSES}")

    last = read_last_receipt(log_path)
    seq = (last["seq"] + 1) if last else 1
    prev = last["receipt_hash"] if last else GENESIS

    body = {
        "seq": seq,
        "job_id": args.job_id,
        "started_at": args.started_at,
        "finished_at": args.finished_at,
        "status": args.status,
        "inputs_sha256": sha256_hex(maybe_read(args.inputs).encode("utf-8")),
        "outputs_sha256": sha256_hex(maybe_read(args.outputs).encode("utf-8")),
        "prev_receipt_hash": prev,
    }
    if args.note:
        body["note"] = args.note

    rhash = receipt_hash_of(body)
    receipt = dict(body)
    receipt["receipt_hash"] = rhash
    receipt["signature"] = sign(key, rhash)

    # Append-only: open in append mode, never rewrite the file.
    with open(log_path, "a") as f:
        f.write(json.dumps(receipt, sort_keys=True) + "\n")
    print(f"emitted receipt seq={seq} job={args.job_id} status={args.status}")
    print(f"  hash: {rhash[:16]}...  log: {log_path}")


# ---------------------------------------------------------------- verify

def cmd_verify(args: argparse.Namespace) -> None:
    key = load_key(args)
    log_path = args.log or default_log()
    if not os.path.exists(log_path):
        die(f"log not found: {log_path}")

    receipts: list[tuple[int, dict]] = []  # (line_no, receipt)
    with open(log_path) as f:
        for i, line in enumerate(f, start=1):
            line = line.strip()
            if not line:
                continue
            try:
                receipts.append((i, json.loads(line)))
            except json.JSONDecodeError as e:
                print(f"BREAK at line {i}: not valid JSON ({e})")

    breaks: list[str] = []
    prev_hash = GENESIS
    expected_seq = 1
    per_job: dict[str, dict] = {}

    for line_no, r in receipts:
        seq = r.get("seq")
        job = r.get("job_id", "?")
        label = f"seq={seq} (line {line_no}, job={job})"

        # 1. sequence continuity -> detects deleted receipts
        if seq != expected_seq:
            breaks.append(f"{label}: sequence break — expected seq {expected_seq}, "
                          f"found {seq} (a receipt may have been deleted)")
            expected_seq = seq if isinstance(seq, int) else expected_seq + 1
        else:
            expected_seq += 1

        # 2. receipt hash -> detects any payload tampering
        stored_hash = r.get("receipt_hash")
        body = {k: v for k, v in r.items() if k not in ("receipt_hash", "signature")}
        recomputed = receipt_hash_of(body)
        if stored_hash != recomputed:
            breaks.append(f"{label}: receipt_hash mismatch — stored {str(stored_hash)[:16]}..., "
                          f"recomputed {recomputed[:16]}... (payload tampered)")

        # 3. chain link -> detects reordering / splicing
        if r.get("prev_receipt_hash") != prev_hash:
            breaks.append(f"{label}: chain link broken — prev_receipt_hash "
                          f"{str(r.get('prev_receipt_hash'))[:16]}... does not match "
                          f"previous receipt's hash {str(prev_hash)[:16]}...")
        prev_hash = stored_hash if isinstance(stored_hash, str) else prev_hash

        # 4. HMAC signature -> detects forgery without the key
        stored_sig = r.get("signature")
        if not isinstance(stored_hash, str) or not isinstance(stored_sig, str):
            breaks.append(f"{label}: missing receipt_hash or signature")
        elif not hmac.compare_digest(stored_sig, sign(key, stored_hash)):
            breaks.append(f"{label}: signature invalid — receipt was not signed "
                          f"with this key (forged or key mismatch)")

        # per-job summary
        info = per_job.setdefault(job, {"ok": 0, "failed": 0,
                                        "first": None, "last": None})
        if r.get("status") in ("ok", "failed"):
            info[r["status"]] += 1
        for edge in ("first", "last"):
            pass
        started = r.get("started_at")
        if info["first"] is None or (started and started < info["first"]):
            info["first"] = started
        finished = r.get("finished_at")
        if info["last"] is None or (finished and finished > info["last"]):
            info["last"] = finished

    print(f"checked {len(receipts)} receipt(s) from {log_path}")
    if breaks:
        print(f"CHAIN BROKEN: {len(breaks)} problem(s) found")
        for b in breaks:
            print("  - " + b)
    else:
        seqs = [r.get("seq") for _, r in receipts]
        span = f"seq {min(seqs)}..{max(seqs)}" if seqs else "empty log"
        print(f"chain intact: all hashes, signatures, and links valid ({span})")

    print("per-job summary:")
    for job in sorted(per_job):
        info = per_job[job]
        print(f"  {job}: {info['ok']} ok, {info['failed']} failed "
              f"(first {info['first']}, last {info['last']})")

    sys.exit(1 if breaks else 0)


# ---------------------------------------------------------------- cli

def main() -> None:
    parser = argparse.ArgumentParser(prog=PROG,
                                     description="Tamper-evident run receipts for scheduled jobs.")
    parser.add_argument("--log", default=None,
                        help="Path to the JSONL receipt log (default: RECEIPTCHAIN_LOG or ./receipts.jsonl).")
    parser.add_argument("--key-file", default=None,
                        help="Path to a file holding the HMAC key (hex or passphrase). "
                             "Overrides RECEIPTCHAIN_KEY_FILE / RECEIPTCHAIN_KEY.")
    sub = parser.add_subparsers(dest="cmd", required=True)

    def common(p: argparse.ArgumentParser) -> None:
        # allow the global options after the subcommand too
        p.add_argument("--log", default=None, dest="sub_log",
                       help=argparse.SUPPRESS)
        p.add_argument("--key-file", default=None, dest="sub_key_file",
                       help=argparse.SUPPRESS)

    p = sub.add_parser("emit", help="Append one receipt for a finished job run.")
    common(p)
    p.add_argument("--job-id", required=True, help="Cron job id, e.g. github-activity.")
    p.add_argument("--started-at", required=True, help="ISO-8601 start time of the run.")
    p.add_argument("--finished-at", required=True, help="ISO-8601 finish time of the run.")
    p.add_argument("--status", required=True, choices=STATUSES, help="ok or failed.")
    p.add_argument("--inputs", default="",
                   help="Run inputs: literal string, or @path to hash a file.")
    p.add_argument("--outputs", default="",
                   help="Run outputs: literal string, or @path to hash a file.")
    p.add_argument("--note", default="", help="Optional short human-readable note.")
    p.set_defaults(func=cmd_emit)

    p = sub.add_parser("verify", help="Verify the whole chain and print per-job summaries.")
    common(p)
    p.set_defaults(func=cmd_verify)

    args = parser.parse_args()
    # subcommand-position options win over the global ones
    if getattr(args, "sub_log", None):
        args.log = args.sub_log
    if getattr(args, "sub_key_file", None):
        args.key_file = args.sub_key_file
    args.func(args)


if __name__ == "__main__":
    main()
