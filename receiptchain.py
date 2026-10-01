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

def emit_receipt(args: argparse.Namespace) -> dict:
    """Append one receipt for a finished job run; return the receipt dict."""
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
    return receipt


def cmd_emit(args: argparse.Namespace) -> None:
    receipt = emit_receipt(args)
    log_path = args.log or default_log()
    print(f"emitted receipt seq={receipt['seq']} job={receipt['job_id']} status={receipt['status']}")
    print(f"  hash: {receipt['receipt_hash'][:16]}...  log: {log_path}")


# ---------------------------------------------------------------- verify

def verify_chain(log_path: str, key: bytes):
    """Verify the whole chain; return (receipts, breaks, per_job).

    receipts: list of (line_no, receipt). breaks: list of problem strings.
    per_job: {job_id: {ok, failed, first, last}}.
    """
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

    return receipts, breaks, per_job


def cmd_verify(args: argparse.Namespace) -> None:
    key = load_key(args)
    log_path = args.log or default_log()
    if not os.path.exists(log_path):
        die(f"log not found: {log_path}")

    receipts, breaks, per_job = verify_chain(log_path, key)

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

    sv = sub.add_parser("serve", help="Run the branded web UI (dashboard + emit).")
    common(sv)
    sv.add_argument("--host", default="0.0.0.0", help="Bind host (default 0.0.0.0).")
    sv.add_argument("--port", type=int, default=8080, help="Port (default 8080).")
    sv.set_defaults(func=cmd_serve)

    args = parser.parse_args()
    # subcommand-position options win over the global ones
    if getattr(args, "sub_log", None):
        args.log = args.sub_log
    if getattr(args, "sub_key_file", None):
        args.key_file = args.sub_key_file
    args.func(args)


# ---------------------------------------------------------------- serve mode
#
#   receiptchain serve [--log receipts.jsonl] [--key-file ...] [--port 8080]
#
# A branded web dashboard over the chain: integrity status, per-job cards,
# recent receipts, and an emit form. The HMAC key still comes only from the
# server's runtime configuration (env var / key file) — never baked in.
#
#   GET  /         dashboard (verify runs live on each load)
#   POST /emit     append one receipt, redirect to /
#   GET  /healthz  "ok"

RC_STYLE = """<style>
.rc-jobs{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:12px}
.rc-job{background:#1f1a15;border:1px solid #332b21;border-radius:12px;padding:14px 16px}
.rc-job h3{margin:.1em 0 .4em;font-size:17px;color:#f3e6cf;overflow-wrap:anywhere}
.rc-job .rc-times{font-size:13px;color:#a49176;margin-top:.5em}
.rc-table{width:100%;border-collapse:collapse;font-size:14px}
.rc-table th{text-align:left;color:#a49176;font-weight:600;padding:8px 10px;
  border-bottom:1px solid #332b21}
.rc-table td{padding:8px 10px;border-bottom:1px solid #2a231b;color:#e8dcc4}
.rc-table tr:last-child td{border-bottom:none}
.rc-hash{font-family:ui-monospace,Menlo,monospace;font-size:12.5px;color:#a49176}
.rc-breaks{background:#2a1512;border:1px solid #7a2d22;border-radius:10px;
  padding:12px 16px;margin:.8em 0;color:#f0b9a8;font-size:14px}
.rc-breaks li{margin:.3em 0}
</style>"""

RECENT_LIMIT = 12


def _esc(s):
    return ("" if s is None else str(s)).replace("&", "&amp;").replace(
        "<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")


def _status_badge(status):
    cls = "b-green" if status == "ok" else "b-red"
    return '<span class="wb-badge %s">%s</span>' % (cls, _esc(status))


def _dashboard_html(log_path, key, err=None):
    parts = [RC_STYLE]
    if err:
        parts.append('<div class="wb-card"><span class="wb-badge b-red">error</span>'
                     "<p>%s</p></div>" % _esc(err))
    if not os.path.exists(log_path):
        parts.append(
            '<div class="wb-card"><h2>No receipts yet</h2>'
            '<p class="wb-sub">The log <span class="rc-hash">%s</span> does not '
            "exist. Emit the first receipt below and the dashboard will come "
            "alive.</p></div>" % _esc(log_path))
        receipts, breaks, per_job = [], [], {}
    elif key is None:
        parts.append(
            '<div class="wb-card"><span class="wb-badge">unverified</span>'
            '<p class="wb-sub">No HMAC key configured — signatures cannot be '
            "checked. Set <span class=\"rc-hash\">RECEIPTCHAIN_KEY</span> or "
            "<span class=\"rc-hash\">RECEIPTCHAIN_KEY_FILE</span> and restart.</p></div>")
        receipts, breaks, per_job = [], [], {}
    else:
        try:
            receipts, breaks, per_job = verify_chain(log_path, key)
        except OSError as e:
            return ("".join(parts) +
                    '<div class="wb-card"><span class="wb-badge b-red">error</span>'
                    "<p>Could not read the log: %s</p></div>" % _esc(e))
        if breaks:
            parts.append(
                '<div class="wb-card"><span class="wb-badge b-red">chain broken</span>'
                ' <span style="color:var(--wb-muted);font-size:14px">%d receipt(s) · '
                "%d problem(s)</span>"
                '<ul class="rc-breaks">%s</ul></div>'
                % (len(receipts), len(breaks),
                   "".join("<li>%s</li>" % _esc(b) for b in breaks)))
        else:
            span = ""
            if receipts:
                seqs = [r.get("seq") for _, r in receipts if r.get("seq")]
                if seqs:
                    span = " · seq %d..%d" % (min(seqs), max(seqs))
            parts.append(
                '<div class="wb-card"><span class="wb-badge b-green">chain intact</span>'
                ' <span style="color:var(--wb-muted);font-size:14px">%d receipt(s)%s · '
                "hashes, signatures and links all valid</span></div>"
                % (len(receipts), span))

    if per_job:
        cards = []
        for job in sorted(per_job):
            info = per_job[job]
            cards.append(
                '<div class="rc-job"><h3>%s</h3>'
                '<span class="wb-badge b-green">%d ok</span> '
                '<span class="wb-badge b-red">%d failed</span>'
                '<div class="rc-times">first %s<br>last %s</div></div>'
                % (_esc(job), info["ok"], info["failed"],
                   _esc(info["first"] or "—"), _esc(info["last"] or "—")))
        parts.append('<div class="wb-card"><h2>Jobs</h2><div class="rc-jobs">%s</div></div>'
                     % "".join(cards))

    recent = receipts[-RECENT_LIMIT:][::-1]
    if recent:
        rows = []
        for _, r in recent:
            rows.append(
                "<tr><td>%s</td><td>%s</td><td>%s</td><td>%s</td>"
                '<td class="rc-hash">%s</td></tr>'
                % (_esc(r.get("seq")), _esc(r.get("job_id")),
                   _status_badge(r.get("status")), _esc(r.get("finished_at")),
                   _esc(str(r.get("receipt_hash"))[:12])))
        parts.append(
            '<div class="wb-card"><h2>Recent receipts</h2>'
            '<table class="rc-table"><thead><tr>'
            "<th>seq</th><th>job</th><th>status</th><th>finished</th><th>hash</th>"
            "</tr></thead><tbody>%s</tbody></table></div>" % "".join(rows))

    return "".join(parts)


def _emit_form_html(key_ok):
    if not key_ok:
        return ('<div class="wb-card"><h2>Emit a receipt</h2>'
                '<p class="wb-sub">No HMAC key is configured on this server, so '
                "emitting is disabled. Set <span class=\"rc-hash\">RECEIPTCHAIN_KEY</span> "
                "or <span class=\"rc-hash\">RECEIPTCHAIN_KEY_FILE</span> (or pass "
                "--key-file) and restart the server.</p></div>")
    return """
<div class="wb-card">
  <h2>Emit a receipt</h2>
  <p class="wb-sub">Append one signed receipt for a finished job run.</p>
  <form action="/emit" method="post">
    <div class="wb-field">
      <label for="job_id">Job id</label>
      <input class="wb-input" id="job_id" name="job_id" required
        placeholder="e.g. github-activity">
    </div>
    <div class="wb-field">
      <label for="started_at">Started at (ISO-8601)</label>
      <input class="wb-input" id="started_at" name="started_at" required
        placeholder="2026-10-01T09:00:00-04:00">
    </div>
    <div class="wb-field">
      <label for="finished_at">Finished at (ISO-8601)</label>
      <input class="wb-input" id="finished_at" name="finished_at" required
        placeholder="2026-10-01T09:07:12-04:00">
    </div>
    <div class="wb-field">
      <label for="status">Status</label>
      <select class="wb-select" id="status" name="status">
        <option value="ok">ok</option>
        <option value="failed">failed</option>
      </select>
    </div>
    <div class="wb-field">
      <label for="inputs">Inputs</label>
      <input class="wb-input" id="inputs" name="inputs"
        placeholder="literal text, or @path to hash a file">
    </div>
    <div class="wb-field">
      <label for="outputs">Outputs</label>
      <input class="wb-input" id="outputs" name="outputs"
        placeholder="literal text, or @path to hash a file">
    </div>
    <div class="wb-field">
      <label for="note">Note (optional)</label>
      <input class="wb-input" id="note" name="note"
        placeholder="short human-readable note">
    </div>
    <div class="wb-btn-row">
      <button class="wb-btn wb-btn-primary" type="submit">Emit receipt</button>
    </div>
  </form>
</div>
"""


def cmd_serve(args: argparse.Namespace) -> None:
    from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
    from urllib.parse import urlparse, parse_qs
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from brand.page import render, brand_asset

    log_path = args.log or default_log()

    def has_key():
        return bool(args.key_file or os.environ.get("RECEIPTCHAIN_KEY_FILE")
                    or (os.environ.get("RECEIPTCHAIN_KEY") or "").strip())

    def shell(title, content):
        return render("receiptchain", "Tamper-evident run receipts",
                      title, content, footer_extra="receiptchain")

    class ChainHandler(BaseHTTPRequestHandler):
        server_version = "receiptchain/serve"

        def log_message(self, fmt, *a):
            sys.stderr.write("receiptchain: %s\n" % (fmt % a))

        def _send(self, body, ctype="text/html; charset=utf-8", code=200):
            data = body.encode() if isinstance(body, str) else body
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def _index(self, err=None, code=200):
            key = None
            if has_key():
                try:
                    key = load_key(args)
                except SystemExit:
                    key = None
            body = (_dashboard_html(log_path, key, err)
                    + _emit_form_html(key is not None))
            return self._send(shell("Receiptchain", body), code=code)

        def do_GET(self):
            path = urlparse(self.path).path
            asset = brand_asset(path)
            if asset:
                ctype, data = asset
                return self._send(data, ctype)
            if path == "/healthz":
                return self._send("ok", "text/plain; charset=utf-8")
            if path in ("/", "/index.html"):
                return self._index()
            self.send_error(404)

        def do_POST(self):
            if urlparse(self.path).path != "/emit":
                self.send_error(404)
                return
            if not has_key():
                return self._index("emitting is disabled: no HMAC key configured",
                                   code=403)
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                length = 0
            if length <= 0 or length > 1024 * 1024:
                return self._index("empty or oversized form", code=400)
            form = parse_qs(self.rfile.read(length).decode("utf-8", "replace"))
            get = lambda k: (form.get(k, [""])[0] or "").strip()
            ea = argparse.Namespace(
                log=args.log, key_file=args.key_file,
                job_id=get("job_id"), started_at=get("started_at"),
                finished_at=get("finished_at"), status=get("status") or "ok",
                inputs=get("inputs"), outputs=get("outputs"), note=get("note"))
            missing = [k for k in ("job_id", "started_at", "finished_at")
                       if not getattr(ea, k)]
            if missing:
                return self._index("missing: " + ", ".join(missing), code=400)
            try:
                emit_receipt(ea)
            except SystemExit:
                return self._index("emit failed (check the server log)", code=500)
            self.send_response(303)
            self.send_header("Location", "/")
            self.end_headers()

    httpd = ThreadingHTTPServer((args.host, args.port), ChainHandler)
    httpd.daemon_threads = True
    host = "localhost" if args.host == "0.0.0.0" else args.host
    print("receiptchain: serving the dashboard at http://%s:%d/" % (host, args.port))
    print("receiptchain: log: %s" % log_path)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
