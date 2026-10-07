"""Logsiegel CLI: init, log, checkpoint, verify, receipt, export, shred, payload."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from .core import EVENT_TYPES, LOG_FILE, Logsiegel, verify_receipt


class UsageError(Exception):
    """An expected operator error: reported as one line on stderr, exit code 2."""


def _attrs(pairs: list[str]) -> dict:
    out = {}
    for p in pairs:
        if "=" not in p:
            raise SystemExit(f"--attr expects key=value, got {p!r}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


def _load_pubkey(path: str):
    try:
        return serialization.load_pem_public_key(Path(path).read_bytes())
    except ValueError as exc:
        raise UsageError(f"{path}: not a PEM public key") from exc


def _load_receipt(path: str) -> dict:
    try:
        rec = json.loads(Path(path).read_text())
    except ValueError as exc:  # also covers UnicodeDecodeError
        raise UsageError(f"{path}: not valid JSON ({exc})") from exc
    if not isinstance(rec, dict):
        raise UsageError(f"{path}: not a receipt (expected a JSON object)")
    return rec


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="logsiegel", description="Tamper-evident event log for AI systems")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("init", help="create a new log")
    p.add_argument("dir")
    p.add_argument("--origin", default="logsiegel-poc")

    p = sub.add_parser("log", help="append an event")
    p.add_argument("dir")
    p.add_argument("--event", required=True, choices=EVENT_TYPES)
    p.add_argument("--attr", action="append", default=[], metavar="K=V")
    p.add_argument("--input", dest="input_text")
    p.add_argument("--output", dest="output_text")
    p.add_argument("--store-payload", action="store_true",
                   help="store encrypted payload alongside the log (crypto-shreddable)")
    p.add_argument("--pii", action="store_true",
                   help="mask identifiers (email/phone/IBAN) in the stored payload; "
                        "hashes still commit to the original")

    p = sub.add_parser("checkpoint", help="sign a checkpoint over the current log")
    p.add_argument("dir")

    p = sub.add_parser("verify", help="verify hash chain, Merkle roots and signatures")
    p.add_argument("dir")
    p.add_argument("--pubkey", help="PEM public key obtained out-of-band (trust anchor); "
                                    "default: the copy stored next to the log")

    p = sub.add_parser("receipt", help="export a standalone proof for one entry")
    p.add_argument("dir")
    p.add_argument("--seq", type=int, required=True)
    p.add_argument("--out", default="-")

    p = sub.add_parser("verify-receipt",
                       help="verify a receipt offline — needs only the receipt and the public key")
    p.add_argument("receipt")
    p.add_argument("--pubkey", required=True, help="PEM public key of the log")

    p = sub.add_parser("export", help="write auditor-readable dossier (markdown)")
    p.add_argument("dir")
    p.add_argument("--out", default="-")

    p = sub.add_parser("shred", help="crypto-shred the payload of one entry")
    p.add_argument("dir")
    p.add_argument("--seq", type=int, required=True)

    p = sub.add_parser("payload", help="decrypt and print a stored payload")
    p.add_argument("dir")
    p.add_argument("--seq", type=int, required=True)

    args = ap.parse_args(argv)

    # Exit codes: 0 success, 1 integrity check failed, 2 usage or I/O error.
    # Only expected errors are caught here; anything else keeps its traceback.
    try:
        return _run(args)
    except UsageError as exc:
        msg = str(exc)
    except OSError as exc:
        msg = f"{exc.filename}: {exc.strerror}" if exc.filename and exc.strerror else str(exc)
    print(f"error: {msg}", file=sys.stderr)
    return 2


def _run(args: argparse.Namespace) -> int:
    if args.cmd == "verify-receipt":
        rec = _load_receipt(args.receipt)
        pub = _load_pubkey(args.pubkey)
        r = verify_receipt(rec, pub)
        status = "PASS" if r.ok else "FAIL"
        print(f"{status}: entry {rec.get('seq')} of origin {rec.get('origin')!r}")
        for prob in r.problems:
            print(f"  ✗ {prob}")
        return 0 if r.ok else 1

    if args.cmd == "init":
        try:
            lb = Logsiegel.init(args.dir, origin=args.origin)
        except FileExistsError as exc:
            raise UsageError(str(exc)) from exc
        print(f"initialized log in {args.dir} (origin={lb.origin}, key={lb.public_key_fingerprint()})")
        return 0

    # Every other command works on an existing log; never create one implicitly.
    if not (Path(args.dir) / LOG_FILE).is_file():
        raise UsageError(f"no log at {args.dir} (run 'logsiegel init' first)")
    lb = Logsiegel(args.dir)

    if args.cmd == "log":
        if args.pii:
            from .pii import RegexDetector
            lb.pii_detector = RegexDetector()
        e = lb.append(args.event, _attrs(args.attr), args.input_text, args.output_text,
                      store_payload=args.store_payload)
        print(json.dumps(e, ensure_ascii=False))
        return 0

    if args.cmd == "checkpoint":
        cp = lb.checkpoint()
        print(f"checkpoint #{len(lb.checkpoints())}: size={cp['size']} root={cp['root'][:16]}…")
        return 0

    if args.cmd == "verify":
        pub = None
        if args.pubkey:
            pub = _load_pubkey(args.pubkey)
        r = lb.verify(public_key=pub)
        status = "PASS" if r.ok else "FAIL"
        print(f"{status}: {r.entries} entries, {r.checkpoints} checkpoints")
        for prob in r.problems:
            print(f"  ✗ {prob}")
        return 0 if r.ok else 1

    if args.cmd == "receipt":
        try:
            rec = lb.receipt(args.seq)
        except (IndexError, ValueError) as exc:
            raise UsageError(str(exc)) from exc
        text = json.dumps(rec, ensure_ascii=False, indent=1)
        if args.out == "-":
            print(text)
        else:
            Path(args.out).write_text(text)
            print(f"receipt for entry {args.seq} written to {args.out}")
        return 0

    if args.cmd == "export":
        text = lb.export_dossier()
        if args.out == "-":
            sys.stdout.write(text)
        else:
            Path(args.out).write_text(text)
            print(f"dossier written to {args.out}")
        # The dossier is written either way; a failed integrity check is the exit code.
        return 0 if lb.verify().ok else 1

    if args.cmd == "shred":
        try:
            lb.shred(args.seq)
        except KeyError as exc:
            raise UsageError(exc.args[0]) from exc
        r = lb.verify()
        print(f"payload of entry {args.seq} shredded; log verification: {'PASS' if r.ok else 'FAIL'}")
        return 0 if r.ok else 1

    if args.cmd == "payload":
        try:
            payload = lb.read_payload(args.seq)
        except KeyError as exc:
            raise UsageError(exc.args[0]) from exc
        print(json.dumps(payload, ensure_ascii=False, indent=1))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
