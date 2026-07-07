"""Logsiegel CLI: init, log, checkpoint, verify, export, shred, payload."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .core import EVENT_TYPES, Logsiegel


def _attrs(pairs: list[str]) -> dict:
    out = {}
    for p in pairs:
        if "=" not in p:
            raise SystemExit(f"--attr expects key=value, got {p!r}")
        k, v = p.split("=", 1)
        out[k] = v
    return out


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

    p = sub.add_parser("checkpoint", help="sign a checkpoint over the current log")
    p.add_argument("dir")

    p = sub.add_parser("verify", help="verify hash chain, Merkle roots and signatures")
    p.add_argument("dir")

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

    if args.cmd == "init":
        lb = Logsiegel.init(args.dir, origin=args.origin)
        print(f"initialized log in {args.dir} (origin={lb.origin}, key={lb.public_key_fingerprint()})")
        return 0

    lb = Logsiegel(args.dir)

    if args.cmd == "log":
        e = lb.append(args.event, _attrs(args.attr), args.input_text, args.output_text,
                      store_payload=args.store_payload)
        print(json.dumps(e, ensure_ascii=False))
        return 0

    if args.cmd == "checkpoint":
        cp = lb.checkpoint()
        print(f"checkpoint #{len(lb.checkpoints())}: size={cp['size']} root={cp['root'][:16]}…")
        return 0

    if args.cmd == "verify":
        r = lb.verify()
        status = "PASS" if r.ok else "FAIL"
        print(f"{status}: {r.entries} entries, {r.checkpoints} checkpoints")
        for prob in r.problems:
            print(f"  ✗ {prob}")
        return 0 if r.ok else 1

    if args.cmd == "export":
        text = lb.export_dossier()
        if args.out == "-":
            sys.stdout.write(text)
        else:
            Path(args.out).write_text(text)
            print(f"dossier written to {args.out}")
        return 0

    if args.cmd == "shred":
        lb.shred(args.seq)
        r = lb.verify()
        print(f"payload of entry {args.seq} shredded; log verification: {'PASS' if r.ok else 'FAIL'}")
        return 0

    if args.cmd == "payload":
        print(json.dumps(lb.read_payload(args.seq), ensure_ascii=False, indent=1))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())
