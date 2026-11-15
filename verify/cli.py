"""Auditor CLI.

Verify a log:
    python -m verify.cli check --log agent_log.jsonl --pubkey operator/public.pem \
        --witness-receipts witness_receipts.jsonl --witness-pubkey witness/public.pem

Check one revealed value against its commitment:
    python -m verify.cli reveal --log agent_log.jsonl --vault vault.jsonl --seq 12 --key gen_ai.tool.call.arguments
"""

import argparse
import json
import sys

from recorder.signer import load_public_key
from verify.verifier import MODES, verify_log, verify_reveal


def cmd_check(args) -> int:
    mode = args.mode or ("witnessed" if args.witness_receipts else "signed" if args.pubkey else "hash")
    problems = verify_log(
        args.log,
        load_public_key(args.pubkey) if args.pubkey else None,
        mode,
        args.witness_receipts,
        load_public_key(args.witness_pubkey) if args.witness_pubkey else None,
    )
    if not problems:
        print(f"OK: no tampering detected ({mode} mode)")
        return 0
    print(f"TAMPERING DETECTED ({mode} mode): {len(problems)} problem(s)")
    for p in problems[: args.max_problems]:
        print("  -", p)
    if len(problems) > args.max_problems:
        print(f"  ... and {len(problems) - args.max_problems} more")
    return 1


def cmd_reveal(args) -> int:
    with open(args.vault) as f:
        rows = [json.loads(line) for line in f if line.strip()]
    row = next((r for r in rows if r["seq"] == args.seq and r["key"] == args.key), None)
    if row is None:
        print(f"no vault entry for seq {args.seq}, key {args.key}")
        return 2
    if verify_reveal(args.log, row):
        print(f"OK: revealed value matches the commitment in the log\n  {args.key} = {json.dumps(row['value'])}")
        return 0
    print("MISMATCH: revealed value does not match the commitment in the log")
    return 1


def main() -> int:
    p = argparse.ArgumentParser(description="Verify a tamper-evident agent log")
    sub = p.add_subparsers(dest="command", required=True)

    c = sub.add_parser("check", help="verify the whole log")
    c.add_argument("--log", required=True)
    c.add_argument("--pubkey", help="operator public key (PEM)")
    c.add_argument("--witness-receipts")
    c.add_argument("--witness-pubkey")
    c.add_argument("--mode", choices=MODES, help="default: strongest mode the given inputs allow")
    c.add_argument("--max-problems", type=int, default=10)
    c.set_defaults(func=cmd_check)

    r = sub.add_parser("reveal", help="check a revealed value against its commitment")
    r.add_argument("--log", required=True)
    r.add_argument("--vault", required=True)
    r.add_argument("--seq", type=int, required=True)
    r.add_argument("--key", required=True)
    r.set_defaults(func=cmd_reveal)

    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
