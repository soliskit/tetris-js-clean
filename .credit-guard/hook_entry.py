"""Prepared local hook entry. Not an installer or a publication grant."""

import argparse
import re
import sys
from pathlib import Path

import strict_guard as guard


def message(path):
    guard.verify_dependency()
    with Path(path).open("rb") as source:
        data = source.read(guard.MAX_COMMIT_BYTES + 1)
    guard.require(len(data) <= guard.MAX_COMMIT_BYTES, "message size bound")
    guard.proven.full_message(data)
    print("CREDIT MESSAGE PASS: message only; final identity/parents not yet checked")


def pre_push(repo, stream):
    data = stream.read(256 * 1024 + 1)
    guard.require(len(data) <= 256 * 1024, "pre-push input byte bound")
    tips = []
    for line in data.splitlines():
        fields = line.split()
        guard.require(len(fields) == 4, "malformed pre-push ref record")
        local_ref, local_oid, remote_ref, remote_oid = fields
        guard.require(
            re.fullmatch(rb"[0-9a-f]{40}", local_oid)
            and re.fullmatch(rb"[0-9a-f]{40}", remote_oid),
            "pre-push exact SHA-1 objects required",
        )
        if local_oid == b"0" * 40:
            continue  # No new object. This is NOT permission to delete a ref.
        tip = local_oid.decode("ascii")
        guard.require(
            guard.git(repo, "cat-file", "-t", tip).strip() == b"commit",
            f"{local_ref!r} -> {remote_ref!r} {tip}: non-commit target unsupported; tagger policy unqualified",
        )
        tips.append(tip)
    if not tips:
        print(
            "CREDIT OBJECTS: no new commit targets; no publication/deletion authorized"
        )
        return 0
    total, failures = guard.audit(repo, tips)
    print(
        f"CREDIT OBJECTS: full ancestry, {total} commits inspected, all proposed tips"
    )
    for oid, reason in failures:
        print(f"FAIL {oid} {reason}")
    guard.require(not failures, "pre-push metadata rejected; no correction applied")
    print("CREDIT OBJECTS PASS: ref-target metadata only, not extra pack objects")
    return 0


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=["commit-msg", "pre-push"])
    parser.add_argument("message_path", nargs="?")
    parser.add_argument("--repo", default=".")
    args = parser.parse_args()
    try:
        if args.mode == "commit-msg":
            guard.require(args.message_path is not None, "message file required")
            message(args.message_path)
            return 0
        return pre_push(args.repo, sys.stdin.buffer)
    except (guard.Failed, guard.proven.StopForReview, OSError, UnicodeError) as error:
        print(f"CREDIT HOOK FAILED CLOSED: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
