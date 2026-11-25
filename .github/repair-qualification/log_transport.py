"""Encode only isolated runner evidence into ordinary logs, not Actions artifacts.
Draft transport. No workload launch, network, secrets or account operations.
"""

import argparse
import base64
import hashlib
import sys
from pathlib import Path


def encode(path, stream):
    data = Path(path).read_bytes()
    digest = hashlib.sha256(data).hexdigest()
    stream.write(f"TETRIS_EVIDENCE_BEGIN {len(data)} {digest}\n")
    for number, start in enumerate(range(0, len(data), 3072)):
        text = base64.b64encode(data[start : start + 3072]).decode("ascii")
        stream.write(f"TETRIS_EVIDENCE_PART {number} {text}\n")
    stream.write(f"TETRIS_EVIDENCE_END {digest}\n")
    stream.flush()


def decode(path, destination):
    started = False
    ended = False
    chunks = []
    expected_length = None
    expected_hash = None
    for raw in Path(path).read_text().splitlines():
        # GitHub prepends per-line timestamp. Find fixed marker, then validate.
        offset = raw.find("TETRIS_EVIDENCE_")
        if offset < 0:
            continue
        fields = raw[offset:].split()
        if fields[0] == "TETRIS_EVIDENCE_BEGIN":
            if started or ended or len(fields) != 3:
                raise ValueError("duplicate or invalid evidence start")
            started = True
            expected_length = int(fields[1])
            expected_hash = fields[2]
        elif fields[0] == "TETRIS_EVIDENCE_PART":
            if (
                not started
                or ended
                or len(fields) != 3
                or int(fields[1]) != len(chunks)
            ):
                raise ValueError("missing, duplicate or unordered evidence part")
            chunks.append(base64.b64decode(fields[2], validate=True))
        elif fields[0] == "TETRIS_EVIDENCE_END":
            if not started or ended or len(fields) != 2 or fields[1] != expected_hash:
                raise ValueError("invalid evidence end")
            ended = True
        else:
            raise ValueError("unknown evidence marker")
    data = b"".join(chunks)
    if (
        not started
        or not ended
        or len(data) != expected_length
        or hashlib.sha256(data).hexdigest() != expected_hash
    ):
        raise ValueError("incomplete or changed evidence transport")
    # Never overwrite a prior result or follow an existing destination link.
    with Path(destination).open("xb") as stream:
        stream.write(data)
    return expected_hash


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("encode", "decode"))
    parser.add_argument("path")
    parser.add_argument("destination", nargs="?")
    args = parser.parse_args()
    if args.mode == "encode":
        if args.destination:
            raise ValueError("encode emits stdout only")
        encode(args.path, sys.stdout)
    else:
        if not args.destination:
            raise ValueError("decode destination required")
        print(decode(args.path, args.destination))


if __name__ == "__main__":
    main()
