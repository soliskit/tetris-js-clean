"""Strict metadata audit candidate, not installed and not a publisher.

All reachable commits are inspected. No historical baseline, date cut-off,
third-party/bot exception, signature exemption or automatic correction exists.
The caller must select exact trusted refs. A PASS is metadata evidence only.
"""

import argparse
import hashlib
import json
import os
import re
import selectors
import subprocess
import sys
import time
from pathlib import Path

import publication_gate as proven

IDENTITY = b"David Solis <doze.inept.0n@icloud.com>"
PROVEN_GATE_SHA256 = "d5c779c572a54dfe5f4ce71c47413d29fe46cc9c0acc2709a60d145722fcf68b"
DENIED_SHA256 = "a0ebdc174a661c2b456f669d99155b398c3ce71fa355819d978c65e3fa83cd0c"
MAX_COMMIT_BYTES = 1024 * 1024


class Failed(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise Failed(reason)


def parse_commit(raw):
    require(type(raw) is bytes and len(raw) <= MAX_COMMIT_BYTES, "commit size bound")
    require(b"\0" not in raw and b"\r" not in raw, "ambiguous commit bytes")
    require(b"\n\n" in raw, "missing message boundary")
    header, message = raw.split(b"\n\n", 1)
    fields = []
    for line in header.split(b"\n"):
        if line.startswith(b" "):
            require(fields and fields[-1][0] == b"gpgsig", "unqualified continuation")
            fields[-1][1].append(line[1:])
        else:
            require(b" " in line, "malformed header")
            key, value = line.split(b" ", 1)
            fields.append((key, [value]))
    keys = [key for key, _ in fields]
    require(keys and keys[0] == b"tree", "tree header required first")
    require(
        keys.count(b"tree") == keys.count(b"author") == keys.count(b"committer") == 1,
        "duplicate or missing identity/tree",
    )
    require(keys.count(b"gpgsig") <= 1, "duplicate signature")
    require(
        all(
            key in {b"tree", b"parent", b"author", b"committer", b"gpgsig"}
            for key in keys
        ),
        "unqualified commit header",
    )
    parents = []
    phase = 0
    for key, parts in fields:
        if key == b"tree":
            require(
                phase == 0 and re.fullmatch(rb"[0-9a-f]{40}", parts[0]), "tree format"
            )
            phase = 1
        elif key == b"parent":
            require(
                phase == 1 and re.fullmatch(rb"[0-9a-f]{40}", parts[0]),
                "parent order/format",
            )
            parents.append(parts[0].decode("ascii"))
        elif key == b"author":
            require(phase == 1, "author header order")
            check_identity(parts[0], "author")
            phase = 2
        elif key == b"committer":
            require(phase == 2, "committer header order")
            check_identity(parts[0], "committer")
            phase = 3
        elif key == b"gpgsig":
            require(phase == 3 and len(parts) >= 3, "signature structure/order")
            require(
                (parts[0], parts[-1])
                in {
                    (b"-----BEGIN PGP SIGNATURE-----", b"-----END PGP SIGNATURE-----"),
                    (b"-----BEGIN SSH SIGNATURE-----", b"-----END SSH SIGNATURE-----"),
                },
                "unqualified signature envelope",
            )
            # Preserving a signature is not verifying it, and never grants an
            # identity exception. Both actual identity headers were checked.
            phase = 4
    require(phase in {3, 4}, "incomplete identity headers")
    require(len(set(parents)) == len(parents), "duplicate parent")
    try:
        proven.full_message(message)
    except proven.StopForReview as error:
        raise Failed(str(error)) from None
    return tuple(parents)


def check_identity(raw, label):
    match = re.fullmatch(rb"(.+>) ([0-9]{1,12}) ([+-][0-9]{4})", raw)
    require(match is not None, label + " identity/timestamp format")
    require(
        match[1] == IDENTITY, label + " must be David Solis <doze.inept.0n@icloud.com>"
    )
    require(
        int(match[3][1:3]) <= 23 and int(match[3][3:]) <= 59, label + " timestamp zone"
    )


def run_bounded(argv, env, limit, seconds=30):
    """Drain both pipes, enforcing a joint byte cap before accumulating output."""
    require(type(limit) is int and 0 < limit <= 16 * 1024 * 1024, "output bound")
    deadline = time.monotonic() + seconds
    output = bytearray()
    used = 0
    try:
        with (
            subprocess.Popen(
                argv,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as process,
            selectors.DefaultSelector() as selector,
        ):
            try:
                selector.register(process.stdout, selectors.EVENT_READ, True)
                selector.register(process.stderr, selectors.EVENT_READ, False)
                while selector.get_map():
                    remaining = deadline - time.monotonic()
                    require(remaining > 0, "native Git timed out")
                    for key, _ in selector.select(remaining):
                        chunk = os.read(key.fd, min(65536, limit - used + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            continue
                        used += len(chunk)
                        require(used <= limit, "native Git output byte bound exceeded")
                        if key.data:
                            output.extend(chunk)
                remaining = deadline - time.monotonic()
                require(remaining > 0, "native Git timed out")
                require(process.wait(timeout=remaining) == 0, "native Git failed")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
    except (subprocess.SubprocessError, OSError):
        raise Failed("native Git unavailable, incomplete, or timed out") from None
    return bytes(output)


def git(repo, *args, limit=16 * 1024 * 1024):
    env = {k: v for k, v in os.environ.items() if not k.startswith("GIT_")}
    env.update(
        GIT_CONFIG_NOSYSTEM="1",
        GIT_CONFIG_SYSTEM=os.devnull,
        GIT_CONFIG_GLOBAL=os.devnull,
        GIT_NO_REPLACE_OBJECTS="1",
        GIT_NO_LAZY_FETCH="1",
        GIT_TERMINAL_PROMPT="0",
    )
    return run_bounded(
        ["/usr/bin/git", "--no-replace-objects", "-C", str(repo), *args], env, limit
    )


def verify_dependency():
    actual = hashlib.sha256(Path(proven.__file__).read_bytes()).hexdigest()
    require(actual == PROVEN_GATE_SHA256, "reviewed validator dependency changed")


def audit(repo, tips):
    verify_dependency()
    require(
        git(repo, "rev-parse", "--is-shallow-repository").strip() == b"false",
        "shallow history is not complete coverage",
    )
    gitdir = Path(
        git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir")
        .decode()
        .strip()
    )
    require(not (gitdir / "info/grafts").exists(), "grafted history is not allowed")
    require(
        not git(repo, "for-each-ref", "--format=%(refname)", "refs/replace").strip(),
        "replacement refs are not allowed",
    )
    require(
        0 < len(tips) <= 256 and all(re.fullmatch(r"[0-9a-f]{40}", t) for t in tips),
        "exact commit OIDs required, not symbolic refs/options",
    )
    graph = {}
    for tip in tips:
        require(
            git(repo, "cat-file", "-t", tip).strip() == b"commit", "tip is not a commit"
        )
        for line in git(repo, "rev-list", "--parents", tip, "--").splitlines():
            row = line.decode("ascii").split()
            require(
                row and all(re.fullmatch(r"[0-9a-f]{40}", x) for x in row),
                "ancestry format",
            )
            if row[0] in graph:
                require(graph[row[0]] == tuple(row[1:]), "inconsistent ancestry")
            graph[row[0]] = tuple(row[1:])
    require(
        graph and all(p in graph for parents in graph.values() for p in parents),
        "incomplete parent closure",
    )
    denied_raw = (Path(__file__).parent / "denied.json").read_bytes()
    require(
        hashlib.sha256(denied_raw).hexdigest() == DENIED_SHA256,
        "denied evidence changed",
    )
    denied = frozenset(json.loads(denied_raw))
    require(
        all(re.fullmatch(r"[0-9a-f]{40}", x) for x in denied), "denied manifest format"
    )
    failures = []
    for oid, announced_parents in sorted(graph.items()):
        try:
            raw = git(repo, "cat-file", "commit", oid, limit=MAX_COMMIT_BYTES)
        except Failed as error:
            raise Failed(f"commit {oid}: inspection incomplete: {error}") from None
        require(
            hashlib.sha1(b"commit " + str(len(raw)).encode() + b"\0" + raw).hexdigest()
            == oid,
            "raw commit identity mismatch",
        )
        try:
            require(oid not in denied, "known-denied commit, no ancestry exemption")
            actual_parents = parse_commit(raw)
            require(actual_parents == announced_parents, "raw parent graph differs")
        except Failed as error:
            failures.append((oid, str(error)))
    return len(graph), failures


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo", required=True)
    parser.add_argument("--tip", required=True, action="append")
    args = parser.parse_args()
    try:
        total, failures = audit(args.repo, args.tip)
        print(f"CREDIT AUDIT: full reachable ancestry, {total} commits inspected")
        for oid, reason in failures:
            print(f"FAIL {oid} {reason}")
        if failures:
            print(
                f"CREDIT AUDIT FAILED: {len(failures)} commit(s), no correction applied"
            )
            return 1
        print(
            "CREDIT AUDIT PASS: exact author, committer and full-message checks passed"
        )
        return 0
    except (Failed, UnicodeError, OSError) as error:
        print(f"CREDIT AUDIT FAILED CLOSED: {error}")
        return 2


if __name__ == "__main__":
    sys.exit(main())
