import hashlib
import json
import os
import stat
from pathlib import Path


class Stop(Exception):
    pass


def read_owned(path, limit=2 << 20):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.getuid()
            or before.st_nlink != 1
            or before.st_size > limit
        ):
            raise Stop("hook is not an owned bounded regular file")
        raw = os.read(fd, limit + 1)
        after = os.fstat(fd)
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != (
            after.st_dev,
            after.st_ino,
            after.st_size,
            after.st_mtime_ns,
        ):
            raise Stop("hook changed during read")
        if len(raw) != before.st_size:
            raise Stop("hook read incomplete")
        return raw, stat.S_IMODE(before.st_mode)
    finally:
        os.close(fd)


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def chain_source(original, original_sha, validator, validator_sha):
    pass

    return (
        """#!/usr/bin/python3
import hashlib, os, stat, subprocess, sys
components = """
        + repr([(str(original), original_sha), (str(validator), validator_sha)])
        + """
try:
    data = sys.stdin.buffer.read(1048577)
    if len(data) > 1048576:
        raise ValueError("pre-push input cap")
    for path, expected in components:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        try:
            info = os.fstat(fd)
            if not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid() or info.st_nlink != 1:
                raise ValueError("hook custody")
            raw = os.read(fd, 2097153)
            if len(raw) != info.st_size or hashlib.sha256(raw).hexdigest() != expected:
                raise ValueError("hook source changed")
        finally:
            os.close(fd)
        result = subprocess.run([path] + sys.argv[1:], input=data, timeout=120)
        if result.returncode:
            sys.exit(result.returncode if result.returncode > 0 else 1)
except Exception:
    print("Credit hook stopped: installation or execution could not be verified", file=sys.stderr)
    sys.exit(1)
"""
    ).encode()


def stage(hook, validator, expected_hook_sha, expected_validator_sha, directory):
    pass
    hook, validator, directory = Path(hook), Path(validator), Path(directory)
    original, mode = read_owned(hook)
    added, added_mode = read_owned(validator)
    if sha(original) != expected_hook_sha or sha(added) != expected_validator_sha:
        raise Stop("source differs from approved installer inputs")
    if not mode & 0o100 or not added_mode & 0o100:
        raise Stop("hook component not executable")
    directory.mkdir(mode=0o700, parents=False, exist_ok=False)
    saved = directory / "original-pre-push"
    extra = directory / "ancestry-pre-push"
    wrapper = directory / "pre-push.new"
    for path, raw in ((saved, original), (extra, added)):
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(fd, "wb") as out:
            out.write(raw)
            out.flush()
            os.fsync(out.fileno())
    raw = chain_source(saved, sha(original), extra, sha(added))
    wrapper.write_bytes(raw)
    wrapper.chmod(0o700)
    receipt = {
        "hook": str(hook),
        "original_sha256": sha(original),
        "original_mode": mode,
        "wrapper_sha256": sha(raw),
        "saved_original": str(saved),
        "validator": str(extra),
        "validator_sha256": sha(added),
        "state": "staged-not-installed",
    }
    (directory / "receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt
