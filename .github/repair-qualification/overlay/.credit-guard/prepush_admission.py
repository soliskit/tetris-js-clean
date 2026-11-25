"""Admission before any file-selected pre-push work.

The publishing procedure admits the generated wrapper and host interpreter.
Receipts record state; they never select allowed source hashes.
"""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
from pathlib import Path

LIMIT = 2 * 1024 * 1024
OVERRIDES = (
    "lefthook-local.yml",
    "lefthook-local.yaml",
    ".lefthook-local.yml",
    ".lefthook-local.yaml",
    "lefthook.yaml",
    ".lefthook.yml",
    ".lefthook.yaml",
    "lefthook.toml",
    "lefthook.json",
    ".lefthook",
    "lefthook",
)


def read_regular(path, limit=LIMIT):
    """Read one ordinary bounded file without following its final component."""
    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise ValueError("absolute anchored path required")
    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=directory
            )
            os.close(directory)
            directory = child
        fd = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        try:
            before = os.fstat(fd)
            if not stat.S_ISREG(before.st_mode) or before.st_size > limit:
                raise ValueError("nonregular/oversized input: " + str(path))
            with os.fdopen(fd, "rb", closefd=False) as stream:
                data = stream.read(limit + 1)
            after = os.fstat(fd)
            if len(data) != before.st_size or (
                before.st_ino,
                before.st_size,
                before.st_mtime_ns,
            ) != (after.st_ino, after.st_size, after.st_mtime_ns):
                raise ValueError("input changed while reading: " + str(path))
            return data
        finally:
            os.close(fd)
    finally:
        os.close(directory)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def admit(manifest):
    repo = Path(manifest["repo"])
    for key in os.environ:
        if key.startswith(("LEFTHOOK", "GIT_CONFIG", "PYTHON")) or (
            key.startswith("GIT_EXEC_PATH") and key != "GIT_EXEC_PATH"
        ):
            raise ValueError("unapproved environment override: " + key)
    if Path.cwd().resolve() != repo:
        raise ValueError("unexpected hook working directory")
    git = manifest["git"]
    # Git itself exports its compiled exec path and prepends it to PATH before
    # invoking hooks. Admit only that exact value from the independently pinned
    # Git with the inherited override removed, never from the incoming value.
    if digest(read_regular(git, 64 * 1024 * 1024)) != manifest["pins"][git]:
        raise ValueError("Git executable changed")
    clean_env = dict(os.environ)
    inherited_exec = clean_env.pop("GIT_EXEC_PATH", None)
    builtin_exec = (
        subprocess.check_output([git, "--exec-path"], env=clean_env, timeout=10)
        .decode()
        .strip()
    )
    if inherited_exec is not None and inherited_exec != builtin_exec:
        raise ValueError("unapproved GIT_EXEC_PATH value")
    resolved = shutil.which("git")
    if resolved != git:
        alias = str(Path(builtin_exec) / "git")
        if inherited_exec != builtin_exec or resolved != alias:
            raise ValueError("Git resolution changed")
        if digest(read_regular(alias, 64 * 1024 * 1024)) != manifest["pins"][git]:
            raise ValueError("Git builtin alias changed")
    custom = subprocess.run(
        [git, "config", "--get", "core.hooksPath"], capture_output=True, check=False
    )
    if custom.returncode != 1:
        raise ValueError("custom hooksPath or config failure")
    for name in OVERRIDES:
        if os.path.lexists(repo / name):
            raise ValueError("unexpected hook source/config: " + name)
    if os.path.lexists(manifest["pending"]):
        raise ValueError("installation pending")
    for path, expected in manifest["pins"].items():
        if digest(read_regular(path, 64 * 1024 * 1024)) != expected:
            raise ValueError("installed dependency changed: " + path)
    # Exact configuration pin binds the reviewed sole-job removal. There is no
    # downstream job/shim to dispatch in this installation revision.
    if manifest["remaining_jobs"] != []:
        raise ValueError("unreviewed downstream jobs")


def run(manifest_path, expected_manifest, receipt_path, expected_receipt):
    try:
        raw = read_regular(manifest_path)
        if digest(raw) != expected_manifest:
            raise ValueError("manifest changed")
        if digest(read_regular(receipt_path)) != expected_receipt:
            raise ValueError("receipt changed")
        manifest = json.loads(raw)
        admit(manifest)
        data = sys.stdin.buffer.read(256 * 1024 + 1)
        if len(data) > 256 * 1024:
            raise ValueError("pre-push input byte bound")
        result = subprocess.run(
            [
                manifest["python"],
                manifest["guard_entry"],
                "pre-push",
                "--repo",
                manifest["repo"],
            ],
            input=data,
            check=False,
        )
        return result.returncode
    except (OSError, ValueError, KeyError, TypeError) as error:
        print("CREDIT ADMISSION FAILED CLOSED: " + str(error), file=sys.stderr)
        return 1
