import hashlib
import os
import subprocess
from pathlib import Path

import atomic_hook
import hook_installer
from production_entry import TARGETS


class Stop(Exception):
    pass


def inspect(checkout, expected_repo, expected_repo_id, read_repository):
    if expected_repo not in TARGETS:
        raise Stop("not an approved replacement target")
    root = Path(checkout).resolve(strict=True)
    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": str(root),
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
    }

    def git(*args, absent=False):
        result = subprocess.run(
            ["/usr/bin/git", "-C", str(root), *args],
            env=env,
            capture_output=True,
            timeout=15,
        )
        if absent and result.returncode == 1:
            return None
        if result.returncode:
            raise Stop("checkout inspection failed")
        return result.stdout.decode("utf-8").strip()

    if (
        git("config", "--local", "--includes", "--get", "core.hooksPath", absent=True)
        is not None
    ):
        raise Stop("alternate hooks path needs a separate exact installer change")
    origin = git("config", "--local", "--get-all", "remote.origin.url")
    if origin not in (
        "https://github.com/" + expected_repo + ".git",
        "https://github.com/" + expected_repo,
    ):
        raise Stop("origin not the exact replacement repository")
    if not (root / ".git").is_dir() or (root / ".git").is_symlink():
        raise Stop("ordinary owned checkout required")
    local = git("config", "--local", "--includes", "--list")
    for line in local.splitlines():
        key = line.split("=", 1)[0].lower()
        if key.startswith(("include.", "includeif.", "url.", "credential.", "http.")):
            raise Stop(
                "redirecting/credential config needs reconciliation before install"
            )
    identity = read_repository(expected_repo)
    if (
        identity.get("id") != expected_repo_id
        or identity.get("full_name") != expected_repo
    ):
        raise Stop("live repository identity differs")
    hook = root / ".git" / "hooks" / "pre-push"
    original, mode = hook_installer.read_owned(hook)
    other = {}
    for name in ("pre-commit", "commit-msg"):
        path = hook.parent / name
        if path.exists():
            raw, original_mode = hook_installer.read_owned(path)
            other[name] = {"sha256": hook_installer.sha(raw), "mode": original_mode}
    return {
        "checkout": str(root),
        "repo": expected_repo,
        "repo_id": expected_repo_id,
        "hook": str(hook),
        "original_sha256": hook_installer.sha(original),
        "original_mode": mode,
        "other_hooks": other,
        "head": git("rev-parse", "HEAD"),
        "status_sha256": hashlib.sha256(
            git("status", "--porcelain=v1", "--untracked-files=all").encode()
        ).hexdigest(),
    }


def install(
    inspection,
    staged_receipt,
    wrapper_bytes,
    verify_original_approval,
    read_repository,
    record,
):
    if verify_original_approval(inspection, staged_receipt) is not True:
        raise Stop("installation is not covered by original approval")
    now = inspect(
        inspection["checkout"],
        inspection["repo"],
        inspection["repo_id"],
        read_repository,
    )
    if now != inspection:
        raise Stop("checkout or existing hook changed after review")
    if (
        staged_receipt["hook"] != inspection["hook"]
        or staged_receipt["original_sha256"] != inspection["original_sha256"]
        or staged_receipt["wrapper_sha256"] != hook_installer.sha(wrapper_bytes)
    ):
        raise Stop("staged installation differs from reviewed inspection")
    atomic_hook.replace(
        inspection["checkout"],
        inspection["original_sha256"],
        wrapper_bytes,
        0o700,
        record,
    )

    for name, expected in inspection["other_hooks"].items():
        raw, mode = hook_installer.read_owned(Path(inspection["hook"]).parent / name)
        if {"sha256": hook_installer.sha(raw), "mode": mode} != expected:
            raise Stop("other hook changed during install, reconciliation required")
    return {
        "repo": inspection["repo"],
        "repo_id": inspection["repo_id"],
        "installed_wrapper_sha256": staged_receipt["wrapper_sha256"],
        "other_hooks_unchanged": True,
    }


def prepare_rollback(checkout, repo, repo_id, installed_receipt, read_repository):
    pass
    current = inspect(checkout, repo, repo_id, read_repository)
    if (
        current["hook"] != installed_receipt["hook"]
        or current["original_sha256"] != installed_receipt["wrapper_sha256"]
    ):
        raise Stop("rollback only covers the exact installed wrapper")
    original, _mode = hook_installer.read_owned(installed_receipt["saved_original"])
    if hook_installer.sha(original) != installed_receipt["original_sha256"]:
        raise Stop("saved original changed")
    return current


def rollback(
    current, installed_receipt, verify_original_approval, read_repository, record
):
    if verify_original_approval(current, installed_receipt) is not True:
        raise Stop("rollback not covered by original approval")
    now = prepare_rollback(
        current["checkout"],
        current["repo"],
        current["repo_id"],
        installed_receipt,
        read_repository,
    )
    if now != current:
        raise Stop("rollback state changed after review")
    atomic_hook.rollback(current["checkout"], installed_receipt, record)
    raw, mode = hook_installer.read_owned(current["hook"])
    if (
        hook_installer.sha(raw) != installed_receipt["original_sha256"]
        or mode != installed_receipt["original_mode"]
    ):
        raise Stop("rollback readback differs")
    for name, expected in current["other_hooks"].items():
        raw, mode = hook_installer.read_owned(Path(current["hook"]).parent / name)
        if {"sha256": hook_installer.sha(raw), "mode": mode} != expected:
            raise Stop("other hook changed during rollback, reconciliation required")
    return {
        "repo": current["repo"],
        "repo_id": current["repo_id"],
        "restored_original_sha256": installed_receipt["original_sha256"],
        "other_hooks_unchanged": True,
    }
