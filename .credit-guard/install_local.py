"""Local isolated-checkout installer candidate. No remote effects."""

import hashlib
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path

import yaml

FILES = ("strict_guard.py", "publication_gate.py", "denied.json", "hook_entry.py")
SOURCE_PINS = {
    "strict_guard.py": "5a48c2a4ab0afacd7ff4fd7a7d722ed30a5d794e42f014ef0ee7ba3c0851e5db",
    "publication_gate.py": "d5c779c572a54dfe5f4ce71c47413d29fe46cc9c0acc2709a60d145722fcf68b",
    "denied.json": "a0ebdc174a661c2b456f669d99155b398c3ce71fa355819d978c65e3fa83cd0c",
    "hook_entry.py": "2be14befd655581f2f1c8d864c2d10d6633385b0d28c74d1f1a68739c6b42316",
}
LEFTHOOK_SHA256 = "0054adbcfc3fea33fb741003f02ee41023c7e2719362835888a3e84d58c75361"
RUN = 'python3 "$(git rev-parse --git-path credit-guard/entry.py)" '
HOOKS = {
    "commit-msg": {"credit-message": {"run": RUN + "commit-msg {1}"}},
    "pre-push": {"credit-objects": {"use_stdin": True, "run": RUN + "pre-push"}},
}


class InstallFailed(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise InstallFailed(reason)


def prepare_config(path):
    """Add commands, preserving original bytes/comments and all existing keys."""
    before = path.read_bytes()
    config = yaml.safe_load(before)
    require(isinstance(config, dict), "mapping configuration required")
    require(
        not any(h in config for h in HOOKS),
        "existing metadata hooks need review, not overwrite",
    )
    addition = yaml.safe_dump(
        {h: {"commands": commands} for h, commands in HOOKS.items()}, sort_keys=False
    ).encode()
    addition = addition.replace(
        b'run: python3 "$(git rev-parse --git-path credit-guard/entry.py)" commit-msg\n',
        b'run:\n        python3 "$(git rev-parse --git-path credit-guard/entry.py)" commit-msg\n',
    )
    path.write_bytes(
        before
        + b"\n# Exact commit metadata checks, alongside existing checks.\n"
        + addition
    )
    return hashlib.sha256(before).hexdigest()


def install(repo, source, lefthook):
    repo, source = Path(repo).resolve(), Path(source).resolve()
    binary = Path(lefthook).resolve()
    require(
        binary.is_file() and os.access(binary, os.X_OK),
        "existing Lefthook executable required",
    )

    def git(*args):
        return (
            subprocess.check_output(
                ["git", "-C", str(repo), *args], stderr=subprocess.PIPE
            )
            .decode()
            .strip()
        )

    require(
        hashlib.sha256(binary.read_bytes()).hexdigest() == LEFTHOOK_SHA256,
        "reviewed Lefthook binary mismatch",
    )
    for name, expected in SOURCE_PINS.items():
        require(
            hashlib.sha256((source / name).read_bytes()).hexdigest() == expected,
            "reviewed guard source mismatch: " + name,
        )
    custom = subprocess.run(
        ["git", "-C", str(repo), "config", "--get", "core.hooksPath"],
        capture_output=True,
        check=False,
    )
    require(
        custom.returncode == 1, "custom hooksPath or config error, no automatic reset"
    )
    config_path = repo / "lefthook.yml"
    before = config_path.read_bytes()
    config = yaml.safe_load(before)
    for hook, commands in HOOKS.items():
        for name, expected in commands.items():
            require(
                config.get(hook, {}).get("commands", {}).get(name) == expected,
                "reviewed metadata configuration missing/changed",
            )
    gitdir = Path(git("rev-parse", "--absolute-git-dir"))
    target = gitdir / "credit-guard"
    require(
        not target.exists(),
        "installed guard already exists, revision needs explicit review",
    )
    for hook in ("pre-commit", *HOOKS):
        path = gitdir / "hooks" / hook
        require(
            not path.exists() or b"lefthook" in path.read_bytes(),
            "existing non-Lefthook hook, do not replace",
        )
    pins = {}
    with tempfile.TemporaryDirectory(prefix="credit-guard-stage-", dir=gitdir) as stage:
        stage = Path(stage)
        for name in FILES:
            raw = (source / name).read_bytes()
            pins[name] = hashlib.sha256(raw).hexdigest()
            (stage / name).write_bytes(raw)
        launcher = (
            "import hashlib, pathlib, runpy, sys\nroot=pathlib.Path(__file__).resolve().parent\npins="
            + repr(pins)
            + '\nfor name, expected in pins.items():\n    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=expected:\n        raise SystemExit("CREDIT HOOK FAILED CLOSED: installed guard changed: "+name)\nsys.path.insert(0,str(root))\nrunpy.run_path(str(root/"hook_entry.py"),run_name="__main__")\n'
        )
        (stage / "entry.py").write_text(launcher)
        shutil.copytree(stage, target)
    subprocess.run([str(binary), "validate"], cwd=repo, check=True, timeout=30)
    subprocess.run([str(binary), "install"], cwd=repo, check=True, timeout=30)
    require(config_path.read_bytes() == before, "Lefthook unexpectedly changed config")
    for hook in config:
        if hook in {"pre-commit", "commit-msg", "pre-push"}:
            path = gitdir / "hooks" / hook
            require(
                path.is_file()
                and os.access(path, os.X_OK)
                and b"lefthook" in path.read_bytes(),
                "actual installed hook missing/nonexecutable",
            )
    receipt = {
        "pins": pins,
        "launcher_sha256": hashlib.sha256(
            (target / "entry.py").read_bytes()
        ).hexdigest(),
        "config_sha256": hashlib.sha256(before).hexdigest(),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }
    (target / "install-receipt.json").write_text(json.dumps(receipt, indent=2) + "\n")
    return receipt
