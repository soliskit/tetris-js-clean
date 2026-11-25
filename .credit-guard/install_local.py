"""Local isolated-checkout installer candidate. No remote effects."""

import hashlib
import json
import os
import platform
import shutil
import stat
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
# Keep the admitted Linux binary unchanged; Mac entries are proposed pins.
LEFTHOOK_PLATFORM_PINS = {
    ("Linux", "x86_64"): LEFTHOOK_SHA256,
    (
        "Darwin",
        "arm64",
    ): "4a2bded27339e7b521b72fe123cd343e8bba6b73fe92641f062c2644ca65a534",
    (
        "Darwin",
        "x86_64",
    ): "28b19fc1c61ec74a1d40aadab932b8262365407cd86a48329791178c95a0ee35",
}


def platform_binary_pin():
    """Closed reviewed platform binding, never an observed-binary allowlist."""
    key = (platform.system(), platform.machine())
    require(key in LEFTHOOK_PLATFORM_PINS, "unreviewed Lefthook platform")
    return LEFTHOOK_PLATFORM_PINS[key]


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


def _read_regular(path, limit=2 * 1024 * 1024):
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


def _durable(path, data, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    try:
        with os.fdopen(fd, "wb", closefd=False) as stream:
            stream.write(data)
            stream.flush()
            os.fsync(fd)
    finally:
        os.close(fd)


def _syncdir(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def install(repo, source, lefthook, expected, checkpoint=None):
    """Install a reviewed revision; interrupted revisions stay blocking."""
    import sys
    import uuid

    # The checked caller verifies this installer against its reviewed candidate
    # before calling. Expectations come from independent review, not this API.
    # Select once, before any filesystem mutation. Unknown platforms refuse.
    selected_binary_pin = platform_binary_pin()
    repo, source = Path(repo).absolute(), Path(source).absolute()
    # Callers select canonical paths before independent admission. Do not
    # silently retarget reviewed expectations or weaken nofollow traversal.
    for canonical_input in (repo, source, Path(lefthook).absolute()):
        require(
            canonical_input == canonical_input.resolve(strict=True),
            "noncanonical input requires separate path admission",
        )
    require(expected["repo"] == str(repo), "expected repository mismatch")
    module = source / "prepush_admission.py"
    # Duplicate anchored bounded reader here: helper is untrusted until hashed.
    read = _read_regular
    for path, pin in expected["source_tools"].items():
        require(
            hashlib.sha256(read(path, 64 * 1024 * 1024)).hexdigest() == pin,
            "reviewed source/tool mismatch: " + path,
        )
    for path in [
        module,
        Path(__file__).absolute(),
        Path(sys.executable).resolve(),
        Path(shutil.which("git")).resolve(),
        Path(lefthook).absolute(),
    ]:
        require(
            str(path) in expected["source_tools"], "missing independent expected pin"
        )
    namespace = {"__name__": "credit_install_io"}
    exec(compile(read(module), str(module), "exec"), namespace)
    git = Path(expected["git"])
    python = Path(expected["python"])
    binary = Path(lefthook).absolute()
    require(git == Path(shutil.which("git")).resolve(), "expected Git path mismatch")
    require(python == Path(sys.executable).resolve(), "expected Python path mismatch")

    def command(*args):
        return (
            subprocess.check_output([str(git), "-C", str(repo), *args]).decode().strip()
        )

    def mark(name):
        if checkpoint is not None:
            checkpoint(name)

    require(
        hashlib.sha256(read(binary, 64 * 1024 * 1024)).hexdigest()
        == selected_binary_pin,
        "reviewed Lefthook binary mismatch",
    )
    for name, expected_digest in SOURCE_PINS.items():
        require(
            hashlib.sha256(read(source / name)).hexdigest() == expected_digest,
            "reviewed guard mismatch: " + name,
        )
    custom = subprocess.run(
        [str(git), "-C", str(repo), "config", "--get", "core.hooksPath"],
        capture_output=True,
        check=False,
    )
    require(custom.returncode == 1, "custom hooksPath or config failure")
    config_raw = read(repo / "lefthook.yml")
    config = yaml.safe_load(config_raw)
    require("pre-push" not in config, "sole old pre-push job must be removed")
    require(
        config.get("commit-msg", {}).get("commands") == HOOKS["commit-msg"],
        "commit-msg configuration changed",
    )
    for key in os.environ:
        require(
            not key.startswith(("LEFTHOOK", "GIT_CONFIG", "GIT_EXEC_PATH", "PYTHON")),
            "unapproved environment override: " + key,
        )
    for name in namespace["OVERRIDES"]:
        require(not os.path.lexists(repo / name), "unexpected config/source: " + name)
    gitdir = Path(command("rev-parse", "--absolute-git-dir"))
    hooks = gitdir / "hooks"
    hooks.mkdir(exist_ok=True)
    pending = gitdir / "credit-admission-pending"
    require(not os.path.lexists(pending), "unfinished installation requires review")
    oldguard = gitdir / "credit-guard"
    old_paths = [hooks / name for name in ("pre-commit", "commit-msg", "pre-push")]
    old_paths += [
        oldguard / name for name in (*FILES, "entry.py", "install-receipt.json")
    ]
    require(
        set(expected["old_pins"]) == {str(p) for p in old_paths},
        "complete expected old installation required",
    )
    for path in old_paths:
        require(
            hashlib.sha256(read(path)).hexdigest() == expected["old_pins"][str(path)],
            "old installation drift: " + str(path),
        )
    require(
        {p.name for p in oldguard.iterdir()}
        == set(FILES) | {"entry.py", "install-receipt.json"},
        "unexpected old guard contents",
    )
    # Existing launcher semantics are fixed by the independent old-installation
    # expectations and receipt; observed bytes alone are never approval.
    old_receipt = json.loads(read(oldguard / "install-receipt.json"))
    old_config = expected["old_config"].encode()
    require(
        hashlib.sha256(old_config).hexdigest() == old_receipt["config_sha256"],
        "old config/receipt lineage mismatch",
    )
    require(old_receipt["pins"] == SOURCE_PINS, "old guard receipt pins changed")
    require(
        old_receipt["launcher_sha256"]
        == expected["old_pins"][str(oldguard / "entry.py")],
        "old launcher receipt mismatch",
    )
    require(old_receipt["binary_sha256"] == selected_binary_pin, "old binary mismatch")
    require(
        hashlib.sha256(config_raw).hexdigest() == expected["new_config_sha256"],
        "new config not reviewed",
    )
    for name, pin in SOURCE_PINS.items():
        require(
            expected["old_pins"][str(oldguard / name)] == pin,
            "old guard source mismatch",
        )
    require(
        {p.name for p in hooks.iterdir() if not p.name.endswith(".sample")}
        == {"pre-commit", "commit-msg", "pre-push"},
        "unexpected active hook",
    )
    scheduler = gitdir / "info/lefthook.checksum"
    require(
        hashlib.sha256(read(scheduler)).hexdigest() == expected["old_scheduler_sha256"],
        "old scheduler state changed",
    )
    # Authentic pinned runner generates NEW deterministic hooks/checksum only in
    # private staging. Its config mtime matches the real target, not fabricated
    # checksum text. No Git metadata from staging is copied beyond these outputs.
    with tempfile.TemporaryDirectory(prefix="credit-sync-stage-", dir=gitdir) as tmp:
        stage = Path(tmp)
        subprocess.run([str(git), "init", "-q", str(stage)], check=True)
        staged_config = stage / "lefthook.yml"
        staged_config.write_bytes(config_raw)
        config_stat = (repo / "lefthook.yml").stat()
        os.utime(staged_config, ns=(config_stat.st_atime_ns, config_stat.st_mtime_ns))
        subprocess.run([str(binary), "install"], cwd=stage, check=True, timeout=30)
        generated = {
            name: read(stage / ".git/hooks" / name)
            for name in ("pre-commit", "commit-msg")
        }
        require(
            set(expected["generated_hook_pins"]) == set(generated),
            "expected generated hook set",
        )
        for name, raw in generated.items():
            require(
                hashlib.sha256(raw).hexdigest()
                == expected["generated_hook_pins"][name],
                "deterministic generated hook mismatch: " + name,
            )
        new_scheduler = read(stage / ".git/info/lefthook.checksum")
        fields = new_scheduler.decode("ascii").strip().split()
        require(
            len(fields) == 2
            and len(fields[0]) == 32
            and fields[1] == str(int(config_stat.st_mtime)),
            "unexpected scheduler format/mtime",
        )
        require(
            {
                p.name
                for p in (stage / ".git/hooks").iterdir()
                if not p.name.endswith(".sample")
            }
            == set(generated),
            "staging generated unexpected hook",
        )
    revision = gitdir / ("credit-admission-" + uuid.uuid4().hex)
    revision.mkdir(mode=0o700)
    archive = revision / "previous"
    archive.mkdir()
    for name in ("pre-commit", "commit-msg", "pre-push"):
        _durable(archive / name, read(hooks / name), 0o700)
    saved = archive / "credit-guard"
    saved.mkdir()
    for path in oldguard.iterdir():
        _durable(saved / path.name, read(path))
    _syncdir(saved)
    _durable(archive / "lefthook.yml", old_config)
    _durable(archive / "lefthook.checksum", read(scheduler))
    _syncdir(archive)
    _syncdir(revision)
    _syncdir(gitdir)
    mark("archive")
    _durable(pending, b"credit admission installation pending\n")
    sentinel = hooks / ("credit-sentinel-" + revision.name)
    _durable(
        sentinel, b'#!/bin/sh\necho "CREDIT INSTALLATION PENDING" >&2\nexit 1\n', 0o700
    )
    os.replace(sentinel, hooks / "pre-push")
    _syncdir(hooks)
    _syncdir(gitdir)
    mark("sentinel")
    guard = revision / "guard"
    guard.mkdir()
    for name in FILES:
        _durable(guard / name, read(source / name))
    # Preserve the admitted per-use pin-verifying stable launcher unchanged.
    _durable(guard / "entry.py", read(oldguard / "entry.py"))
    _durable(revision / "prepush_admission.py", read(module))
    # Only independently expected generated hook bytes and authentic scheduler
    # output are installed under the durable rejecting pre-push barrier.
    for name, raw in generated.items():
        staged_hook = hooks / ("credit-generated-" + name)
        _durable(staged_hook, raw, 0o755)
        os.replace(staged_hook, hooks / name)
    staged_scheduler = scheduler.with_name("credit-generated-checksum")
    _durable(staged_scheduler, new_scheduler)
    os.replace(staged_scheduler, scheduler)
    _syncdir(scheduler.parent)
    _syncdir(hooks)
    mark("scheduler")
    pins = {}
    paths = [
        binary,
        git,
        python,
        repo / "lefthook.yml",
        revision / "prepush_admission.py",
        scheduler,
    ]
    paths += (
        list(guard.iterdir())
        + list(oldguard.iterdir())
        + [hooks / "pre-commit", hooks / "commit-msg"]
    )
    for path in paths:
        pins[str(path)] = hashlib.sha256(read(path, 64 * 1024 * 1024)).hexdigest()
    manifest = {
        "repo": str(repo),
        "python": str(python),
        "git": str(git),
        "guard_entry": str(guard / "entry.py"),
        "pending": str(pending),
        "remaining_jobs": [],
        "pins": pins,
        "old_receipt_sha256": expected["old_pins"][
            str(oldguard / "install-receipt.json")
        ],
    }
    manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    manifest_path = revision / "manifest.json"
    _durable(manifest_path, manifest_raw)
    receipt = {
        "manifest_sha256": hashlib.sha256(manifest_raw).hexdigest(),
        "previous_receipt_sha256": expected["old_pins"][
            str(oldguard / "install-receipt.json")
        ],
        "revision": str(revision),
    }
    receipt_raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    receipt_path = revision / "install-receipt.json"
    _durable(receipt_path, receipt_raw)
    # Reader source is embedded from this independently reviewed installer.
    import inspect

    reader_source = inspect.getsource(_read_regular).replace(
        "def _read_regular(", "def read("
    )
    wrapper = (
        "#!"
        + str(python)
        + "\nimport os,stat,hashlib,sys\nfrom pathlib import Path\n"
        + reader_source
        + "\ntry:\n p="
        + repr(str(revision / "prepush_admission.py"))
        + "\n b=read(p)\n if hashlib.sha256(b).hexdigest()!="
        + repr(pins[str(revision / "prepush_admission.py")])
        + ': raise ValueError("module changed")\n g={"__name__":"credit_admission"}\n'
        + ' exec(compile(b,p,"exec"),g)\n sys.exit(g["run"]('
        + repr(str(manifest_path))
        + ","
        + repr(hashlib.sha256(manifest_raw).hexdigest())
        + ","
        + repr(str(receipt_path))
        + ","
        + repr(hashlib.sha256(receipt_raw).hexdigest())
        + '))\nexcept (OSError,ValueError) as e:\n print("CREDIT BOOTSTRAP FAILED CLOSED: "+str(e),file=sys.stderr)\n sys.exit(1)\n'
    ).encode()
    _syncdir(guard)
    _syncdir(revision)
    _syncdir(gitdir)
    _syncdir(hooks)
    mark("dependencies")
    staged = hooks / ("credit-wrapper-" + revision.name)
    _durable(staged, wrapper, 0o700)
    os.replace(staged, hooks / "pre-push")
    _syncdir(hooks)
    mark("wrapper")
    pending.unlink()
    _syncdir(gitdir)
    mark("complete")
    return {
        "manifest": manifest,
        "receipt": receipt,
        "wrapper_sha256": hashlib.sha256(wrapper).hexdigest(),
    }
