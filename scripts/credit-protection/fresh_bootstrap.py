import hashlib
import json
import os
import stat
import subprocess
import tempfile
from pathlib import Path

from hook_installer import read_owned
from production_entry import TARGETS


class Stop(Exception):
    pass


def sha(raw):
    return hashlib.sha256(raw).hexdigest()


def durable(path, raw, mode=0o600):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, mode)
    os.fchmod(fd, mode)
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())


def sync(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def read_pinned(path, limit):
    pass
    from release_owner import parent_fd

    directory, name = parent_fd(path)
    fd = None
    try:
        fd = os.open(
            name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory
        )
        before = os.fstat(fd)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid not in (0, os.getuid())
            or stat.S_IMODE(before.st_mode) & 0o022
            or before.st_size > limit
        ):
            raise Stop("reviewed host tool custody")
        data = bytearray()
        while len(data) <= limit:
            chunk = os.read(fd, min(65536, limit + 1 - len(data)))
            if not chunk:
                break
            data.extend(chunk)
        after = os.fstat(fd)
        if len(data) != before.st_size or (
            before.st_dev,
            before.st_ino,
            before.st_size,
            before.st_mtime_ns,
        ) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns):
            raise Stop("host tool changed during read")
        return bytes(data)
    finally:
        if fd is not None:
            os.close(fd)
        os.close(directory)


def install(checkout, sources, expected, read_repository, verify_original, record):
    pass

    import copy

    import atomic_hook
    import installer_owner

    expected = copy.deepcopy(expected)
    approved_digest = installer_owner.digest(expected)
    if verify_original(expected, approved_digest) is not True:
        raise Stop("standing hook authority does not cover exact bootstrap")
    if installer_owner.digest(expected) != approved_digest:
        raise Stop("approval callback changed bootstrap")
    root, source = Path(checkout), Path(sources)
    if (
        not root.is_absolute()
        or root != root.resolve(strict=True)
        or source != source.resolve(strict=True)
        or str(root) != expected["checkout"]
    ):
        raise Stop("bootstrap canonical paths differ")
    if expected["repo"] not in TARGETS:
        raise Stop("bootstrap outside selected replacement repositories")
    identity = read_repository(expected["repo"])
    if (
        identity.get("id") != expected["repo_id"]
        or identity.get("full_name") != expected["repo"]
    ):
        raise Stop("bootstrap live repo identity differs")

    for path, pin in expected["source_tools"].items():
        raw = read_pinned(path, 64 << 20)
        if sha(raw) != pin:
            raise Stop("bootstrap source or host tool differs")
    for name in (
        "strict_guard.py",
        "publication_gate.py",
        "denied.json",
        "hook_entry.py",
        "prepush_admission.py",
    ):
        if str(source / name) not in expected["source_tools"]:
            raise Stop("missing reviewed project source pin")
    git, python, runner = (expected[key] for key in ("git", "python", "lefthook"))
    for path in (git, python, runner, str(Path(__file__).resolve())):
        if path not in expected["source_tools"]:
            raise Stop("missing reviewed runtime or installer pin")
    env = {
        "PATH": str(Path(git).parent) + ":/usr/bin:/bin",
        "HOME": str(root),
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }

    def command(*args):
        value = subprocess.run(
            [git, "-C", str(root), *args], env=env, capture_output=True, timeout=30
        )
        if value.returncode:
            raise Stop("bootstrap Git inspection failed")
        return value.stdout.decode().strip()

    if command("rev-parse", "HEAD") != expected["head"]:
        raise Stop("bootstrap head differs")
    config_text = command("config", "--local", "--includes", "--list")
    for line in config_text.splitlines():
        key = line.split("=", 1)[0].lower()
        if key.startswith(
            (
                "include.",
                "includeif.",
                "url.",
                "http.",
                "credential.",
                "core.hookspath",
                "core.sshcommand",
                "core.gitproxy",
            )
        ):
            raise Stop("bootstrap redirecting configuration")
    if (
        command("config", "--local", "--get-all", "remote.origin.url")
        != expected["origin"]
    ):
        raise Stop("bootstrap origin differs")
    if expected["origin"] != "https://github.com/" + expected["repo"] + ".git":
        raise Stop("bootstrap origin outside repository")
    hookfd = atomic_hook.open_hooks(str(root))
    os.close(hookfd)
    gitdir = root / ".git"
    hooks = gitdir / "hooks"
    if (
        gitdir.is_symlink()
        or not gitdir.is_dir()
        or any(not path.name.endswith(".sample") for path in hooks.iterdir())
        or (gitdir / "credit-guard").exists()
        or (gitdir / "credit-admission-pending").exists()
        or (gitdir / "info/lefthook.checksum").exists()
    ):
        raise Stop("bootstrap requires actual empty fresh hook state")
    pending = gitdir / "credit-admission-pending"
    record(
        "fresh_hook_bootstrap_pending",
        {
            "digest": approved_digest,
            "repo": expected["repo"],
            "repo_id": expected["repo_id"],
        },
    )
    durable(pending, b"fresh genuine hook installation pending\n")
    durable(
        hooks / "pre-push",
        b'#!/bin/sh\necho "CREDIT INSTALLATION PENDING" >&2\nexit 1\n',
        0o700,
    )
    sync(hooks)
    sync(gitdir)
    source_config, _ = read_owned(root / "lefthook.yml")
    config_raw = source_config
    if not isinstance(expected.get("generated_hook_pins"), dict):
        raise Stop("independent generated hook pins missing")
    if sha(config_raw) != expected["config_sha256"]:
        raise Stop("bootstrap config differs from project review")

    module_raw, _ = read_owned(source / "prepush_admission.py")
    namespace = {"__name__": "reviewed_project_admission"}
    exec(compile(module_raw, str(source / "prepush_admission.py"), "exec"), namespace)
    for override in namespace["OVERRIDES"]:
        if os.path.lexists(root / override):
            raise Stop("bootstrap local override present")

    with tempfile.TemporaryDirectory(prefix="genuine-hooks-", dir=gitdir) as temporary:
        stage = Path(temporary)
        subprocess.run([git, "init", "-q", str(stage)], env=env, check=True, timeout=30)
        staged_config = stage / "lefthook.yml"
        staged_config.write_bytes(config_raw)
        config_stat = (root / "lefthook.yml").stat()
        os.utime(staged_config, ns=(config_stat.st_atime_ns, config_stat.st_mtime_ns))
        subprocess.run([runner, "install"], cwd=stage, env=env, check=True, timeout=30)
        outputs = {
            name: (stage / ".git/hooks" / name).read_bytes()
            for name in ("pre-commit", "commit-msg")
        }
        if set(expected["generated_hook_pins"]) != set(outputs) or any(
            sha(raw) != expected["generated_hook_pins"][name]
            for name, raw in outputs.items()
        ):
            raise Stop("genuine generated hook outputs differ from review")
        active = {
            p.name
            for p in (stage / ".git/hooks").iterdir()
            if not p.name.endswith(".sample")
        }
        if active != set(outputs):
            raise Stop("runner generated unreviewed hook set")
        scheduler = (stage / ".git/info/lefthook.checksum").read_bytes()
        fields = scheduler.decode("ascii").strip().split()
        if (
            len(fields) != 2
            or len(fields[0]) != 32
            or fields[1] != str(int(config_stat.st_mtime))
        ):
            raise Stop("genuine scheduler format or timestamp differs")
    guard = gitdir / "credit-guard"
    guard.mkdir(mode=0o700)
    pins = {}
    for name in (
        "strict_guard.py",
        "publication_gate.py",
        "denied.json",
        "hook_entry.py",
    ):
        raw, _ = read_owned(source / name)
        durable(guard / name, raw)
        pins[name] = sha(raw)

    launcher = (
        "import hashlib,pathlib,runpy,sys\nsys.dont_write_bytecode=True\nroot=pathlib.Path(__file__).resolve().parent\npins="
        + repr(pins)
        + "\nfor name,pin in pins.items():\n"
        + ' if hashlib.sha256((root/name).read_bytes()).hexdigest()!=pin: raise SystemExit("CREDIT SOURCE CHANGED")\n'
        + 'sys.path.insert(0,str(root))\nrunpy.run_path(str(root/"hook_entry.py"),run_name="__main__")\n'
    ).encode()
    durable(guard / "entry.py", launcher)
    for name, raw in outputs.items():
        durable(hooks / name, raw, 0o755)
    scheduler_path = gitdir / "info/lefthook.checksum"
    durable(scheduler_path, scheduler)
    revision = gitdir / "credit-admission-fresh"
    revision.mkdir(mode=0o700)
    durable(revision / "prepush_admission.py", module_raw)
    dependencies = [
        Path(git),
        Path(python),
        Path(runner),
        root / "lefthook.yml",
        scheduler_path,
        hooks / "pre-commit",
        hooks / "commit-msg",
        revision / "prepush_admission.py",
        *guard.iterdir(),
    ]
    manifest = {
        "repo": str(root),
        "python": python,
        "git": git,
        "guard_entry": str(guard / "entry.py"),
        "pending": str(pending),
        "remaining_jobs": [],
        "pins": {str(p): sha(p.read_bytes()) for p in dependencies},
    }
    manifest_raw = (json.dumps(manifest, sort_keys=True, indent=2) + "\n").encode()
    manifest_path = revision / "manifest.json"
    durable(manifest_path, manifest_raw)
    receipt = {
        "kind": "genuine-fresh-no-prior-installation",
        "manifest_sha256": sha(manifest_raw),
        "bootstrap_digest": approved_digest,
    }
    receipt_raw = (json.dumps(receipt, sort_keys=True, indent=2) + "\n").encode()
    receipt_path = revision / "install-receipt.json"
    durable(receipt_path, receipt_raw)

    import ast

    tree = ast.parse(module_raw)
    node = next(
        n
        for n in tree.body
        if isinstance(n, ast.FunctionDef) and n.name == "read_regular"
    )
    reader = ast.get_source_segment(module_raw.decode(), node).replace(
        "limit=LIMIT", "limit=2097152"
    )
    wrapper = (
        "#!"
        + python
        + "\nimport os,stat,hashlib,sys\nfrom pathlib import Path\n"
        + reader
        + "\ntry:\n p="
        + repr(str(revision / "prepush_admission.py"))
        + "\n b=read_regular(p)\n if hashlib.sha256(b).hexdigest()!="
        + repr(sha(module_raw))
        + ': raise ValueError("admission source changed")\n g={"__name__":"genuine_admission"}\n'
        + ' exec(compile(b,p,"exec"),g)\n sys.exit(g["run"]('
        + repr(str(manifest_path))
        + ","
        + repr(sha(manifest_raw))
        + ","
        + repr(str(receipt_path))
        + ","
        + repr(sha(receipt_raw))
        + "))\n"
        + 'except (OSError,ValueError) as error:\n print("CREDIT ADMISSION STOPPED",file=sys.stderr)\n sys.exit(1)\n'
    ).encode()
    durable(hooks / "fresh-prepush.pending", wrapper, 0o700)

    for dependency, expected_pin in manifest["pins"].items():
        if sha(read_pinned(dependency, 64 << 20)) != expected_pin:
            raise Stop("bootstrap dependency changed before final wrapper")
    for directory in (guard, revision, scheduler_path.parent, hooks, gitdir):
        sync(directory)
    if (root / "lefthook.yml").read_bytes() != config_raw:
        raise Stop("project config changed during bootstrap")
    os.replace(hooks / "fresh-prepush.pending", hooks / "pre-push")
    sync(hooks)
    pending.unlink()
    sync(gitdir)
    record(
        "fresh_hook_bootstrap_confirmed",
        {
            "digest": approved_digest,
            "prepush_sha256": sha(wrapper),
            "manifest_sha256": sha(manifest_raw),
            "genuine_hooks": {name: sha(raw) for name, raw in outputs.items()},
        },
    )
    installed = [
        *guard.iterdir(),
        *revision.iterdir(),
        scheduler_path,
        hooks / "pre-commit",
        hooks / "commit-msg",
        hooks / "pre-push",
    ]
    return {
        "hook": str(hooks / "pre-push"),
        "sha256": sha(wrapper),
        "manifest": str(manifest_path),
        "receipt": str(receipt_path),
        "created_files": {str(path): sha(path.read_bytes()) for path in installed},
        "created_directories": [str(guard), str(revision)],
        "repo": expected["repo"],
        "repo_id": expected["repo_id"],
        "checkout": str(root),
        "head": expected["head"],
        "origin": expected["origin"],
        "config_sha256": expected["config_sha256"],
    }


def rollback_fresh(receipt, verify_original, read_repository, record):
    pass

    import copy

    import installer_owner
    from release_owner import parent_fd

    receipt = copy.deepcopy(receipt)
    expected_digest = installer_owner.digest(receipt)
    if verify_original(receipt, expected_digest) is not True:
        raise Stop("fresh hook rollback not covered by original authority")
    if installer_owner.digest(receipt) != expected_digest:
        raise Stop("fresh rollback receipt mutated")
    identity = read_repository(receipt["repo"])
    if (
        identity.get("id") != receipt["repo_id"]
        or identity.get("full_name") != receipt["repo"]
    ):
        raise Stop("fresh rollback repository identity differs")
    root = Path(receipt["checkout"])
    if not root.is_absolute() or root != root.resolve(strict=True):
        raise Stop("fresh rollback checkout custody differs")
    gitdir = root / ".git"
    hooks = gitdir / "hooks"
    guard = gitdir / "credit-guard"
    revision = gitdir / "credit-admission-fresh"
    allowed = {str(hooks / name) for name in ("pre-commit", "commit-msg", "pre-push")}
    allowed.add(str(gitdir / "info/lefthook.checksum"))
    allowed.update(
        str(guard / name)
        for name in (
            "strict_guard.py",
            "publication_gate.py",
            "denied.json",
            "hook_entry.py",
            "entry.py",
        )
    )
    allowed.update(
        str(revision / name)
        for name in ("prepush_admission.py", "manifest.json", "install-receipt.json")
    )
    if set(receipt["created_files"]) != allowed or receipt["created_directories"] != [
        str(guard),
        str(revision),
    ]:
        raise Stop("fresh rollback file scope differs")
    if {str(p) for p in guard.iterdir()} != {
        s for s in allowed if str(Path(s).parent) == str(guard)
    }:
        raise Stop("fresh guard has unexpected later files")
    if {str(p) for p in revision.iterdir()} != {
        s for s in allowed if str(Path(s).parent) == str(revision)
    }:
        raise Stop("fresh revision has unexpected later files")
    if {p.name for p in hooks.iterdir() if not p.name.endswith(".sample")} != {
        "pre-commit",
        "commit-msg",
        "pre-push",
    }:
        raise Stop("fresh hooks have unexpected later entries")
    opened = []
    try:
        for path, expected_pin in receipt["created_files"].items():
            directory, name = parent_fd(path)
            raw, _ = read_owned(path, 64 << 20)
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if sha(raw) != expected_pin:
                os.close(directory)
                raise Stop("fresh installed file changed, not removed")
            opened.append((directory, name, info.st_dev, info.st_ino))
        config_raw, _ = read_owned(root / "lefthook.yml")
        if sha(config_raw) != receipt["config_sha256"]:
            raise Stop("fresh rollback config changed")
        record(
            "fresh_hook_rollback_pending",
            {
                "receipt_sha256": expected_digest,
                "repo": receipt["repo"],
                "repo_id": receipt["repo_id"],
            },
        )

        for directory, name, dev, ino in opened:
            info = os.stat(name, dir_fd=directory, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != (dev, ino):
                raise Stop("fresh rollback identity changed")
            os.unlink(name, dir_fd=directory)
            os.fsync(directory)
        os.rmdir(guard)
        os.rmdir(revision)
        sync(gitdir)
        record(
            "fresh_hook_rollback_confirmed",
            {
                "receipt_sha256": expected_digest,
                "restored": "original-empty-hook-state-no-work-authorized",
            },
        )
    finally:
        for directory, _, _, _ in opened:
            os.close(directory)
