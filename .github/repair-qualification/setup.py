"""Bootstrap pinned Apple Silicon tools and unchanged full qualification.

No sudo, global installs, credentials or existing project reads.
"""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shlex
import shutil
import signal
import ssl
import sys
import tarfile
import tempfile
import time
import urllib.request
import zipfile
from pathlib import Path


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for chunk in iter(lambda: stream.read(65536), b""):
            result.update(chunk)
    return result.hexdigest()


def archive_target(root, name):
    path = Path(name)
    if path.is_absolute() or ".." in path.parts:
        raise ValueError("archive path rejected")
    return root / path


def extract_tar(archive, root):
    # Fixed upstream digest plus full closed inventory. Stage files first and
    # links last so no regular-file write traverses an archive-created link.
    root = root.resolve(strict=True)
    with tarfile.open(archive, "r:gz") as source:
        members = source.getmembers()
        if len(members) > 100000 or sum(m.size for m in members) > 1024 * 1024 * 1024:
            raise ValueError("archive expansion bound")
        names = set()
        for item in members:
            destination = archive_target(root, item.name)
            if item.name in names:
                raise ValueError("duplicate archive destination")
            names.add(item.name)
            if not (item.isfile() or item.isdir() or item.issym()):
                raise ValueError("unsupported archive item")
            if item.issym():
                target = (destination.parent / item.linkname).resolve()
                if target != root and root not in target.parents:
                    raise ValueError("archive symlink escapes runtime")
        link_paths = {Path(m.name) for m in members if m.issym()}
        for item in members:
            if any(parent in link_paths for parent in Path(item.name).parents):
                raise ValueError("archive entry under symbolic parent")
        for item in members:
            if item.issym():
                continue
            destination = archive_target(root, item.name)
            if item.isdir():
                destination.mkdir(parents=True, exist_ok=True)
            else:
                destination.parent.mkdir(parents=True, exist_ok=True)
                with (
                    source.extractfile(item) as incoming,
                    destination.open("xb") as output,
                ):
                    shutil.copyfileobj(incoming, output, 65536)
                destination.chmod(item.mode & 0o777)
        for item in members:
            if item.issym():
                destination = archive_target(root, item.name)
                destination.parent.mkdir(parents=True, exist_ok=True)
                destination.symlink_to(item.linkname)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-parent", required=True)
    parser.add_argument("--host-deadline-unix", required=True, type=float)
    args = parser.parse_args()
    if sys.version_info < (3, 9):  # noqa: UP036
        raise SystemExit("Existing Python3.9+ is required. Do not install anything.")
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise SystemExit("This reviewed package is for native Apple Silicon only.")
    if int(platform.mac_ver()[0].split(".")[0]) < 14:
        raise SystemExit("Playwright requires macOS14 or newer. No setup started.")
    package = Path(__file__).resolve().parent
    pins = json.loads((package / "payload/pins.json").read_text())
    for rel, expected in pins.items():
        if digest(package / rel) != expected:
            raise ValueError("package changed before setup")
    root = Path(
        tempfile.mkdtemp(
            prefix="tetrisjs-private-tools-",
            dir=Path(args.output_parent).resolve(strict=True),
        )
    )
    os.chmod(root, 0o700)
    os.umask(0o077)
    report = {
        "status": "INCOMPLETE",
        "phase": "setup",
        "qualification": False,
        "downloads": [],
        "root": str(root),
        "application_tests_started": False,
    }
    receipt = root / "setup.json"

    def save():
        temporary = root / "setup.pending"
        with temporary.open("w") as out:
            json.dump(report, out, indent=2)
            out.flush()
            os.fsync(out.fileno())
        os.replace(temporary, receipt)
        directory = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    save()
    setup_deadline = time.monotonic() + 45 * 60
    handlers = {}

    def interrupted(signum, frame):
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        report["signal"] = signum
        raise InterruptedError("setup interrupted")

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        handlers[sig] = signal.signal(sig, interrupted)
    try:
        if shutil.disk_usage(root).free < 8 * 1024 * 1024 * 1024:
            raise ValueError("at least8GiB free space required")
        # Check existing native Git before expensive download work. Full real
        # local bundle, no network/original checkout/identity mutation.
        git = Path("/usr/bin/git")
        if git.resolve(strict=True) != git or not git.is_file():
            raise ValueError("hosted Git path not canonical")
        hosted_git_hash = digest(git)
        report["hosted_git_sha256"] = hosted_git_hash
        report["hosted_image"] = {
            key: os.environ.get(key)
            for key in ("ImageOS", "ImageVersion", "RUNNER_OS", "RUNNER_ARCH")
        }
        save()
        spec = importlib.util.spec_from_file_location(
            "setup_lifetime", package / "lifetime.py"
        )
        owned = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(owned)
        probe = root / "git-feature-probe"
        probe_logs = root / "setup-commands"
        probe_logs.mkdir(mode=0o700)
        probe_env = {
            "HOME": str(root),
            "PATH": "/usr/bin:/bin",
            "LANG": "en_US.UTF-8",
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_CONFIG_GLOBAL": "/dev/null",
            "GIT_TERMINAL_PROMPT": "0",
        }
        probes = [
            ("git-init", [str(git), "init", "-q", str(probe)]),
            (
                "git-local-fetch",
                [
                    str(git),
                    "-C",
                    str(probe),
                    "fetch",
                    "--no-tags",
                    str(package / "payload/base.bundle"),
                    "refs/heads/admitted-base",
                ],
            ),
            (
                "git-feature-path",
                [
                    str(git),
                    "-C",
                    str(probe),
                    "rev-parse",
                    "--path-format=absolute",
                    "--git-common-dir",
                ],
            ),
            (
                "git-feature-shallow",
                [str(git), "-C", str(probe), "rev-parse", "--is-shallow-repository"],
            ),
            (
                "git-feature-ancestry",
                [
                    str(git),
                    "-C",
                    str(probe),
                    "rev-list",
                    "--parents",
                    "97fad4864c11b9669cd80bd6d7e7e7998f314eaa",
                    "--",
                ],
            ),
            (
                "git-feature-object",
                [
                    str(git),
                    "-C",
                    str(probe),
                    "cat-file",
                    "-t",
                    "97fad4864c11b9669cd80bd6d7e7e7998f314eaa",
                ],
            ),
        ]
        report["git_feature_commands"] = []
        for label, argv in probes:
            result, error = owned.run(argv, root, probe_env, probe_logs, label, 60)
            report["git_feature_commands"].append(result)
            save()
            if error is not None:
                raise error
        if (probe_logs / "git-feature-path/stdout.log").read_text().strip() != str(
            probe / ".git"
        ):
            raise ValueError("Git absolute-path feature unsupported")
        if (
            probe_logs / "git-feature-shallow/stdout.log"
        ).read_text().strip() != "false":
            raise ValueError("Git shallow feature mismatch")
        if (
            probe_logs / "git-feature-object/stdout.log"
        ).read_text().strip() != "commit":
            raise ValueError("Git commit feature mismatch")
        # Ignore ambient proxy/CA selection, keep certificate verification ON.
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        prior_ca = {
            k: os.environ.pop(k, None) for k in ("SSL_CERT_FILE", "SSL_CERT_DIR")
        }
        try:
            context.load_default_certs()
        finally:
            for key, value in prior_ca.items():
                if value is not None:
                    os.environ[key] = value
        opener = urllib.request.build_opener(
            urllib.request.ProxyHandler({}),
            urllib.request.HTTPSHandler(context=context),
        )
        sources = json.loads((package / "payload/runtime-sources.json").read_text())
        # Each expected digest comes from upstream-verified review, not live
        # machine observation. Downloads are explicit approved setup effects.
        for name, info in sources.items():
            if time.monotonic() >= setup_deadline:
                raise TimeoutError("setup allowance expired")
            report["current_download"] = name
            save()
            target = root / (name + ".download")
            request = urllib.request.Request(
                info["url"], headers={"User-Agent": "TetrisJS-private-check"}
            )
            total = 0
            with (
                opener.open(request, timeout=60) as incoming,
                target.open("xb") as out,
            ):
                while True:
                    if time.monotonic() >= setup_deadline:
                        raise TimeoutError("setup allowance expired")
                    data = incoming.read(65536)
                    if not data:
                        break
                    total += len(data)
                    if total > 200 * 1024 * 1024:
                        raise ValueError(
                            "setup archive exceeds reviewed generous bound"
                        )
                    out.write(data)
            if digest(target) != info["sha256"]:
                raise ValueError("download digest mismatch")
            report["downloads"].append(
                {"name": name, "sha256": info["sha256"], "bytes": total}
            )
            save()
        runtime = root / "runtime"
        runtime.mkdir(mode=0o700)
        extract_tar(root / "python.download", runtime)
        extract_tar(root / "node.download", runtime)
        npm_root = runtime / "npm"
        npm_root.mkdir()
        extract_tar(root / "npm.download", npm_root)
        site = runtime / "python/lib/python3.13/site-packages"
        with zipfile.ZipFile(root / "PyYAML.download") as wheel:
            for name in wheel.namelist():
                archive_target(site, name)
                if (wheel.getinfo(name).external_attr >> 16) & 0o170000 == 0o120000:
                    raise ValueError("wheel symlink rejected")
            wheel.extractall(site)
        bindir = runtime / "bin"
        bindir.mkdir()
        python = (runtime / "python/bin/python3.13").resolve(strict=True)
        node = (runtime / "node-v26.13.0-darwin-arm64/bin/node").resolve(strict=True)
        lefthook = bindir / "lefthook"
        shutil.copyfile(root / "lefthook.download", lefthook)
        lefthook.chmod(0o755)
        with zipfile.ZipFile(root / "ruff.download") as wheel:
            (bindir / "ruff").write_bytes(wheel.read("ruff-0.17.4.data/scripts/ruff"))
        (bindir / "ruff").chmod(0o755)
        (bindir / "python3").symlink_to(python)
        (bindir / "node").symlink_to(node)
        # Exact npm12.2.0 package, not Node's bundled11.x. Minimal wrapper binds
        # explicit Node and CLI, no global npm installation or user npmrc.
        npm_cli = npm_root / "package/bin/npm-cli.js"
        npm = bindir / "npm"
        npm.write_text(
            "#!/bin/sh\nexec "
            + shlex.quote(str(node))
            + " "
            + shlex.quote(str(npm_cli))
            + ' "$@"\n'
        )
        npm.chmod(0o755)
        home = root / "private-home"
        home.mkdir(mode=0o700)
        browsers = root / "browsers"
        browsers.mkdir(mode=0o700)
        user_npmrc = root / "empty-user.npmrc"
        global_npmrc = root / "empty-global.npmrc"
        for config in (user_npmrc, global_npmrc):
            descriptor = os.open(config, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(descriptor)
        env = {
            "HOME": str(home),
            "PATH": str(bindir) + ":/usr/bin:/bin:/usr/sbin:/sbin",
            "LANG": "en_US.UTF-8",
            "CI": "1",
            "CREDIT_TEST_LEFTHOOK": str(lefthook),
            "PLAYWRIGHT_BROWSERS_PATH": str(browsers),
            "PLAYWRIGHT_SKIP_BROWSER_GC": "1",
            "npm_config_cache": str(root / "npm-cache"),
            "npm_config_userconfig": str(user_npmrc),
            "npm_config_globalconfig": str(global_npmrc),
        }
        # Fresh GitHub-hosted image trust, same feature probes and run binding.
        git = Path("/usr/bin/git")
        if git.resolve(strict=True) != git or digest(git) != hosted_git_hash:
            raise ValueError("hosted native Git changed during setup")
        tools = [git, python, node, npm, npm_cli, bindir / "ruff", lefthook]
        admission = {
            "platform": ["Darwin", "arm64"],
            "base": "97fad4864c11b9669cd80bd6d7e7e7998f314eaa",
            "python": str(python),
            "git": str(git),
            "node": str(node),
            "npm": str(npm),
            "ruff": str(bindir / "ruff"),
            "lefthook": str(lefthook),
            "tools": {str(p): digest(p) for p in tools},
            "environment": env,
            "browsers": {},
            "browser_install": True,
            "provenance": "reviewed upstream archives; fresh GitHub image native Git, feature-probed and hash-bound",
            "host_deadline_unix": args.host_deadline_unix,
        }
        admission_path = root / "runtime-admission.json"
        admission_path.write_text(json.dumps(admission, indent=2))
        if time.monotonic() >= setup_deadline:
            raise TimeoutError("setup allowance expired before handoff")
        report["phase"] = "full_tests"
        report["fullrun_handoff_attempted"] = True
        save()
        # Full-run foreground process must own SIGINT/TERM/HUP and complete
        # lifetime itself. exec preserves Terminal, no short parent timeout.
        os.execve(
            str(python),
            [
                str(python),
                "-I",
                str(package / "run.py"),
                "--admission",
                str(admission_path),
                "--output-parent",
                str(root),
            ],
            env,
        )
    except BaseException as exc:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        report["error_class"] = type(exc).__name__
        report["status"] = "INCOMPLETE"
        save()
        print("Setup incomplete. Keep only setup.json for review; do not rerun.")
        print(receipt)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
