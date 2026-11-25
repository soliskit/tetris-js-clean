"""Review draft. Never run before source/runtime effect decision and review."""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import shutil
import signal
import sys
import tarfile
import time
from pathlib import Path

_LIFETIME_PATH = Path(__file__).resolve().parent / "lifetime.py"
if (
    hashlib.sha256(_LIFETIME_PATH.read_bytes()).hexdigest()
    != "58b59786d9e0a8f18be3d3078611e519552ba4ae221def27f79f671fe48b6b37"
):
    raise ValueError("lifetime source changed")
_SPEC = importlib.util.spec_from_file_location("reviewed_lifetime", _LIFETIME_PATH)
lifetime = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(lifetime)

BASE = "97fad4864c11b9669cd80bd6d7e7e7998f314eaa"
EXCLUDE = {
    ".git",
    "node_modules",
    "dist",
    ".release-evidence",
    "coverage",
    "reports",
    "test-results",
    "playwright-report",
    "__pycache__",
    ".ruff_cache",
}


def digest(path):
    result = hashlib.sha256()
    with Path(path).open("rb") as source:
        for chunk in iter(lambda: source.read(65536), b""):
            result.update(chunk)
    return result.hexdigest()


def file_map(root, exclude=()):
    data = {}
    for path in sorted(Path(root).rglob("*")):
        rel = path.relative_to(root)
        if any(part in exclude for part in rel.parts):
            continue
        if path.is_symlink():
            raise ValueError("source/output symlink")
        if path.is_file():
            data[str(rel)] = {
                "sha256": digest(path),
                "mode": path.stat().st_mode & 0o777,
            }
    return data


def browser_map(root):
    data = {}
    for path in sorted(Path(root).rglob("*")):
        rel = str(path.relative_to(root))
        if path.is_symlink():
            data[rel] = {"symlink": os.readlink(path)}
        elif path.is_file():
            data[rel] = {"sha256": digest(path), "mode": path.stat().st_mode & 0o777}
    return data


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--admission", required=True)
    parser.add_argument("--output-parent", required=True)
    args = parser.parse_args()
    package = Path(__file__).resolve().parent
    admission = json.loads(Path(args.admission).read_text())
    # Supplied admission is independently reviewed before delivery, not a list
    # generated from whatever tools happen to exist on the user's computer.
    if sys.version_info < (3, 10) or platform.system() != "Darwin":
        raise ValueError("full-run Python 3.10+ on Darwin required")
    if admission["platform"] != [platform.system(), platform.machine()]:
        raise ValueError("reviewed platform mismatch")
    if admission["base"] != BASE:
        raise ValueError("base mismatch")
    pins = json.loads((package / "payload/pins.json").read_text())
    for rel, expected in pins.items():
        if digest(package / rel) != expected:
            raise ValueError("package changed")
    for path, pin in admission["tools"].items():
        canonical = Path(path).resolve(strict=True)
        if str(canonical) != path or digest(canonical) != pin:
            raise ValueError("runtime observation differs from review")
    if str(Path(sys.executable).resolve()) != admission["python"]:
        raise ValueError("selected Python mismatch")
    git = admission["git"]
    selection = admission["git_selection"]
    selected_paths = selection["paths"]
    if (
        selection["status"] != "BOUND"
        or selected_paths["shim"] != "/usr/bin/git"
        or selected_paths["resolver"] != "/usr/bin/xcrun"
        or selected_paths["actual"] != git
        or selected_paths["alias_target"] != git
        or str(Path(selected_paths["alias"]).resolve(strict=True)) != git
        or selected_paths["shim_exec"] != selected_paths["actual_exec"]
        or any(
            admission["tools"].get(path) != pin
            for path, pin in selection["hashes"].items()
        )
    ):
        raise ValueError("native Git selection binding changed")
    node, npm, ruff, lefthook = [
        admission[key] for key in ("node", "npm", "ruff", "lefthook")
    ]
    env = dict(admission["environment"])
    if env.get("CI") != "1" or env.get("CREDIT_TEST_LEFTHOOK") != lefthook:
        raise ValueError("full-scope environment mismatch")
    if any(k.startswith(("GIT_", "PYTHON", "LEFTHOOK")) for k in env):
        raise ValueError("environment override")
    for path in (git, node, npm, ruff, lefthook, admission["python"]):
        if path not in admission["tools"]:
            raise ValueError("unbound runtime path")
    for path, info in admission["browsers"].items():
        if digest(path) != info["sha256"]:
            raise ValueError("browser changed")
    # npm ci and lock-local Playwright browser preparation below are explicit
    # approved setup effects. No hidden tool/system dependency installation.
    parent = Path(args.output_parent).resolve(strict=True)
    import tempfile

    evidence = Path(tempfile.mkdtemp(prefix="tetrisjs-fullrun-", dir=parent))
    os.chmod(evidence, 0o700)
    # Outer evidence/root0700; ordinary source checkout must retain exact Git
    # 0644/0755 inventory, so use deliberate022 for isolated child/source work.
    os.umask(0o022)
    status = {
        "status": "INCOMPLETE",
        "qualification": False,
        "base": BASE,
        "source_platform_delta": True,
        "effects": "tests-only isolated checkout; npm ci network dependencies",
        "commands": [],
    }
    lifetime.save(evidence / "result.json", status)
    checkout = evidence / "checkout"
    logs = evidence / "commands"
    logs.mkdir(mode=0o700)
    setup_root = Path(args.admission).resolve().parent
    for name in ("setup.json", "runtime-admission.json"):
        shutil.copyfile(setup_root / name, evidence / name)
        (evidence / name).chmod(0o600)
    shutil.copyfile(
        package / "payload/pins.json", evidence / "package-source-pins.json"
    )
    lifetime.save(
        evidence / "fullrun-identity.json",
        {
            "run_source_sha256": digest(__file__),
            "lifetime_sha256": digest(package / "lifetime.py"),
            "base": BASE,
            "admission_sha256": digest(args.admission),
        },
    )

    # Generous chosen allowances: ordinary commands30min, full browser2hours,
    # overall6hours. These exceed old600s per-command choice; no shortened suite.
    # Keep original command/test allowances. Only host time remaining limits
    # this run, reserving fifteen minutes for cleanup, evidence and transport.
    host_remaining = admission["host_deadline_unix"] - time.time() - 15 * 60
    if host_remaining <= 0:
        raise TimeoutError("host envelope exhausted before qualification")
    overall_deadline = time.monotonic() + min(6 * 60 * 60, host_remaining)

    def command(label, argv):
        remaining = overall_deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("overall allowance expired")
        allowance = min(
            2 * 60 * 60 if label.endswith("test:e2e") else 30 * 60, remaining
        )
        status["current_command"] = {
            "label": label,
            "argv": argv,
            "status": "INCOMPLETE",
        }
        lifetime.save(evidence / "result.json", status)
        result, error = lifetime.run(
            argv,
            checkout if checkout.exists() else evidence,
            env,
            logs,
            label,
            allowance,
        )
        status["commands"].append(result)
        status["current_command"] = result
        lifetime.save(evidence / "result.json", status)
        if error is not None:
            raise error
        return result

    handlers = {}

    def interrupted(signum, frame):
        status["signal"] = signum
        raise lifetime.InterruptedRun("full run interrupted")

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        handlers[sig] = signal.signal(sig, interrupted)
    try:
        command("prereq-git-version", [git, "--version"])
        command(
            "prereq-python-yaml",
            [
                admission["python"],
                "-c",
                "import sys,yaml; assert sys.version_info[:3] == (3,13,18); assert yaml.__version__ == '6.0.3'; print(sys.version); print(yaml.__version__)",
            ],
        )
        command(
            "prereq-node-version",
            [
                node,
                "-e",
                "if(process.version !== 'v26.13.0') process.exit(1); console.log(process.version)",
            ],
        )
        command("prereq-npm-version", [npm, "--version"])
        command("prereq-ruff-version", [ruff, "--version"])
        command("prereq-lefthook-version", [lefthook, "version"])
        command("00-git-init", [git, "init", "-q", str(checkout)])
        command(
            "01-local-fetch",
            [
                git,
                "-C",
                str(checkout),
                "fetch",
                "--no-tags",
                str(package / "payload/base.bundle"),
                "refs/heads/admitted-base",
            ],
        )
        command("02-checkout", [git, "-C", str(checkout), "checkout", "--detach", BASE])
        if file_map(checkout, {".git"}) != json.loads(
            (package / "payload/expected-base.json").read_text()
        ):
            raise ValueError("clean base inventory mismatch")
        command("03-npm-ci", [npm, "ci"])
        # Supported lock-local browser CLI, private path, all required engines.
        # No npx/latest fallback, no OS/system dependency installation.
        if admission.get("browser_install"):
            command(
                "03b-browser-install",
                [
                    node,
                    "node_modules/playwright/cli.js",
                    "install",
                    "chromium",
                    "firefox",
                    "webkit",
                ],
            )
            lifetime.save(
                evidence / "browser-setup-manifest.json",
                browser_map(Path(env["PLAYWRIGHT_BROWSERS_PATH"])),
            )

        command("04-clean-base-build", [npm, "run", "build"])
        inventory = json.loads((checkout / ".release-evidence/inputs.json").read_text())
        if inventory["sourceRevision"] != BASE:
            raise ValueError("build revision mismatch")
        for name, pin in inventory["files"].items():
            if digest(checkout / "public" / name) != pin:
                raise ValueError("build inputs changed")
        for path in sorted((package / "overlay").rglob("*")):
            if path.is_file():
                dest = checkout / path.relative_to(package / "overlay")
                dest.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, dest)
                dest.chmod(0o644)
        expected_source = json.loads(
            (package / "payload/expected-candidate.json").read_text()
        )

        def integrity():
            source = file_map(checkout, EXCLUDE)
            if source != expected_source:
                raise ValueError("complete source inventory mismatch")
            return {
                "source": source,
                "lock": digest(checkout / "package-lock.json"),
                "dist": file_map(checkout / "dist"),
                "release_evidence": file_map(checkout / ".release-evidence"),
            }

        initial = integrity()
        if not initial["dist"] or not initial["release_evidence"]:
            raise ValueError("missing release output")
        lifetime.save(evidence / "initial-integrity.json", initial)
        checks = [
            (
                "05-hook-integration",
                [admission["python"], ".credit-guard/test_prepush_admission.py"],
            ),
            (
                "06-ruff",
                [
                    ruff,
                    "check",
                    "--config",
                    str(package / "ruff-source.toml"),
                    ".credit-guard/install_local.py",
                    ".credit-guard/prepush_admission.py",
                    ".credit-guard/test_prepush_admission.py",
                ],
            ),
            (
                "07-ruff-format",
                [
                    ruff,
                    "format",
                    "--config",
                    str(package / "ruff-source.toml"),
                    "--check",
                    ".credit-guard/install_local.py",
                    ".credit-guard/prepush_admission.py",
                    ".credit-guard/test_prepush_admission.py",
                ],
            ),
        ]
        checks += [
            (str(n) + "-" + script, [npm, "run", script])
            for n, script in enumerate(
                (
                    "lint",
                    "format:check",
                    "typecheck",
                    "typecheck:tests",
                    "test",
                    "test:delivery:unit",
                    "test:e2e",
                ),
                8,
            )
        ]
        for label, argv in checks:
            command(label, argv)
        final = integrity()
        lifetime.save(evidence / "final-integrity.json", final)
        if final != initial:
            raise ValueError("final source/output changed")
        final_browsers = browser_map(Path(env["PLAYWRIGHT_BROWSERS_PATH"]))
        lifetime.save(evidence / "final-browser-manifest.json", final_browsers)
        if final_browsers != json.loads(
            (evidence / "browser-setup-manifest.json").read_text()
        ):
            raise ValueError("browser files changed during checks")
        if time.monotonic() >= overall_deadline:
            raise TimeoutError("overall allowance expired before completion")
        status["qualification"] = True
        status["status"] = "COMPLETE"
    except BaseException as exc:
        status["error_class"] = type(exc).__name__
        raise
    finally:
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        archive = evidence.with_suffix(".evidence.tar.gz")
        partial = evidence.with_suffix(".evidence.INCOMPLETE.tar.gz")
        try:
            lifetime.save(evidence / "result.json", status)
            # Preserve coverage/reports/browser artifacts, not dependency tree.
            fd = os.open(partial, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "wb") as output:
                with tarfile.open(fileobj=output, mode="w:gz") as target:
                    for name in (
                        "result.json",
                        "setup.json",
                        "runtime-admission.json",
                        "package-source-pins.json",
                        "fullrun-identity.json",
                        "initial-integrity.json",
                        "final-integrity.json",
                        "browser-setup-manifest.json",
                        "final-browser-manifest.json",
                        "commands",
                    ):
                        path = evidence / name
                        if path.exists():
                            target.add(path, arcname=name)
                    if (setup_root / "setup-commands").exists():
                        target.add(
                            setup_root / "setup-commands", arcname="setup-commands"
                        )
                    for name in (
                        "coverage",
                        "reports",
                        "test-results",
                        "playwright-report",
                        ".release-evidence",
                    ):
                        path = checkout / name
                        if path.exists():
                            target.add(path, arcname="test-artifacts/" + name)
                output.flush()
                os.fsync(output.fileno())
            os.rename(partial, archive)
            print("Evidence archive: " + str(archive), flush=True)
        except BaseException as exc:
            status["archive_error_class"] = type(exc).__name__
            status["status"] = "INCOMPLETE"
            status["qualification"] = False
            try:
                lifetime.save(evidence / "result.json", status)
            except BaseException:
                pass  # Disk failure may preserve only initial INCOMPLETE receipt.
            print(
                "Evidence archive incomplete. Keep private result directory.",
                flush=True,
            )
        finally:
            for sig, prior in handlers.items():
                signal.signal(sig, prior)
        print("Status: " + status["status"], flush=True)
    return 0 if status["qualification"] and status["status"] == "COMPLETE" else 1


if __name__ == "__main__":
    raise SystemExit(main())
