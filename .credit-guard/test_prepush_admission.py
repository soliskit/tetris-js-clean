"""Exercise actual generated hooks in disposable local repositories."""

import hashlib
import importlib.util
import json
import os
import platform
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location(
    "credit_installer", ROOT / "install_local.py"
)
installer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(installer)
BINARY = Path(os.environ["CREDIT_TEST_LEFTHOOK"])


OLD_INSTALLER = '"""Local isolated-checkout installer candidate. No remote effects."""\n\nimport hashlib\nimport json\nimport os\nimport shutil\nimport subprocess\nimport tempfile\nfrom pathlib import Path\n\nimport yaml\n\nFILES = ("strict_guard.py", "publication_gate.py", "denied.json", "hook_entry.py")\nSOURCE_PINS = {\n    "strict_guard.py": "5a48c2a4ab0afacd7ff4fd7a7d722ed30a5d794e42f014ef0ee7ba3c0851e5db",\n    "publication_gate.py": "d5c779c572a54dfe5f4ce71c47413d29fe46cc9c0acc2709a60d145722fcf68b",\n    "denied.json": "a0ebdc174a661c2b456f669d99155b398c3ce71fa355819d978c65e3fa83cd0c",\n    "hook_entry.py": "2be14befd655581f2f1c8d864c2d10d6633385b0d28c74d1f1a68739c6b42316",\n}\nLEFTHOOK_SHA256 = "0054adbcfc3fea33fb741003f02ee41023c7e2719362835888a3e84d58c75361"\nRUN = \'python3 "$(git rev-parse --git-path credit-guard/entry.py)" \'\nHOOKS = {\n    "commit-msg": {"credit-message": {"run": RUN + "commit-msg {1}"}},\n    "pre-push": {"credit-objects": {"use_stdin": True, "run": RUN + "pre-push"}},\n}\n\n\nclass InstallFailed(ValueError):\n    pass\n\n\ndef require(condition, reason):\n    if not condition:\n        raise InstallFailed(reason)\n\n\ndef prepare_config(path):\n    """Add commands, preserving original bytes/comments and all existing keys."""\n    before = path.read_bytes()\n    config = yaml.safe_load(before)\n    require(isinstance(config, dict), "mapping configuration required")\n    require(\n        not any(h in config for h in HOOKS),\n        "existing metadata hooks need review, not overwrite",\n    )\n    addition = yaml.safe_dump(\n        {h: {"commands": commands} for h, commands in HOOKS.items()}, sort_keys=False\n    ).encode()\n    addition = addition.replace(\n        b\'run: python3 "$(git rev-parse --git-path credit-guard/entry.py)" commit-msg\\n\',\n        b\'run:\\n        python3 "$(git rev-parse --git-path credit-guard/entry.py)" commit-msg\\n\',\n    )\n    path.write_bytes(\n        before\n        + b"\\n# Exact commit metadata checks, alongside existing checks.\\n"\n        + addition\n    )\n    return hashlib.sha256(before).hexdigest()\n\n\ndef install(repo, source, lefthook):\n    repo, source = Path(repo).resolve(), Path(source).resolve()\n    binary = Path(lefthook).resolve()\n    require(\n        binary.is_file() and os.access(binary, os.X_OK),\n        "existing Lefthook executable required",\n    )\n\n    def git(*args):\n        return (\n            subprocess.check_output(\n                ["git", "-C", str(repo), *args], stderr=subprocess.PIPE\n            )\n            .decode()\n            .strip()\n        )\n\n    require(\n        hashlib.sha256(binary.read_bytes()).hexdigest() == LEFTHOOK_SHA256,\n        "reviewed Lefthook binary mismatch",\n    )\n    for name, expected in SOURCE_PINS.items():\n        require(\n            hashlib.sha256((source / name).read_bytes()).hexdigest() == expected,\n            "reviewed guard source mismatch: " + name,\n        )\n    custom = subprocess.run(\n        ["git", "-C", str(repo), "config", "--get", "core.hooksPath"],\n        capture_output=True,\n        check=False,\n    )\n    require(\n        custom.returncode == 1, "custom hooksPath or config error, no automatic reset"\n    )\n    config_path = repo / "lefthook.yml"\n    before = config_path.read_bytes()\n    config = yaml.safe_load(before)\n    for hook, commands in HOOKS.items():\n        for name, expected in commands.items():\n            require(\n                config.get(hook, {}).get("commands", {}).get(name) == expected,\n                "reviewed metadata configuration missing/changed",\n            )\n    gitdir = Path(git("rev-parse", "--absolute-git-dir"))\n    target = gitdir / "credit-guard"\n    require(\n        not target.exists(),\n        "installed guard already exists, revision needs explicit review",\n    )\n    for hook in ("pre-commit", *HOOKS):\n        path = gitdir / "hooks" / hook\n        require(\n            not path.exists() or b"lefthook" in path.read_bytes(),\n            "existing non-Lefthook hook, do not replace",\n        )\n    pins = {}\n    with tempfile.TemporaryDirectory(prefix="credit-guard-stage-", dir=gitdir) as stage:\n        stage = Path(stage)\n        for name in FILES:\n            raw = (source / name).read_bytes()\n            pins[name] = hashlib.sha256(raw).hexdigest()\n            (stage / name).write_bytes(raw)\n        launcher = (\n            "import hashlib, pathlib, runpy, sys\\nroot=pathlib.Path(__file__).resolve().parent\\npins="\n            + repr(pins)\n            + \'\\nfor name, expected in pins.items():\\n    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=expected:\\n        raise SystemExit("CREDIT HOOK FAILED CLOSED: installed guard changed: "+name)\\nsys.path.insert(0,str(root))\\nrunpy.run_path(str(root/"hook_entry.py"),run_name="__main__")\\n\'\n        )\n        (stage / "entry.py").write_text(launcher)\n        shutil.copytree(stage, target)\n    subprocess.run([str(binary), "validate"], cwd=repo, check=True, timeout=30)\n    subprocess.run([str(binary), "install"], cwd=repo, check=True, timeout=30)\n    require(config_path.read_bytes() == before, "Lefthook unexpectedly changed config")\n    for hook in config:\n        if hook in {"pre-commit", "commit-msg", "pre-push"}:\n            path = gitdir / "hooks" / hook\n            require(\n                path.is_file()\n                and os.access(path, os.X_OK)\n                and b"lefthook" in path.read_bytes(),\n                "actual installed hook missing/nonexecutable",\n            )\n    receipt = {\n        "pins": pins,\n        "launcher_sha256": hashlib.sha256(\n            (target / "entry.py").read_bytes()\n        ).hexdigest(),\n        "config_sha256": hashlib.sha256(before).hexdigest(),\n        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),\n    }\n    (target / "install-receipt.json").write_text(json.dumps(receipt, indent=2) + "\\n")\n    return receipt\n'


# Explicit Mac historical-layout adaptations, not historical deployed source.
MAC_OLD_INSTALLER_ARM64 = '"""Local isolated-checkout installer candidate. No remote effects."""\n\nimport hashlib\nimport json\nimport os\nimport shutil\nimport subprocess\nimport tempfile\nfrom pathlib import Path\n\nimport yaml\n\nFILES = ("strict_guard.py", "publication_gate.py", "denied.json", "hook_entry.py")\nSOURCE_PINS = {\n    "strict_guard.py": "5a48c2a4ab0afacd7ff4fd7a7d722ed30a5d794e42f014ef0ee7ba3c0851e5db",\n    "publication_gate.py": "d5c779c572a54dfe5f4ce71c47413d29fe46cc9c0acc2709a60d145722fcf68b",\n    "denied.json": "a0ebdc174a661c2b456f669d99155b398c3ce71fa355819d978c65e3fa83cd0c",\n    "hook_entry.py": "2be14befd655581f2f1c8d864c2d10d6633385b0d28c74d1f1a68739c6b42316",\n}\nLEFTHOOK_SHA256 = "4a2bded27339e7b521b72fe123cd343e8bba6b73fe92641f062c2644ca65a534"\nRUN = \'python3 "$(git rev-parse --git-path credit-guard/entry.py)" \'\nHOOKS = {\n    "commit-msg": {"credit-message": {"run": RUN + "commit-msg {1}"}},\n    "pre-push": {"credit-objects": {"use_stdin": True, "run": RUN + "pre-push"}},\n}\n\n\nclass InstallFailed(ValueError):\n    pass\n\n\ndef require(condition, reason):\n    if not condition:\n        raise InstallFailed(reason)\n\n\ndef prepare_config(path):\n    """Add commands, preserving original bytes/comments and all existing keys."""\n    before = path.read_bytes()\n    config = yaml.safe_load(before)\n    require(isinstance(config, dict), "mapping configuration required")\n    require(\n        not any(h in config for h in HOOKS),\n        "existing metadata hooks need review, not overwrite",\n    )\n    addition = yaml.safe_dump(\n        {h: {"commands": commands} for h, commands in HOOKS.items()}, sort_keys=False\n    ).encode()\n    addition = addition.replace(\n        b\'run: python3 "$(git rev-parse --git-path credit-guard/entry.py)" commit-msg\\n\',\n        b\'run:\\n        python3 "$(git rev-parse --git-path credit-guard/entry.py)" commit-msg\\n\',\n    )\n    path.write_bytes(\n        before\n        + b"\\n# Exact commit metadata checks, alongside existing checks.\\n"\n        + addition\n    )\n    return hashlib.sha256(before).hexdigest()\n\n\ndef install(repo, source, lefthook):\n    repo, source = Path(repo).resolve(), Path(source).resolve()\n    binary = Path(lefthook).resolve()\n    require(\n        binary.is_file() and os.access(binary, os.X_OK),\n        "existing Lefthook executable required",\n    )\n\n    def git(*args):\n        return (\n            subprocess.check_output(\n                ["git", "-C", str(repo), *args], stderr=subprocess.PIPE\n            )\n            .decode()\n            .strip()\n        )\n\n    require(\n        hashlib.sha256(binary.read_bytes()).hexdigest() == LEFTHOOK_SHA256,\n        "reviewed Lefthook binary mismatch",\n    )\n    for name, expected in SOURCE_PINS.items():\n        require(\n            hashlib.sha256((source / name).read_bytes()).hexdigest() == expected,\n            "reviewed guard source mismatch: " + name,\n        )\n    custom = subprocess.run(\n        ["git", "-C", str(repo), "config", "--get", "core.hooksPath"],\n        capture_output=True,\n        check=False,\n    )\n    require(\n        custom.returncode == 1, "custom hooksPath or config error, no automatic reset"\n    )\n    config_path = repo / "lefthook.yml"\n    before = config_path.read_bytes()\n    config = yaml.safe_load(before)\n    for hook, commands in HOOKS.items():\n        for name, expected in commands.items():\n            require(\n                config.get(hook, {}).get("commands", {}).get(name) == expected,\n                "reviewed metadata configuration missing/changed",\n            )\n    gitdir = Path(git("rev-parse", "--absolute-git-dir"))\n    target = gitdir / "credit-guard"\n    require(\n        not target.exists(),\n        "installed guard already exists, revision needs explicit review",\n    )\n    for hook in ("pre-commit", *HOOKS):\n        path = gitdir / "hooks" / hook\n        require(\n            not path.exists() or b"lefthook" in path.read_bytes(),\n            "existing non-Lefthook hook, do not replace",\n        )\n    pins = {}\n    with tempfile.TemporaryDirectory(prefix="credit-guard-stage-", dir=gitdir) as stage:\n        stage = Path(stage)\n        for name in FILES:\n            raw = (source / name).read_bytes()\n            pins[name] = hashlib.sha256(raw).hexdigest()\n            (stage / name).write_bytes(raw)\n        launcher = (\n            "import hashlib, pathlib, runpy, sys\\nroot=pathlib.Path(__file__).resolve().parent\\npins="\n            + repr(pins)\n            + \'\\nfor name, expected in pins.items():\\n    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=expected:\\n        raise SystemExit("CREDIT HOOK FAILED CLOSED: installed guard changed: "+name)\\nsys.path.insert(0,str(root))\\nrunpy.run_path(str(root/"hook_entry.py"),run_name="__main__")\\n\'\n        )\n        (stage / "entry.py").write_text(launcher)\n        shutil.copytree(stage, target)\n    subprocess.run([str(binary), "validate"], cwd=repo, check=True, timeout=30)\n    subprocess.run([str(binary), "install"], cwd=repo, check=True, timeout=30)\n    require(config_path.read_bytes() == before, "Lefthook unexpectedly changed config")\n    for hook in config:\n        if hook in {"pre-commit", "commit-msg", "pre-push"}:\n            path = gitdir / "hooks" / hook\n            require(\n                path.is_file()\n                and os.access(path, os.X_OK)\n                and b"lefthook" in path.read_bytes(),\n                "actual installed hook missing/nonexecutable",\n            )\n    receipt = {\n        "pins": pins,\n        "launcher_sha256": hashlib.sha256(\n            (target / "entry.py").read_bytes()\n        ).hexdigest(),\n        "config_sha256": hashlib.sha256(before).hexdigest(),\n        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),\n    }\n    (target / "install-receipt.json").write_text(json.dumps(receipt, indent=2) + "\\n")\n    return receipt\n'
MAC_OLD_INSTALLER_ARM64_SHA256 = (
    "04c8c7483ebba71128f68d25298cc873f720f73f144cdb3d0273674f73e84deb"
)
MAC_OLD_INSTALLER_X86_64 = '"""Local isolated-checkout installer candidate. No remote effects."""\n\nimport hashlib\nimport json\nimport os\nimport shutil\nimport subprocess\nimport tempfile\nfrom pathlib import Path\n\nimport yaml\n\nFILES = ("strict_guard.py", "publication_gate.py", "denied.json", "hook_entry.py")\nSOURCE_PINS = {\n    "strict_guard.py": "5a48c2a4ab0afacd7ff4fd7a7d722ed30a5d794e42f014ef0ee7ba3c0851e5db",\n    "publication_gate.py": "d5c779c572a54dfe5f4ce71c47413d29fe46cc9c0acc2709a60d145722fcf68b",\n    "denied.json": "a0ebdc174a661c2b456f669d99155b398c3ce71fa355819d978c65e3fa83cd0c",\n    "hook_entry.py": "2be14befd655581f2f1c8d864c2d10d6633385b0d28c74d1f1a68739c6b42316",\n}\nLEFTHOOK_SHA256 = "28b19fc1c61ec74a1d40aadab932b8262365407cd86a48329791178c95a0ee35"\nRUN = \'python3 "$(git rev-parse --git-path credit-guard/entry.py)" \'\nHOOKS = {\n    "commit-msg": {"credit-message": {"run": RUN + "commit-msg {1}"}},\n    "pre-push": {"credit-objects": {"use_stdin": True, "run": RUN + "pre-push"}},\n}\n\n\nclass InstallFailed(ValueError):\n    pass\n\n\ndef require(condition, reason):\n    if not condition:\n        raise InstallFailed(reason)\n\n\ndef prepare_config(path):\n    """Add commands, preserving original bytes/comments and all existing keys."""\n    before = path.read_bytes()\n    config = yaml.safe_load(before)\n    require(isinstance(config, dict), "mapping configuration required")\n    require(\n        not any(h in config for h in HOOKS),\n        "existing metadata hooks need review, not overwrite",\n    )\n    addition = yaml.safe_dump(\n        {h: {"commands": commands} for h, commands in HOOKS.items()}, sort_keys=False\n    ).encode()\n    addition = addition.replace(\n        b\'run: python3 "$(git rev-parse --git-path credit-guard/entry.py)" commit-msg\\n\',\n        b\'run:\\n        python3 "$(git rev-parse --git-path credit-guard/entry.py)" commit-msg\\n\',\n    )\n    path.write_bytes(\n        before\n        + b"\\n# Exact commit metadata checks, alongside existing checks.\\n"\n        + addition\n    )\n    return hashlib.sha256(before).hexdigest()\n\n\ndef install(repo, source, lefthook):\n    repo, source = Path(repo).resolve(), Path(source).resolve()\n    binary = Path(lefthook).resolve()\n    require(\n        binary.is_file() and os.access(binary, os.X_OK),\n        "existing Lefthook executable required",\n    )\n\n    def git(*args):\n        return (\n            subprocess.check_output(\n                ["git", "-C", str(repo), *args], stderr=subprocess.PIPE\n            )\n            .decode()\n            .strip()\n        )\n\n    require(\n        hashlib.sha256(binary.read_bytes()).hexdigest() == LEFTHOOK_SHA256,\n        "reviewed Lefthook binary mismatch",\n    )\n    for name, expected in SOURCE_PINS.items():\n        require(\n            hashlib.sha256((source / name).read_bytes()).hexdigest() == expected,\n            "reviewed guard source mismatch: " + name,\n        )\n    custom = subprocess.run(\n        ["git", "-C", str(repo), "config", "--get", "core.hooksPath"],\n        capture_output=True,\n        check=False,\n    )\n    require(\n        custom.returncode == 1, "custom hooksPath or config error, no automatic reset"\n    )\n    config_path = repo / "lefthook.yml"\n    before = config_path.read_bytes()\n    config = yaml.safe_load(before)\n    for hook, commands in HOOKS.items():\n        for name, expected in commands.items():\n            require(\n                config.get(hook, {}).get("commands", {}).get(name) == expected,\n                "reviewed metadata configuration missing/changed",\n            )\n    gitdir = Path(git("rev-parse", "--absolute-git-dir"))\n    target = gitdir / "credit-guard"\n    require(\n        not target.exists(),\n        "installed guard already exists, revision needs explicit review",\n    )\n    for hook in ("pre-commit", *HOOKS):\n        path = gitdir / "hooks" / hook\n        require(\n            not path.exists() or b"lefthook" in path.read_bytes(),\n            "existing non-Lefthook hook, do not replace",\n        )\n    pins = {}\n    with tempfile.TemporaryDirectory(prefix="credit-guard-stage-", dir=gitdir) as stage:\n        stage = Path(stage)\n        for name in FILES:\n            raw = (source / name).read_bytes()\n            pins[name] = hashlib.sha256(raw).hexdigest()\n            (stage / name).write_bytes(raw)\n        launcher = (\n            "import hashlib, pathlib, runpy, sys\\nroot=pathlib.Path(__file__).resolve().parent\\npins="\n            + repr(pins)\n            + \'\\nfor name, expected in pins.items():\\n    if hashlib.sha256((root/name).read_bytes()).hexdigest()!=expected:\\n        raise SystemExit("CREDIT HOOK FAILED CLOSED: installed guard changed: "+name)\\nsys.path.insert(0,str(root))\\nrunpy.run_path(str(root/"hook_entry.py"),run_name="__main__")\\n\'\n        )\n        (stage / "entry.py").write_text(launcher)\n        shutil.copytree(stage, target)\n    subprocess.run([str(binary), "validate"], cwd=repo, check=True, timeout=30)\n    subprocess.run([str(binary), "install"], cwd=repo, check=True, timeout=30)\n    require(config_path.read_bytes() == before, "Lefthook unexpectedly changed config")\n    for hook in config:\n        if hook in {"pre-commit", "commit-msg", "pre-push"}:\n            path = gitdir / "hooks" / hook\n            require(\n                path.is_file()\n                and os.access(path, os.X_OK)\n                and b"lefthook" in path.read_bytes(),\n                "actual installed hook missing/nonexecutable",\n            )\n    receipt = {\n        "pins": pins,\n        "launcher_sha256": hashlib.sha256(\n            (target / "entry.py").read_bytes()\n        ).hexdigest(),\n        "config_sha256": hashlib.sha256(before).hexdigest(),\n        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),\n    }\n    (target / "install-receipt.json").write_text(json.dumps(receipt, indent=2) + "\\n")\n    return receipt\n'
MAC_OLD_INSTALLER_X86_64_SHA256 = (
    "0e49f12212f8d70283f61c347badde1a1edf961bb02fb52db2e6771813df4ace"
)


def old_fixture_for_platform():
    key = (platform.system(), platform.machine())
    if key == ("Linux", "x86_64"):
        return (
            OLD_INSTALLER,
            "8fc50761256bcdcfdc3afad0a58f4129f6f1deb4c8a84745a47bceb55fb0fe9f",
        )
    if key == ("Darwin", "arm64"):
        return MAC_OLD_INSTALLER_ARM64, MAC_OLD_INSTALLER_ARM64_SHA256
    if key == ("Darwin", "x86_64"):
        return MAC_OLD_INSTALLER_X86_64, MAC_OLD_INSTALLER_X86_64_SHA256
    raise ValueError("unreviewed historical-layout fixture platform")


def verify_old_fixture(fixture, expected):
    if hashlib.sha256(fixture.encode()).hexdigest() != expected:
        raise ValueError("platform fixture digest mismatch")


class AdmissionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="credit-admission-test-")
        self.addCleanup(self.tmp.cleanup)
        self.repo = Path(self.tmp.name).resolve(strict=True) / "repo"
        subprocess.run(["git", "init", "-q", str(self.repo)], check=True)
        self.source = self.repo / ".credit-guard"
        shutil.copytree(ROOT, self.source, ignore=shutil.ignore_patterns("__pycache__"))
        self.new_config = (ROOT.parent / "lefthook.yml").read_bytes()
        self.old_config = (
            self.new_config
            + b'pre-push:\n  commands:\n    credit-objects:\n      use_stdin: true\n      run: python3 "$(git rev-parse --git-path credit-guard/entry.py)" pre-push\n'
        )
        (self.repo / "lefthook.yml").write_bytes(self.old_config)
        os.utime(self.repo / "lefthook.yml", (1700000000, 1700000000))
        # Frozen prior installer creates a real admitted old installation.
        self.assertEqual(
            hashlib.sha256(OLD_INSTALLER.encode()).hexdigest(),
            "8fc50761256bcdcfdc3afad0a58f4129f6f1deb4c8a84745a47bceb55fb0fe9f",
        )
        old = {"__name__": "old_fixture_installer"}
        fixture, fixture_sha256 = old_fixture_for_platform()
        verify_old_fixture(fixture, fixture_sha256)
        exec(compile(fixture, "platform_bound_old_installer", "exec"), old)
        old["install"](self.repo, self.source, BINARY)
        self.old_hook = (self.repo / ".git/hooks/pre-push").read_bytes()
        self.old_receipt = (
            self.repo / ".git/credit-guard/install-receipt.json"
        ).read_bytes()
        git = Path(shutil.which("git")).resolve()
        python = Path(sys.executable).resolve()
        tools = [
            ROOT / "install_local.py",
            self.source / "install_local.py",
            self.source / "prepush_admission.py",
            git,
            python,
            BINARY,
        ]
        oldpaths = [
            self.repo / ".git/hooks" / n
            for n in ("pre-commit", "commit-msg", "pre-push")
        ]
        oldpaths += list((self.repo / ".git/credit-guard").iterdir())
        # These expectations are fixture inputs captured BEFORE mutation. Real
        # publication supplies independently reviewed external expectations.
        self.expected = {
            "repo": str(self.repo),
            "git": str(git),
            "python": str(python),
            "source_tools": {
                str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in tools
            },
            "old_pins": {
                str(p): hashlib.sha256(p.read_bytes()).hexdigest() for p in oldpaths
            },
            "old_config": self.old_config.decode(),
            "new_config_sha256": hashlib.sha256(self.new_config).hexdigest(),
        }
        scheduler = self.repo / ".git/info/lefthook.checksum"
        self.expected["old_scheduler_sha256"] = hashlib.sha256(
            scheduler.read_bytes()
        ).hexdigest()
        self.old_scheduler = scheduler.read_bytes()
        # Frozen prior installer uses this exact reviewed binary path in the
        # fixture. The real mismatch case below explicitly changes fallback.
        self.expected["generated_hook_pins"] = {
            name: hashlib.sha256(
                (self.repo / ".git/hooks" / name).read_bytes()
            ).hexdigest()
            for name in ("pre-commit", "commit-msg")
        }
        (self.repo / "lefthook.yml").write_bytes(self.new_config)
        os.utime(self.repo / "lefthook.yml", (1700000100, 1700000100))
        self.assertEqual(int(self.old_scheduler.split()[1]), 1700000000)

    def install(self, checkpoint=None):
        return installer.install(
            self.repo, self.source, BINARY, self.expected, checkpoint
        )

    def invoke(self, data=b"", args=("origin", "local-fixture"), env=None):
        return subprocess.run(
            [str(self.repo / ".git/hooks/pre-push"), *args],
            cwd=self.repo,
            input=data,
            capture_output=True,
            env=env,
            check=False,
            timeout=30,
        )

    def test_empty_candidate_still_runs_audit(self):
        self.install()
        result = self.invoke()
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stdout.count(b"no new commit targets"), 1)
        # No remaining downstream job exists. Remote arguments, including
        # whitespace/metacharacters, cannot select a different audit or shell.
        original = self.invoke(args=("remote with spaces", "local;$fixture"))
        self.assertEqual(original.returncode, 0, original.stderr)
        self.assertEqual(original.stdout, result.stdout)

    def test_malformed_input_rejected(self):
        self.install()
        self.assertNotEqual(self.invoke(b"broken\n").returncode, 0)
        self.assertNotEqual(self.invoke(b"x" * (256 * 1024 + 1)).returncode, 0)

    def test_post_install_config_and_module_tamper(self):
        receipt = self.install()
        config = self.repo / "lefthook.yml"
        original = config.read_bytes()
        config.write_bytes(original + b"\n# changed\n")
        self.assertNotEqual(self.invoke().returncode, 0)
        config.write_bytes(original)
        module = next(
            Path(p)
            for p in receipt["manifest"]["pins"]
            if p.endswith("prepush_admission.py")
        )
        module.unlink()
        module.mkdir()
        self.assertNotEqual(self.invoke().returncode, 0)
        module.rmdir()
        module.symlink_to(self.source / "prepush_admission.py")
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_override_and_receipt_are_not_authority(self):
        receipt = self.install()
        manifest = receipt["manifest"]
        revision = Path(manifest["guard_entry"]).parent.parent
        receiptfile = revision / "install-receipt.json"
        saved = receiptfile.read_bytes()
        receiptfile.write_text(json.dumps({"pins": {}}))
        result = self.invoke()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"receipt changed", result.stderr)
        receiptfile.write_bytes(saved)
        (self.repo / "lefthook-local.yml").write_text("pre-push: {}\n")
        self.assertNotEqual(self.invoke().returncode, 0)
        (self.repo / "lefthook-local.yml").unlink()
        env = dict(os.environ)
        env["LEFTHOOK_EXCLUDE"] = "credit-objects"
        self.assertNotEqual(self.invoke(env=env).returncode, 0)
        subprocess.run(
            ["git", "config", "core.hooksPath", "elsewhere"], cwd=self.repo, check=True
        )
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_crash_commit_boundaries_block(self):
        for boundary in (
            "archive",
            "sentinel",
            "scheduler",
            "dependencies",
            "wrapper",
            "complete",
        ):
            with self.subTest(boundary=boundary):
                # Each fixture is a fresh repository, never an automatic retry
                # of a failed publication operation.
                nested = AdmissionTests("test_empty_candidate_still_runs_audit")
                nested.setUp()
                try:

                    def crash(name, boundary=boundary):
                        if name == boundary:
                            raise RuntimeError("injected crash: " + name)

                    with self.assertRaises(RuntimeError):
                        nested.install(crash)
                    result = nested.invoke()
                    if boundary == "archive":
                        self.assertEqual(
                            (nested.repo / ".git/hooks/pre-push").read_bytes(),
                            nested.old_hook,
                        )
                    elif boundary == "complete":
                        self.assertEqual(result.returncode, 0, result.stderr)
                    else:
                        self.assertNotEqual(result.returncode, 0)
                finally:
                    nested.doCleanups()

    def test_same_tree_candidate_ancestry_is_checked(self):
        self.install()
        env = dict(os.environ)
        env.update(
            {
                "GIT_AUTHOR_NAME": "David Solis",
                "GIT_AUTHOR_EMAIL": "doze.inept.0n@icloud.com",
                "GIT_COMMITTER_NAME": "David Solis",
                "GIT_COMMITTER_EMAIL": "doze.inept.0n@icloud.com",
            }
        )
        tree = subprocess.check_output(
            ["git", "mktree"], cwd=self.repo, input=b""
        ).strip()
        message = b"Check the local hook\n\nWhy: Exercise metadata checks.\n\nHow: Use a local fixture.\n\nTags: Bug Fix\n"
        first = subprocess.check_output(
            ["git", "commit-tree", tree], cwd=self.repo, input=message, env=env
        ).strip()
        second = subprocess.check_output(
            ["git", "commit-tree", tree, "-p", first],
            cwd=self.repo,
            input=message,
            env=env,
        ).strip()
        record = (
            b"refs/heads/fixture "
            + second
            + b" refs/heads/fixture "
            + b"0" * 40
            + b"\n"
        )
        subprocess.run(
            ["git", "update-ref", "refs/heads/fixture", second],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "symbolic-ref", "HEAD", "refs/heads/fixture"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "update-ref", "refs/remotes/origin/fixture", first],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "branch.fixture.remote", "origin"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "branch.fixture.merge", "refs/heads/fixture"],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "remote", "add", "origin", str(self.repo / "local-remote.git")],
            cwd=self.repo,
            check=True,
        )
        subprocess.run(
            ["git", "config", "push.default", "current"], cwd=self.repo, check=True
        )
        self.assertEqual(
            subprocess.check_output(
                ["git", "diff", "HEAD", "@{push}", "--name-only"], cwd=self.repo
            ),
            b"",
        )
        result = self.invoke(record)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b"2 commits inspected", result.stdout)
        existing = self.invoke(record.replace(b"0" * 40, first))
        self.assertEqual(existing.returncode, 0, existing.stdout + existing.stderr)
        self.assertIn(b"2 commits inspected", existing.stdout)
        env["GIT_AUTHOR_NAME"] = "Forbidden fixture"
        bad = subprocess.check_output(
            ["git", "commit-tree", tree, "-p", first],
            cwd=self.repo,
            input=message,
            env=env,
        ).strip()
        badrecord = record.replace(second, bad)
        self.assertNotEqual(self.invoke(badrecord).returncode, 0)
        # A good tip cannot hide forbidden ancestor metadata.
        env["GIT_AUTHOR_NAME"] = "David Solis"
        tip = subprocess.check_output(
            ["git", "commit-tree", tree, "-p", bad],
            cwd=self.repo,
            input=message,
            env=env,
        ).strip()
        self.assertNotEqual(self.invoke(record.replace(second, tip)).returncode, 0)
        env["GIT_COMMITTER_NAME"] = "Forbidden committer"
        badcommitter = subprocess.check_output(
            ["git", "commit-tree", tree], cwd=self.repo, input=message, env=env
        ).strip()
        self.assertNotEqual(
            self.invoke(record.replace(second, badcommitter)).returncode, 0
        )
        env["GIT_COMMITTER_NAME"] = "David Solis"
        forbidden_credit_message = subprocess.check_output(
            ["git", "commit-tree", tree],
            cwd=self.repo,
            input=b"Check the local hook\n\nCo-authored-by: Fixture <fixture@example.invalid>\n",
            env=env,
        ).strip()
        forbidden_result = self.invoke(record.replace(second, forbidden_credit_message))
        self.assertNotEqual(forbidden_result.returncode, 0)
        self.assertIn(
            b"credit marker requires review",
            forbidden_result.stdout + forbidden_result.stderr,
        )

    def test_old_drift_and_archive_lineage(self):
        stable = self.repo / ".git/credit-guard/entry.py"
        before = stable.read_bytes()
        stable.write_bytes(before + b"\n# drift\n")
        with self.assertRaises(installer.InstallFailed):
            self.install()
        stable.write_bytes(before)
        receipt = self.install()
        archive = Path(receipt["manifest"]["guard_entry"]).parent.parent / "previous"
        self.assertEqual((archive / "lefthook.yml").read_bytes(), self.old_config)
        self.assertEqual(
            (archive / "credit-guard/install-receipt.json").read_bytes(),
            self.old_receipt,
        )
        self.assertEqual(
            (archive / "lefthook.checksum").read_bytes(), self.old_scheduler
        )
        for name in ("pre-commit", "commit-msg"):
            pin = self.expected["old_pins"][str(self.repo / ".git/hooks" / name)]
            self.assertEqual(
                hashlib.sha256(
                    (self.repo / ".git/hooks" / name).read_bytes()
                ).hexdigest(),
                pin,
            )
        with self.assertRaises(installer.InstallFailed):
            self.install()

    def test_expected_source_and_prior_config_reject_drift(self):
        path = self.source / "prepush_admission.py"
        before = path.read_bytes()
        path.write_bytes(before + b"\n# changed\n")
        with self.assertRaises(installer.InstallFailed):
            self.install()
        path.write_bytes(before)
        self.expected["old_config"] += "\n# changed\n"
        with self.assertRaises(installer.InstallFailed):
            self.install()

    def test_individual_runtime_tampering(self):
        result = self.install()
        manifest = result["manifest"]
        paths = [
            Path(manifest["guard_entry"]),
            self.repo / ".git/credit-guard/entry.py",
            self.repo / ".git/credit-guard/strict_guard.py",
            Path(manifest["guard_entry"]).parent.parent / "manifest.json",
        ]
        for path in paths:
            with self.subTest(path=str(path)):
                raw = path.read_bytes()
                path.write_bytes(raw + b"\n# mutation\n")
                rejected = self.invoke()
                self.assertNotEqual(rejected.returncode, 0)
                self.assertIn(b"changed", rejected.stderr)
                path.write_bytes(raw)
        module = Path(manifest["guard_entry"]).parent.parent / "prepush_admission.py"
        raw = module.read_bytes()
        module.unlink()
        self.assertNotEqual(self.invoke().returncode, 0)
        module.write_bytes(raw + b"\n# mutation\n")
        self.assertNotEqual(self.invoke().returncode, 0)
        module.write_bytes(raw)
        guard = Path(manifest["guard_entry"]).parent
        moved = guard.with_name("guard-moved")
        guard.rename(moved)
        guard.symlink_to(moved, target_is_directory=True)
        self.assertNotEqual(self.invoke().returncode, 0)
        guard.unlink()
        moved.rename(guard)
        config = self.repo / "lefthook.yml"
        raw = config.read_bytes()
        target = self.repo / "redirected-config"
        target.write_bytes(raw)
        config.unlink()
        config.symlink_to(target)
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_direct_commit_message_retains_per_use_guard_checks(self):
        self.install()
        message = self.repo / "message.txt"
        message.write_text(
            "Check the local hook\n\nWhy: Exercise metadata checks.\n\nHow: Use a local fixture.\n\nTags: Bug Fix\n"
        )
        hook = self.repo / ".git/hooks/commit-msg"
        result = subprocess.run(
            [str(hook), str(message)], cwd=self.repo, capture_output=True, check=False
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        valid = message.read_bytes()
        message.write_text(
            "Check the local hook\n\nCo-authored-by: Fixture <fixture@example.invalid>\n"
        )
        rejected = subprocess.run(
            [str(hook), str(message)], cwd=self.repo, capture_output=True, check=False
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(
            b"credit marker requires review", rejected.stdout + rejected.stderr
        )
        message.write_bytes(valid)
        source = self.repo / ".git/credit-guard/strict_guard.py"
        source.write_bytes(source.read_bytes() + b"\n# drift\n")
        result = subprocess.run(
            [str(hook), str(message)], cwd=self.repo, capture_output=True, check=False
        )
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b"installed guard changed", result.stdout + result.stderr)

    def test_noncanonical_source_refuses_before_mutation(self):
        alias = self.repo / "guard-alias"
        alias.symlink_to(self.source, target_is_directory=True)
        before = {
            str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.repo.rglob("*")
            if p.is_file() and not p.is_symlink()
        }
        with self.assertRaisesRegex(installer.InstallFailed, "noncanonical input"):
            installer.install(self.repo, alias, BINARY, self.expected)
        after = {
            str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.repo.rglob("*")
            if p.is_file() and not p.is_symlink()
        }
        self.assertEqual(before, after)
        self.assertTrue(alias.is_symlink())
        self.assertEqual(list((self.repo / ".git").glob("credit-admission-*")), [])

    def test_unknown_platform_refuses_before_mutation(self):
        before = {
            str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.repo.rglob("*")
            if p.is_file()
        }
        with mock.patch.object(installer.platform, "system", return_value="Unknown"):
            with self.assertRaisesRegex(
                installer.InstallFailed, "unreviewed Lefthook platform"
            ):
                self.install()
        after = {
            str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.repo.rglob("*")
            if p.is_file()
        }
        self.assertEqual(before, after)
        self.assertEqual(list((self.repo / ".git").glob("credit-admission-*")), [])

    def test_wrong_platform_binary_refuses_before_writes(self):
        before = {
            str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.repo.rglob("*")
            if p.is_file()
        }
        with mock.patch.object(installer, "platform_binary_pin", return_value="0" * 64):
            with self.assertRaisesRegex(installer.InstallFailed, "binary mismatch"):
                self.install()
        after = {
            str(p.relative_to(self.repo)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in self.repo.rglob("*")
            if p.is_file()
        }
        self.assertEqual(before, after)

    def test_cross_platform_old_receipt_refuses(self):
        receipt_path = self.repo / ".git/credit-guard/install-receipt.json"
        receipt = json.loads(receipt_path.read_bytes())
        receipt["binary_sha256"] = "0" * 64
        receipt_path.write_text(json.dumps(receipt))
        # Re-admit the fixture's deliberately changed receipt bytes so the
        # semantic binary-binding check, not the outer old-file hash, refuses.
        self.expected["old_pins"][str(receipt_path)] = hashlib.sha256(
            receipt_path.read_bytes()
        ).hexdigest()
        with self.assertRaisesRegex(installer.InstallFailed, "old binary mismatch"):
            self.install()
        self.assertEqual(list((self.repo / ".git").glob("credit-admission-*")), [])

    def test_normal_commit_keeps_generated_hooks_and_push_admission(self):
        # Full real Tetris JS source/dependencies let unchanged typecheck and
        # formatting hooks run. No Git metadata or installed guard is copied.
        for item in ROOT.parent.iterdir():
            if item.name.startswith(".") or item.name == "lefthook.yml":
                continue
            destination = self.repo / item.name
            if item.is_dir():
                shutil.copytree(
                    item,
                    destination,
                    dirs_exist_ok=True,
                    symlinks=item.name == "node_modules",
                )
            elif item.is_file():
                shutil.copyfile(item, destination)
        shutil.copyfile(
            ROOT.parent / ".prettierrc.json", self.repo / ".prettierrc.json"
        )
        # Model different historical installation fallback path with identical
        # executable bytes: independently expected new shims still use BINARY.
        old_path = "/retained/old-runner-location"
        for name in ("pre-commit", "commit-msg"):
            hook = self.repo / ".git/hooks" / name
            hook.write_bytes(
                hook.read_bytes().replace(
                    str(BINARY.resolve()).encode(), old_path.encode()
                )
            )
            self.expected["old_pins"][str(hook)] = hashlib.sha256(
                hook.read_bytes()
            ).hexdigest()
        self.install()
        scheduler = self.repo / ".git/info/lefthook.checksum"
        before_scheduler = scheduler.read_bytes()
        self.assertNotEqual(before_scheduler.split()[0], self.old_scheduler.split()[0])
        self.assertEqual(int(before_scheduler.split()[1]), 1700000100)
        os.utime(self.repo / "lefthook.yml", (1700000200, 1700000200))
        self.assertNotEqual(
            int((self.repo / "lefthook.yml").stat().st_mtime),
            int(before_scheduler.split()[1]),
        )
        before_hooks = {
            n: (self.repo / ".git/hooks" / n).read_bytes()
            for n in ("pre-commit", "commit-msg", "pre-push")
        }
        env = dict(os.environ)
        env.update(
            {
                "GIT_AUTHOR_NAME": "David Solis",
                "GIT_AUTHOR_EMAIL": "doze.inept.0n@icloud.com",
                "GIT_COMMITTER_NAME": "David Solis",
                "GIT_COMMITTER_EMAIL": "doze.inept.0n@icloud.com",
            }
        )
        subprocess.run(
            [
                "git",
                "add",
                "--",
                ".credit-guard/install_local.py",
                ".credit-guard/prepush_admission.py",
                ".credit-guard/test_prepush_admission.py",
                "lefthook.yml",
            ],
            cwd=self.repo,
            check=True,
        )
        message = b"Check the local hook\n\nWhy: Exercise metadata checks.\n\nHow: Use a local fixture.\n\nTags: Bug Fix\n"
        result = subprocess.run(
            ["git", "commit", "--allow-empty", "-F", "-"],
            cwd=self.repo,
            input=message,
            env=env,
            capture_output=True,
            check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn(b"typecheck", result.stdout + result.stderr)
        self.assertIn(b"typecheck:tests", result.stdout + result.stderr)
        self.assertIn(b"prettier", result.stdout + result.stderr)
        self.assertIn(b"python-lint", result.stdout + result.stderr)
        self.assertIn(b"python-format", result.stdout + result.stderr)
        self.assertIn(b"CREDIT MESSAGE PASS", result.stdout + result.stderr)
        self.assertNotIn(b"sync hooks:", result.stdout + result.stderr)
        self.assertEqual(scheduler.read_bytes(), before_scheduler)
        for name, raw in before_hooks.items():
            self.assertEqual((self.repo / ".git/hooks" / name).read_bytes(), raw)
        tip = subprocess.check_output(
            ["git", "rev-parse", "HEAD"], cwd=self.repo
        ).strip()
        self.assertEqual(
            self.invoke(
                b"refs/heads/fixture "
                + tip
                + b" refs/heads/fixture "
                + b"0" * 40
                + b"\n"
            ).returncode,
            0,
        )
        # Exercise Git's actual automatic hook environment and local transport,
        # not only a manually executed hook with synthesized ref records.
        remote = Path(self.tmp.name) / "remote.git"
        subprocess.run(["git", "init", "--bare", "-q", str(remote)], check=True)
        ref = "refs/heads/fixture"
        push = subprocess.run(
            ["git", "push", "--porcelain", str(remote), tip.decode() + ":" + ref],
            cwd=self.repo,
            env=env,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertEqual(push.returncode, 0, push.stdout + push.stderr)
        self.assertIn(b"CREDIT OBJECTS: full ancestry,", push.stdout + push.stderr)
        self.assertIn(b"CREDIT OBJECTS PASS", push.stdout + push.stderr)
        self.assertEqual(
            subprocess.check_output(
                ["git", "--git-dir", str(remote), "rev-parse", ref]
            ).strip(),
            tip,
        )
        self.assertNotIn(b"sync hooks:", push.stdout + push.stderr)
        self.assertEqual(scheduler.read_bytes(), before_scheduler)
        for name, raw in before_hooks.items():
            self.assertEqual((self.repo / ".git/hooks" / name).read_bytes(), raw)
        bad_env = dict(env)
        bad_env["GIT_EXEC_PATH"] = str(Path(self.tmp.name) / "wrong-exec")
        rejected = subprocess.run(
            [
                "git",
                "push",
                "--porcelain",
                str(remote),
                tip.decode() + ":refs/heads/rejected",
            ],
            cwd=self.repo,
            env=bad_env,
            capture_output=True,
            check=False,
            timeout=30,
        )
        self.assertNotEqual(rejected.returncode, 0)
        self.assertIn(
            b"unapproved GIT_EXEC_PATH value", rejected.stdout + rejected.stderr
        )
        absent = subprocess.run(
            [
                "git",
                "--git-dir",
                str(remote),
                "rev-parse",
                "--verify",
                "refs/heads/rejected",
            ],
            capture_output=True,
            check=False,
        )
        self.assertNotEqual(absent.returncode, 0)
        bad_env["GIT_EXEC_PATH_EXTRA"] = "unreviewed"
        self.assertNotEqual(self.invoke(env=bad_env).returncode, 0)
        self.assertTrue((self.repo / ".git/credit-guard/__pycache__").is_dir())
        # Scheduler mutation is independently rejected, not silently adopted.
        scheduler.write_bytes(before_scheduler + b"changed\n")
        self.assertNotEqual(self.invoke().returncode, 0)

    def test_unknown_active_hook_and_old_scheduler_drift_rejected(self):
        unknown = self.repo / ".git/hooks/post-checkout"
        unknown.write_text("#!/bin/sh\nexit 0\n")
        with self.assertRaises(installer.InstallFailed):
            self.install()
        unknown.unlink()
        scheduler = self.repo / ".git/info/lefthook.checksum"
        scheduler.write_bytes(scheduler.read_bytes() + b"changed\n")
        with self.assertRaises(installer.InstallFailed):
            self.install()

    def test_generated_expectations_cannot_select_own_trust(self):
        original = dict(self.expected["generated_hook_pins"])
        cases = [
            {"pre-commit": "0" * 64, "commit-msg": original["commit-msg"]},
            {"pre-commit": original["pre-commit"]},
            original | {"post-checkout": "0" * 64},
        ]
        for pins in cases:
            with self.subTest(pins=pins):
                self.expected["generated_hook_pins"] = pins
                with self.assertRaises(installer.InstallFailed):
                    self.install()
                self.assertFalse((self.repo / ".git/credit-admission-pending").exists())
                self.assertEqual(
                    list((self.repo / ".git").glob("credit-admission-*")), []
                )
        self.expected["generated_hook_pins"] = original


class PlatformBindingTests(unittest.TestCase):
    def test_tampered_fixture_refuses_before_exec(self):
        fixture, pin = old_fixture_for_platform()
        with self.assertRaisesRegex(ValueError, "fixture digest mismatch"):
            verify_old_fixture(fixture + "\n# drift\n", pin)

    def test_unknown_installer_platform_fails_closed(self):
        with mock.patch.object(installer.platform, "system", return_value="Unknown"):
            with self.assertRaises(installer.InstallFailed):
                installer.platform_binary_pin()

    def test_unknown_installer_architecture_fails_closed(self):
        with mock.patch.object(installer.platform, "system", return_value="Darwin"):
            with mock.patch.object(installer.platform, "machine", return_value="other"):
                with self.assertRaises(installer.InstallFailed):
                    installer.platform_binary_pin()

    def test_unknown_fixture_platform_fails_closed(self):
        with mock.patch.object(platform, "system", return_value="Darwin"):
            with mock.patch.object(platform, "machine", return_value="other"):
                with self.assertRaises(ValueError):
                    old_fixture_for_platform()

    def test_closed_fixture_hashes_and_binary_bindings(self):
        cases = (
            ("Linux", "x86_64", OLD_INSTALLER),
            ("Darwin", "arm64", MAC_OLD_INSTALLER_ARM64),
            ("Darwin", "x86_64", MAC_OLD_INSTALLER_X86_64),
        )
        pins = set()
        for system, machine, fixture in cases:
            with self.subTest(system=system, machine=machine):
                with mock.patch.object(platform, "system", return_value=system):
                    with mock.patch.object(platform, "machine", return_value=machine):
                        selected, pin = old_fixture_for_platform()
                        self.assertEqual(selected, fixture)
                        self.assertEqual(
                            hashlib.sha256(selected.encode()).hexdigest(), pin
                        )
                        pins.add(installer.platform_binary_pin())
        self.assertEqual(len(pins), 3)


class BuiltinAliasTests(unittest.TestCase):
    def test_builtin_alias_binding_and_refusals(self):
        spec = importlib.util.spec_from_file_location(
            "alias_admission_fixture", ROOT / "prepush_admission.py"
        )
        m = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(m)
        rows = []
        with tempfile.TemporaryDirectory(prefix="builtin-alias-fixtures-") as td:
            root = Path(td).resolve()
            canonical = root / "canonical-git"
            canonical.write_bytes(b"fixture-git")
            pin = hashlib.sha256(canonical.read_bytes()).hexdigest()
            regular = root / "regular-alias"
            os.link(canonical, regular)
            correct = root / "symlink-alias"
            correct.symlink_to(canonical)
            other = root / "other-target"
            other.write_bytes(canonical.read_bytes())
            wrong = root / "wrong-alias"
            wrong.symlink_to(other)
            parent = root / "real-dir"
            parent.mkdir()
            (parent / "git").symlink_to(canonical)
            linkdir = root / "linked-dir"
            linkdir.symlink_to(parent, target_is_directory=True)
            for name, path, accepted in (
                ("regular-hardlink", regular, True),
                ("canonical-symlink", correct, True),
                ("parent-symlink-to-canonical", linkdir / "git", True),
                ("same-bytes-different-target", wrong, False),
            ):
                try:
                    m.verify_builtin_alias(str(path), str(canonical), pin)
                    ok = True
                except (ValueError, OSError):
                    ok = False
                assert ok == accepted
                rows.append({"case": name, "accepted": ok})
            canonical.write_bytes(b"changed")
            try:
                m.verify_builtin_alias(str(correct), str(canonical), pin)
            except ValueError:
                rows.append({"case": "changed-canonical-content", "accepted": False})
            else:
                raise AssertionError("changed Git accepted")
            canonical.write_bytes(b"fixture-git")
            # Verify old surrounding selector still refuses unknown spelling/wrong exec
            # before the new helper is reached. Only Git's exact builtin alias is eligible.
            manifest = {
                "repo": str(root),
                "git": str(canonical),
                "pins": {str(canonical): pin},
            }
            old = Path.cwd()
            os.chdir(root)
            try:
                for name, inherited, resolved in (
                    ("wrong-exec-value", str(root / "wrong-exec"), str(correct)),
                    ("arbitrary-path-alias", str(parent), str(correct)),
                ):
                    with (
                        mock.patch.dict(
                            os.environ, {"GIT_EXEC_PATH": inherited}, clear=True
                        ),
                        mock.patch.object(
                            m.subprocess,
                            "check_output",
                            return_value=str(parent).encode(),
                        ),
                        mock.patch.object(m.shutil, "which", return_value=resolved),
                        mock.patch.object(m, "verify_builtin_alias") as helper,
                    ):
                        try:
                            m.admit(manifest)
                        except ValueError:
                            pass
                        else:
                            raise AssertionError(
                                "selector unexpectedly admitted override"
                            )
                        helper.assert_not_called()
                        rows.append({"case": name, "accepted": False})
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()
