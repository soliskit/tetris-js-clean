import copy
import hashlib
import json
import os
import shutil
import subprocess
from pathlib import Path

from fresh_bootstrap import read_pinned
from hook_installer import read_owned
from production_entry import TARGETS


class Stop(Exception):
    pass


def sha(data):
    return hashlib.sha256(data).hexdigest()


def commit(packet, expected_digest, verify_original, read_repository, record):
    packet = copy.deepcopy(packet)

    def digest(value):
        return sha(json.dumps(value, sort_keys=True, separators=(",", ":")).encode())

    if digest(packet) != expected_digest:
        raise Stop("commit packet differs")
    if (
        verify_original(packet, expected_digest) is not True
        or digest(packet) != expected_digest
    ):
        raise Stop("original authority does not cover exact commit packet")
    if packet["repo"] not in TARGETS:
        raise Stop("commit target outside replacements")
    repo = read_repository(packet["repo"])
    if repo.get("id") != packet["repo_id"] or repo.get("full_name") != packet["repo"]:
        raise Stop("commit live repository identity differs")
    root = Path(packet["checkout"])
    if not root.is_absolute() or root != root.resolve(strict=True):
        raise Stop("commit checkout custody differs")
    tools = packet["tools"]
    for name in ("git", "python3", "lefthook"):
        if name not in tools:
            raise Stop("missing commit-stage executable custody")
    paths = []
    for _name, tool in tools.items():
        path = Path(tool["path"])
        if str(path.resolve(strict=True)) != str(path):
            raise Stop("commit-stage tool path not canonical")
        if sha(read_pinned(str(path), 64 << 20)) != tool["sha256"]:
            raise Stop("commit-stage executable changed")
        if str(path.parent) not in paths:
            paths.append(str(path.parent))

    env = {
        "PATH": ":".join(paths),
        "HOME": str(root),
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": os.devnull,
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_AUTHOR_NAME": "David Solis",
        "GIT_COMMITTER_NAME": "David Solis",
        "GIT_AUTHOR_EMAIL": "doze.inept.0n@icloud.com",
        "GIT_COMMITTER_EMAIL": "doze.inept.0n@icloud.com",
    }
    for name in ("git", "python3"):
        resolved = shutil.which(name, path=env["PATH"])
        if (
            resolved is None
            or str(Path(resolved).resolve(strict=True)) != tools[name]["path"]
        ):
            raise Stop("genuine hook runtime would select a different tool")
    selected_runner = shutil.which("lefthook", path=env["PATH"])
    if (
        selected_runner is not None
        and str(Path(selected_runner).resolve(strict=True)) != tools["lefthook"]["path"]
    ):
        raise Stop("genuine runner would be shadowed")
    if selected_runner is None:
        fallback = tools["lefthook"]["path"].encode()
        for hook in ("pre-commit", "commit-msg"):
            raw, _ = read_owned(root / ".git/hooks" / hook)
            if fallback not in raw:
                raise Stop("genuine shim does not name admitted runner fallback")
    git = tools["git"]["path"]

    def run(*args):
        value = subprocess.run(
            [git, "-C", str(root), *args], env=env, capture_output=True, timeout=120
        )
        if value.returncode:
            raise Stop("ordinary commit inspection or genuine hook failed")
        return value.stdout

    if run("rev-parse", "HEAD").decode().strip() != packet["old_head"]:
        raise Stop("commit predecessor changed")
    if run("write-tree").decode().strip() != packet["tree"]:
        raise Stop("staged tree differs from approved candidate")
    config = run("config", "--local", "--includes", "--list").decode()
    for line in config.splitlines():
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
                "core.fsmonitor",
            )
        ):
            raise Stop("commit redirecting config requires review")

    for path, pin in packet["hook_files"].items():
        raw, _ = read_owned(path, 64 << 20)
        if sha(raw) != pin:
            raise Stop("genuine hook/config/scheduler changed")
    required = [
        root / ".git/hooks/pre-commit",
        root / ".git/hooks/commit-msg",
        root / ".git/hooks/pre-push",
        root / "lefthook.yml",
        root / ".git/info/lefthook.checksum",
    ]
    if any(str(path) not in packet["hook_files"] for path in required):
        raise Stop("incomplete genuine commit hook custody")

    receipt = packet["fresh_hook_receipt"]
    if (
        receipt["checkout"] != str(root)
        or receipt["repo"] != packet["repo"]
        or receipt["repo_id"] != packet["repo_id"]
    ):
        raise Stop("fresh hook receipt binding differs")
    allowed_hook_files = set(receipt["created_files"]) | {str(root / "lefthook.yml")}
    if set(packet["hook_files"]) != allowed_hook_files:
        raise Stop("commit hook custody is not the complete genuine installation")
    for path, pin in receipt["created_files"].items():
        if packet["hook_files"].get(path) != pin:
            raise Stop("commit hook receipt differs")
    if packet["hook_files"][str(root / "lefthook.yml")] != receipt["config_sha256"]:
        raise Stop("commit project config differs from genuine bootstrap")
    manifest_path = receipt["manifest"]
    if manifest_path not in receipt["created_files"]:
        raise Stop("genuine manifest not in reviewed receipt")
    manifest_raw, _ = read_owned(manifest_path)
    manifest = json.loads(manifest_raw)
    if (
        manifest["repo"] != str(root)
        or manifest["git"] != tools["git"]["path"]
        or manifest["python"] != tools["python3"]["path"]
    ):
        raise Stop("commit and genuine audit runtime bindings differ")
    for path, pin in manifest["pins"].items():
        if sha(read_pinned(path, 64 << 20)) != pin:
            raise Stop("complete genuine dependency custody differs")
    if os.path.lexists(manifest["pending"]):
        raise Stop("genuine hook installation still pending")
    from production_policy import policy
    from project_bootstrap.publication_gate import full_message

    message = packet["message"].encode("utf-8")
    if not message.endswith(b"\n"):
        raise Stop("review exact final commit message including trailing newline")
    policy.check_message(packet["message"])
    full_message(message)

    runner = tools["lefthook"]["path"]
    value = subprocess.run(
        [runner, "-h"], cwd=root, env=env, capture_output=True, timeout=10
    )
    if value.returncode:
        raise Stop("genuine runner unavailable, do not enter fail-open shim")
    record(
        "ordinary_commit_pending",
        {
            "packet_sha256": expected_digest,
            "repo": packet["repo"],
            "old_head": packet["old_head"],
            "tree": packet["tree"],
        },
    )

    import signal

    process = subprocess.Popen(
        [git, "-C", str(root), "commit", "--cleanup=verbatim", "--file=-"],
        env=env,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        process.communicate(input=message, timeout=120)
    except BaseException:
        try:
            os.killpg(process.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        process.communicate()
        raise Stop(
            "normal commit interrupted, actual state requires reconciliation"
        ) from None
    if process.returncode:
        raise Stop("normal commit or genuine hooks failed, inspect actual state")
    new = run("rev-parse", "HEAD").decode().strip()
    from production_policy import issuer

    admitted = issuer.admit(issuer.LocalGitSource(str(root)), new)
    if packet["old_head"] not in admitted:
        raise Stop("normal commit predecessor not retained")
    if run("rev-parse", new + "^{tree}").decode().strip() != packet["tree"]:
        raise Stop("normal commit changed reviewed tree")
    raw = run("cat-file", "commit", new)
    if raw.partition(b"\n\n")[2] != message:
        raise Stop("actual complete commit message differs, do not publish")
    record(
        "ordinary_commit_confirmed",
        {"packet_sha256": expected_digest, "head": new, "tree": packet["tree"]},
    )
    return {"head": new, "tree": packet["tree"], "publication": "not-performed"}
