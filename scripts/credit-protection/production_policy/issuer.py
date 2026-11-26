import hashlib
import json
import subprocess
from dataclasses import dataclass

from baseline import httpapi

from . import policy


class Refusal(Exception):
    pass


class LocalGitSource:
    pass

    def __init__(self, repo_dir, deadline=None):
        self.repo_dir = repo_dir
        self.deadline = deadline

    def commit_bytes(self, sha):

        timeout = (
            30 if self.deadline is None else min(30, self.deadline.total_remaining())
        )
        raw = subprocess.run(
            ["/usr/bin/git", "-C", self.repo_dir, "cat-file", "commit", sha],
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(self.repo_dir),
                "LC_ALL": "C.UTF-8",
                "GIT_CONFIG_NOSYSTEM": "1",
                "GIT_CONFIG_SYSTEM": "/dev/null",
                "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_NO_REPLACE_OBJECTS": "1",
            },
            capture_output=True,
            check=True,
            timeout=timeout,
        ).stdout
        recomputed = hashlib.sha1(b"commit %d\0" % len(raw) + raw).hexdigest()
        if recomputed != sha:
            raise Refusal(
                f"raw-id mismatch: walked {sha[:12]} but content "
                f"hashes to {recomputed[:12]}"
            )
        return raw


class RestSource:
    pass

    def __init__(self, owner, repo, token=None, client=None):
        self.base = f"https://api.github.com/repos/{owner}/{repo}/git/commits"
        self.token = token
        self.client = client

    def commit_json(self, sha):
        rq = (
            self.client.request_json
            if self.client is not None
            else httpapi.request_json
        )
        return rq(f"{self.base}/{sha}", token=self.token)


def parse_commit(raw):
    pass
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise Refusal("commit is not UTF-8") from None
    head, sep, message = text.partition("\n\n")
    if not sep:
        raise Refusal("no header/message separator")
    entries = []
    for line in head.split("\n"):
        if line.startswith(" "):
            raise Refusal("header continuation (signature/wrapped header)")
        key, sp, value = line.partition(" ")
        if not sp:
            raise Refusal("malformed header line")
        entries.append((key, value))
    keys = [k for k, _ in entries]

    expect = 0
    for key in keys:
        while expect < len(policy.HEADER_ORDER) and policy.HEADER_ORDER[expect] != key:
            expect += 1
        if expect == len(policy.HEADER_ORDER):
            raise Refusal(f"unexpected or misordered header {key!r}")
        if key != "parent":
            expect += 1
    for needed in ("tree", "author", "committer"):
        if keys.count(needed) != 1:
            raise Refusal(f"missing or duplicated {needed} header")
    parents = [v for k, v in entries if k == "parent"]
    if policy.MAX_PARENTS is not None and len(parents) > policy.MAX_PARENTS:
        raise Refusal("parent count exceeds policy bound")
    for k, v in entries:
        if k in ("tree", "parent"):
            if len(v.split()) != 1 or not policy.OID_RE.match(v):
                raise Refusal(f"{k} value is not exactly one 40-hex id")
    ident = {}
    for k, v in entries:
        if k in ("author", "committer"):
            m = policy.IDENT_LINE_RE.match(v)
            if not m:
                raise Refusal(f"malformed {k} line")
            ident[k] = (m.group(1), m.group(2))
    return {
        "parents": parents,
        "author": ident["author"],
        "committer": ident["committer"],
        "message": message,
    }


def admit(source, head_sha):
    pass

    order, stack, seen = [], [head_sha], set()
    while stack:
        sha = stack.pop()
        if sha in seen:
            continue
        if len(seen) >= policy.MAX_COMMITS:
            raise Refusal("full-history commit count cap")
        if not policy.OID_RE.fullmatch(sha):
            raise Refusal("ancestry contains invalid object id")
        seen.add(sha)
        if isinstance(source, LocalGitSource):
            c = parse_commit(source.commit_bytes(sha))
        else:
            j = source.commit_json(sha)
            parents = [p["sha"] for p in j["parents"]]
            if policy.MAX_PARENTS is not None and len(parents) > policy.MAX_PARENTS:
                raise Refusal("parent count exceeds policy bound")
            c = {
                "parents": parents,
                "author": (j["author"]["name"], j["author"]["email"]),
                "committer": (j["committer"]["name"], j["committer"]["email"]),
                "message": j["message"],
            }
        for role in ("author", "committer"):
            if c[role] != policy.REQUIRED_IDENT:
                raise Refusal(
                    f"{sha[:12]}: {role} is {c[role]!r}, required "
                    f"{policy.REQUIRED_IDENT!r}"
                )
        try:
            policy.check_message(c["message"])
        except ValueError as e:
            raise Refusal(f"{sha[:12]}: {e}") from None
        order.append(sha)
        stack.extend(c["parents"])
    return order


def require_predecessor(ancestry, approved_old):
    pass

    if approved_old != "0" * 40 and approved_old not in set(ancestry):
        raise Refusal("candidate does not contain the approved predecessor")


_RECEIPT_SEAL = object()


@dataclass(frozen=True)
class AdmissionReceipt:
    repo_id: int
    head_sha: str
    ancestry: tuple
    epoch: int
    policy_sha256: str
    release_source_sha256: str
    seal: object

    def __post_init__(self):
        if self.seal is not _RECEIPT_SEAL:
            raise TypeError("AdmissionReceipt can only be created by issue()")

    @property
    def ancestry_digest(self):
        return hashlib.sha256("\n".join(self.ancestry).encode()).hexdigest()

    def payload(self):
        return {
            "title": "credit admission",
            "summary": json.dumps(
                {
                    "repo_id": self.repo_id,
                    "head_sha": self.head_sha,
                    "ancestry_sha256": self.ancestry_digest,
                    "policy_sha256": self.policy_sha256,
                    "release_source_sha256": self.release_source_sha256,
                    "release": policy.ISSUER_VERSION,
                    "epoch": self.epoch,
                },
                indent=2,
            ),
        }

    def revalidate(self):
        pass

        if self.epoch != policy.EPOCH:
            raise Refusal(
                f"receipt epoch {self.epoch} is not current policy epoch {policy.EPOCH}"
            )
        if not self.ancestry or self.ancestry[0] != self.head_sha:
            raise Refusal("receipt head is not the walk root")
        if not policy.OID_RE.match(self.head_sha) or any(
            not policy.OID_RE.match(s) for s in self.ancestry
        ):
            raise Refusal("receipt contains a non-OID")
        if policy.policy_digest(self.epoch) != self.policy_sha256:
            raise Refusal("policy changed since admission; re-admit")
        if policy.source_digest() != self.release_source_sha256:
            raise Refusal("release source changed since admission; re-admit")


def issue(source, head_sha, repo_id, approved_old, epoch=policy.EPOCH):
    pass

    if epoch != policy.EPOCH:
        raise Refusal(
            f"approval epoch {epoch} is not the current policy epoch {policy.EPOCH}"
        )
    ancestry = admit(source, head_sha)
    require_predecessor(ancestry, approved_old)
    return AdmissionReceipt(
        repo_id,
        head_sha,
        tuple(ancestry),
        epoch,
        policy.policy_digest(epoch),
        policy.source_digest(),
        _RECEIPT_SEAL,
    )


def _b64u(b):
    import base64

    return base64.urlsafe_b64encode(b).rstrip(b"=")


def _run_bounded(cmd, data, timeout):
    pass

    import os
    import signal

    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        start_new_session=True,
    )
    try:
        out, _err = proc.communicate(input=data, timeout=timeout)
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.communicate()
        raise
    if proc.returncode != 0:
        raise subprocess.CalledProcessError(proc.returncode, cmd)
    return out


def publish_check(client, token, owner, repo, receipt, app_id=None):
    pass

    if not isinstance(receipt, AdmissionReceipt):
        raise TypeError("publish_check requires a sealed AdmissionReceipt")
    receipt.revalidate()
    want_name = policy.context_name(receipt.epoch)
    r = client.request_json(
        f"https://api.github.com/repos/{owner}/{repo}/check-runs",
        method="POST",
        token=token,
        body={
            "name": want_name,
            "head_sha": receipt.head_sha,
            "status": "completed",
            "conclusion": "success",
            "output": receipt.payload(),
        },
    )
    if (
        r.get("head_sha") != receipt.head_sha
        or r.get("name") != want_name
        or r.get("status") != "completed"
        or r.get("conclusion") != "success"
        or "id" not in r
    ):
        raise Refusal(
            "check-runs response does not match the issued check "
            "(id/head/name/status/conclusion)"
        )
    if app_id is not None and r.get("app", {}).get("id") != app_id:
        raise Refusal(
            "check-runs response names a different App than the approved manifest"
        )
    return r["id"]
