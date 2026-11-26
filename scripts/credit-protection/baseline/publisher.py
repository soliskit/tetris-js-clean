import hashlib
import os
import signal
import subprocess

ZERO = "0" * 40


class StopPush(Exception):
    pass


def approved_env(approved_old=None, new_sha=None, remote=None, ref=None):
    pass

    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
        "HOME": os.environ.get("HOME", "/tmp"),
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_SYSTEM": os.devnull,
    }
    if approved_old is not None:
        env.update(
            {
                "APPROVED_OLD": approved_old,
                "APPROVED_NEW": new_sha,
                "EXPECTED_REMOTE_URL": remote,
                "EXPECTED_REF": f"refs/heads/{ref}",
            }
        )
    return env


def _timeout(deadline, cap):
    pass

    if deadline is None:
        return cap
    return min(cap, deadline.total_remaining())


def _git(args, work_repo, env, deadline=None, cap=60):
    pass

    timeout = _timeout(deadline, cap)
    try:
        proc = subprocess.Popen(
            ["git", "-C", work_repo, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            env=env,
            start_new_session=True,
        )
    except OSError as e:
        raise StopPush(f"cannot start git: {type(e).__name__}") from None
    try:
        out, err = proc.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.communicate()
        raise StopPush(
            "git invocation exceeded its deadline; process group killed"
        ) from None
    except BaseException:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        proc.communicate()
        raise
    return proc.returncode, out, err


_REFUSE_LOCAL_CONFIG = (
    "url.",
    "http.",
    "credential.",
    "core.gitproxy",
    "core.sshcommand",
    "core.hookspath",
    "core.fsmonitor",
    "include.",
    "includeif.",
    "protocol.ext.allow",
)
_REFUSE_LOCAL_CONFIG_EXACT_SUFFIX = (".pushurl", ".receivepack")


def _scan_local_config(work_repo, env, deadline):
    pass

    rc, out, _err = _git(
        ["config", "--local", "--includes", "--get-regexp", "."],
        work_repo,
        env,
        deadline,
    )
    if rc not in (0, 1):
        raise StopPush(f"cannot read local config (rc={rc}); refusing")
    for line in out.splitlines():
        key = line.split(None, 1)[0].lower() if line.split() else ""
        if any(key.startswith(bad) for bad in _REFUSE_LOCAL_CONFIG) or any(
            key.endswith(sfx) for sfx in _REFUSE_LOCAL_CONFIG_EXACT_SUFFIX
        ):
            raise StopPush(
                f"local config key {key!r} can redirect the "
                f"transport or hook; refusing to push"
            )


def _git_config(work_repo, key, env, deadline):
    pass

    rc, out, _err = _git(["config", "--get", key], work_repo, env, deadline)
    if rc == 1:
        return None
    if rc != 0:
        raise StopPush(f"git config --get {key} failed (rc={rc})")
    value = out.strip()
    if value == "":
        raise StopPush(f"{key} is set to an empty value; refusing")
    return value


def _verify_effective_hook(
    work_repo, hook_path, env, deadline, approved_hook_sha256=None
):
    pass

    override = _git_config(work_repo, "core.hooksPath", env, deadline)
    if override:
        raise StopPush(
            f"core.hooksPath is set to {override!r}; the "
            f"effective hook is not the reviewed one"
        )
    _scan_local_config(work_repo, env, deadline)

    rc, gd, _err = _git(
        ["rev-parse", "--git-common-dir"], work_repo, env, deadline, cap=30
    )
    if rc != 0 or not gd.strip():
        raise StopPush("cannot resolve the common git dir; refusing")
    gitdir = gd.strip()
    if not os.path.isabs(gitdir):
        gitdir = os.path.join(work_repo, gitdir)
    installed = os.path.join(gitdir, "hooks", "pre-push")
    st = os.lstat(installed) if os.path.lexists(installed) else None
    import stat as _stat

    if st is None or _stat.S_ISLNK(st.st_mode) or not _stat.S_ISREG(st.st_mode):
        raise StopPush(
            "installed pre-push hook missing, not a regular file, or a symlink"
        )
    if not os.access(installed, os.X_OK):
        raise StopPush("installed pre-push hook not executable")

    have = hashlib.sha256(open(installed, "rb").read()).hexdigest()
    want = hashlib.sha256(open(hook_path, "rb").read()).hexdigest()
    if have != want:
        raise StopPush(f"installed hook sha256 {have[:16]} != reviewed {want[:16]}")
    if approved_hook_sha256 is not None and have != approved_hook_sha256:
        raise StopPush(
            "installed hook does not match the manifest-approved hook digest"
        )
    return installed


def _ls_remote(work_repo, remote, ref, env, deadline):
    pass

    rc, out, _err = _git(
        ["ls-remote", remote, f"refs/heads/{ref}"], work_repo, env, deadline
    )
    if rc != 0:
        raise StopPush(f"ls-remote failed (rc={rc})")
    out = out.strip()
    return out.split()[0] if out else None


def wrapper_push(
    work_repo,
    remote,
    ref,
    new_sha,
    approved_old,
    hook_path,
    deadline=None,
    approved_hook_sha256=None,
    interpose=None,
    timeout=120,
):
    pass

    env = approved_env(approved_old, new_sha, remote, ref)

    _verify_effective_hook(work_repo, hook_path, env, deadline, approved_hook_sha256)
    rc, out, _err = _git(
        ["rev-parse", f"refs/heads/{ref}"], work_repo, env, deadline, cap=30
    )
    if rc != 0 or out.strip() != new_sha:
        raise StopPush(
            f"local refs/heads/{ref} is not the approved candidate {new_sha[:12]}"
        )
    if approved_old != ZERO:
        rc, out, _err = _git(
            ["merge-base", "--is-ancestor", approved_old, new_sha],
            work_repo,
            env,
            deadline,
            cap=30,
        )
        if rc != 0:
            raise StopPush(
                f"approved predecessor {approved_old[:12]} is "
                f"not an ancestor of {new_sha[:12]} locally"
            )
    expected = None if approved_old == ZERO else approved_old
    advertised = _ls_remote(work_repo, remote, ref, env, deadline)
    if advertised != expected:
        raise StopPush(
            f"advertised {ref}="
            f"{(advertised or 'absent')[:12]} != approved "
            f"{approved_old[:12]}; re-admission required"
        )
    if interpose is not None:
        interpose()
    rc, out, _err = _git(
        [
            "-c",
            "push.followTags=false",
            "-c",
            "push.mirror=false",
            "push",
            "--no-tags",
            remote,
            f"refs/heads/{ref}:refs/heads/{ref}",
        ],
        work_repo,
        env,
        deadline,
        cap=timeout,
    )
    if rc != 0:
        raise StopPush(f"git push failed: {_err.strip()!r}")
    landed = _ls_remote(work_repo, remote, ref, env, deadline)
    if landed != new_sha:
        raise StopPush(
            f"reconciliation failed: {ref} is "
            f"{(landed or 'absent')[:12]}, expected "
            f"{new_sha[:12]}"
        )
    return {"updated": ref, "head": landed}


def _pkt(data):
    return b"%04x" % (len(data) + 4) + data


def _read_pkts(stream):
    out = []
    while True:
        hdr = stream.read(4)
        if len(hdr) < 4:
            raise StopPush("unexpected EOF from receive-pack")
        n = int(hdr, 16)
        if n == 0:
            return out
        out.append(stream.read(n - 4))


class StrictPush:
    pass

    def __init__(
        self,
        source_repo,
        remote_dir,
        ref,
        hook_path,
        enforce_advertisement=True,
        run_guards=True,
    ):
        self.source_repo = source_repo
        self.ref = ref
        self.hook_path = hook_path
        self.enforce_advertisement = enforce_advertisement
        self.run_guards = run_guards
        self.proc = None

    def _guard_no_delete_and_ff(self, new_sha, approved_old):
        if new_sha == ZERO:
            raise StopPush("ref deletion is never published")
        if approved_old != ZERO:
            r = subprocess.run(
                [
                    "git",
                    "-C",
                    self.source_repo,
                    "merge-base",
                    "--is-ancestor",
                    approved_old,
                    new_sha,
                ]
            )
            if r.returncode != 0:
                raise StopPush(
                    f"not fast-forward: {approved_old[:12]} is not an "
                    f"ancestor of {new_sha[:12]}"
                )

    def _guard_hook(self, new_sha, approved_old, remote_url):
        env = dict(os.environ)
        env.update(
            {
                "APPROVED_OLD": approved_old,
                "APPROVED_NEW": new_sha,
                "EXPECTED_REMOTE_URL": remote_url,
                "EXPECTED_REF": f"refs/heads/{self.ref}",
            }
        )
        line = f"refs/heads/{self.ref} {new_sha} refs/heads/{self.ref} {approved_old}\n"
        r = subprocess.run(
            ["sh", self.hook_path, self.ref, remote_url],
            input=line.encode(),
            cwd=self.source_repo,
            env=env,
            capture_output=True,
        )
        if r.returncode != 0:
            raise StopPush(
                f"pre-push hook refused: {r.stderr.decode(errors='replace').strip()!r}"
            )

    def _advertisement(self):
        adv = {}
        first = True
        for line in _read_pkts(self.proc.stdout):
            if first:
                line, _, _caps = line.partition(b"\0")
                first = False
            oid, _, name = line.rstrip(b"\n").partition(b" ")
            adv[name.decode()] = oid.decode()
        return adv

    def push(self, new_sha, approved_old, remote_dir):
        if self.run_guards:
            self._guard_no_delete_and_ff(new_sha, approved_old)
            self._guard_hook(new_sha, approved_old, remote_dir)
        self.proc = subprocess.Popen(
            ["git", "receive-pack", remote_dir],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        adv = self._advertisement()
        advertised = adv.get(f"refs/heads/{self.ref}")
        if self.enforce_advertisement:
            if advertised is None and approved_old != ZERO:
                self._abort()
                raise StopPush(
                    f"ref {self.ref} does not exist but approved_old is not zero"
                )
            if advertised is not None and advertised != approved_old:
                self._abort()
                raise StopPush(
                    f"advertised {self.ref}={advertised[:12]} "
                    f"!= approved {approved_old[:12]}; "
                    f"re-admission required"
                )
        self._send_update(approved_old, new_sha)
        return self._report()

    def _send_update(self, old, new):
        pack = subprocess.run(
            [
                "git",
                "-C",
                self.source_repo,
                "pack-objects",
                "--stdout",
                "--revs",
                "--delta-base-offset",
            ],
            input=f"{new}\n".encode(),
            capture_output=True,
            check=True,
        ).stdout
        cmd = f"{old} {new} refs/heads/{self.ref}".encode()
        self.proc.stdin.write(_pkt(cmd + b"\0 report-status"))
        self.proc.stdin.write(b"0000")
        self.proc.stdin.write(pack)
        self.proc.stdin.flush()

    def _report(self):
        lines = _read_pkts(self.proc.stdout)
        self.proc.wait()
        text = b"".join(lines).decode(errors="replace")
        if f"ok refs/heads/{self.ref}" in text and "unpack ok" in text:
            return {"updated": self.ref}
        raise StopPush(f"server refused update: {text.strip()!r}")

    def _abort(self):
        self.proc.kill()
        self.proc.wait()


if __name__ == "__main__":
    import sys

    src, remote, ref, hook, new, old = sys.argv[1:7]
    try:
        print(StrictPush(src, remote, ref, hook).push(new, old, remote))
    except StopPush as s:
        print(f"STOPPED: {s}")
        sys.exit(3)
