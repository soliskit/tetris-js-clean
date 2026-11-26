import ctypes
import hashlib
import json
import os
import signal
import stat
import subprocess
import time
from pathlib import Path


class Stop(Exception):
    pass


def process(pid):
    try:
        raw = Path("/proc", str(pid), "stat").read_text()
        rest = raw[raw.rfind(")") + 2 :].split()
        return {"pid": pid, "parent": int(rest[1]), "start": rest[19], "state": rest[0]}
    except (OSError, ValueError, IndexError):
        return None


def scan():
    result = {}
    for path in Path("/proc").iterdir():
        if path.name.isdigit():
            value = process(int(path.name))
            if value:
                result[value["pid"]] = value
    return result


def parent_fd(path):
    pass

    path = Path(path)
    if not path.is_absolute() or ".." in path.parts:
        raise Stop("absolute anchored path required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in path.parts[1:-1]:
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
            info = os.fstat(fd)
            writable = stat.S_IMODE(info.st_mode) & 0o022
            sticky_root = info.st_uid == 0 and info.st_mode & stat.S_ISVTX
            if info.st_uid not in (0, os.getuid()) or (writable and not sticky_root):
                raise Stop("untrusted allocation ancestor")
        return fd, path.name
    except BaseException:
        os.close(fd)
        raise


def adopt_at(directory, name, mode, expected=None):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        identity = (info.st_dev, info.st_ino, info.st_size)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or stat.S_IMODE(info.st_mode) != mode
            or (expected is not None and identity != tuple(expected))
        ):
            raise Stop("allocation identity or custody differs")
        return identity
    finally:
        os.close(fd)


def erase_at(directory, name, identity):
    fd = os.open(name, os.O_WRONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (
            (info.st_dev, info.st_ino, info.st_size) != tuple(identity)
            or not stat.S_ISREG(info.st_mode)
            or info.st_nlink != 1
            or info.st_uid != os.getuid()
        ):
            raise Stop("changed allocation not erased")
        remaining = info.st_size
        while remaining:
            count = os.write(fd, b"\0" * min(65536, remaining))
            if count <= 0:
                raise Stop("overwrite incomplete")
            remaining -= count
        os.fsync(fd)
        now = os.stat(name, dir_fd=directory, follow_symlinks=False)
        if (now.st_dev, now.st_ino) != tuple(identity[:2]):
            raise Stop("allocation pathname replaced")
        os.unlink(name, dir_fd=directory)
        os.fsync(directory)
        try:
            os.stat(name, dir_fd=directory, follow_symlinks=False)
        except FileNotFoundError:
            return True
        raise Stop("allocation still present")
    finally:
        os.close(fd)


def write_record(directory, name, value):
    raw = (json.dumps(value, sort_keys=True) + "\n").encode()
    if len(raw) > 4 << 20:
        raise Stop("record cap")
    fd = os.open(
        name,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
        0o600,
        dir_fd=directory,
    )
    with os.fdopen(fd, "wb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    os.fsync(directory)


def read_record(directory, name):
    fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=directory)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
            or info.st_size > 4 << 20
        ):
            raise Stop("record custody")
        raw = os.read(fd, (4 << 20) + 1)
        if len(raw) != info.st_size:
            raise Stop("record incomplete")
        return json.loads(raw)
    finally:
        os.close(fd)


def run(
    launch_path,
    pem_path,
    fresh_root,
    expected_launch_sha256,
    allocated_pem_identity,
    verify_original_approval,
):
    pass

    result = {
        "state": "stopped",
        "worker_exit": None,
        "cleanup_errors": [],
        "quiescent": False,
        "key_absent": False,
        "helper_absent": False,
        "token_revocation": "not-started",
    }
    pem_dir = root_dir = root_parent = None
    pem_identity = helper_identity = None
    known = {}
    child = None
    launch_fd = None
    owner = os.getpid()
    dedicated = subreaper = False
    try:
        if len(list(Path("/proc/self/task").iterdir())) != 1:
            raise Stop("dedicated single-thread owner required")
        if any(item["parent"] == owner for item in scan().values()):
            raise Stop("dedicated owner already has children")
        dedicated = True
        pem_dir, pem_name = parent_fd(pem_path)
        pem_identity = adopt_at(pem_dir, pem_name, 0o600, allocated_pem_identity)

        launch_parent, launch_name = parent_fd(launch_path)
        try:
            read_record(launch_parent, launch_name)
            fd = os.open(launch_name, os.O_RDONLY | os.O_NOFOLLOW, dir_fd=launch_parent)
            try:
                launch_raw = os.read(fd, (4 << 20) + 1)
            finally:
                os.close(fd)
        finally:
            os.close(launch_parent)
        if hashlib.sha256(launch_raw).hexdigest() != expected_launch_sha256:
            raise Stop("launch digest differs from review")

        launch = json.loads(launch_raw)
        import launch_entry

        launch_entry.assert_integrity(launch)
        if verify_original_approval(launch, expected_launch_sha256) is not True:
            raise Stop("original approval does not cover production launch")
        budget = launch["budget_seconds"]
        if type(budget) is not int or not 30 <= budget <= 600:
            raise Stop("invalid execution budget")
        root_parent, root_name = parent_fd(fresh_root)
        os.mkdir(root_name, mode=0o700, dir_fd=root_parent)
        root_dir = os.open(
            root_name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=root_parent
        )
        info = os.fstat(root_dir)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700:
            raise Stop("output root custody")
        root_identity = (info.st_dev, info.st_ino)
        write_record(
            root_dir,
            "allocation-recovery.json",
            {
                "pem_path": str(pem_path),
                "pem_identity": pem_identity,
                "root_identity": root_identity,
                "launch_sha256": expected_launch_sha256,
            },
        )
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.prctl(36, 1, 0, 0, 0) != 0:
            raise Stop("cannot adopt orphaned descendants")
        subreaper = True
        due = time.monotonic() + budget
        worker = Path(__file__).resolve().with_name("release_worker.py")
        launch_fd = os.memfd_create("production-launch", os.MFD_CLOEXEC)
        offset = 0
        while offset < len(launch_raw):
            count = os.write(launch_fd, launch_raw[offset:])
            if count <= 0:
                raise Stop("launch memfd write incomplete")
            offset += count
        os.lseek(launch_fd, 0, os.SEEK_SET)
        child = subprocess.Popen(
            ["/usr/bin/python3", str(worker), str(pem_path), str(fresh_root)],
            stdin=launch_fd,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env={
                "PATH": "/usr/bin:/bin",
                "HOME": str(fresh_root),
                "LC_ALL": "C.UTF-8",
                "PYTHONDONTWRITEBYTECODE": "1",
            },
            start_new_session=True,
        )
        initial = process(child.pid)
        if initial is not None:
            known[child.pid] = initial
        os.close(launch_fd)
        launch_fd = None
        while True:
            current = scan()
            changed = True
            while changed:
                changed = False
                for pid, value in current.items():
                    if pid not in known and (
                        value["parent"] == owner or value["parent"] in known
                    ):
                        known[pid] = value
                        changed = True

            info = os.stat(root_name, dir_fd=root_parent, follow_symlinks=False)
            if (info.st_dev, info.st_ino) != root_identity:
                raise Stop("output root pathname changed")
            if helper_identity is None:
                try:
                    receipt = read_record(root_dir, "helper-custody.json")
                except FileNotFoundError:
                    receipt = None
                if receipt is not None:
                    helper_identity = adopt_at(root_dir, "askpass", 0o700)
                    if receipt.get("path") != str(
                        Path(fresh_root) / "askpass"
                    ) or helper_identity[:2] != (
                        receipt.get("dev"),
                        receipt.get("ino"),
                    ):
                        raise Stop("helper receipt differs")
                    write_record(root_dir, "helper-adopted", {"adopted": True})
            code = child.poll()
            if code is not None:
                child.wait()
                result["worker_exit"] = code
                break
            if time.monotonic() >= due:
                raise Stop("production deadline")
            time.sleep(0.05)
        result["token_revocation"] = "unverified-worker-result"
        result["worker"] = read_record(root_dir, "worker-result.json")
        if not isinstance(result["worker"], dict):
            raise Stop("worker result schema invalid")
        result["state"] = result["worker"].get("state", "stopped")
        result["token_revocation"] = result["worker"].get(
            "token_revocation", "unverified"
        )
    except BaseException as error:
        result["error_type"] = type(error).__name__
    finally:
        if launch_fd is not None:
            os.close(launch_fd)

        cleanup_due = time.monotonic() + 30
        if dedicated:
            while time.monotonic() < cleanup_due:
                current = scan()
                live = []
                for pid, value in current.items():
                    if value["parent"] == owner:
                        known[pid] = value
                for pid, expected in list(known.items()):
                    value = process(pid)
                    if (
                        value
                        and value["start"] == expected["start"]
                        and value["state"] not in ("Z", "X")
                    ):
                        live.append(pid)
                        try:
                            os.kill(pid, signal.SIGKILL)
                        except ProcessLookupError:
                            pass
                while True:
                    try:
                        pid, _ = os.waitpid(-1, os.WNOHANG)
                        if pid == 0:
                            break
                    except ChildProcessError:
                        break

                if not live and not any(v["parent"] == owner for v in scan().values()):
                    result["quiescent"] = True
                    break
                time.sleep(0.05)
        if child is not None:
            for stream in (child.stdout, child.stderr):
                if stream is not None:
                    stream.close()
            if result["worker_exit"] is None:
                result["token_revocation"] = "unverified-worker-interrupted"
        if result["quiescent"]:
            if root_dir is not None and helper_identity is None:
                try:
                    helper_identity = adopt_at(root_dir, "askpass", 0o700)
                except FileNotFoundError:
                    result["helper_absent"] = True
                except Exception as error:
                    result["cleanup_errors"].append(
                        "helper-adopt-" + type(error).__name__
                    )
            for label, directory, name, identity in (
                ("key", pem_dir, Path(pem_path).name, pem_identity),
                ("helper", root_dir, "askpass", helper_identity),
            ):
                if directory is not None and identity is not None:
                    try:
                        result[label + "_absent"] = erase_at(directory, name, identity)
                    except Exception as error:
                        result["cleanup_errors"].append(
                            label + "-" + type(error).__name__
                        )
        else:
            result["cleanup_errors"].append(
                "unverified-quiescence-retained-allocations"
            )
        if pem_identity is None:
            result["cleanup_errors"].append(
                "external-key-allocation-not-adopted-caller-recovery"
            )
        result["process_identities"] = len(known)
        result["subreaper_active"] = subreaper
        if result["cleanup_errors"] or (
            child is not None
            and result["token_revocation"]
            not in ("confirmed", "not-issued", "not-started")
        ):
            result["state"] = "stopped-needs-reconciliation"
        if root_dir is not None:
            try:
                write_record(root_dir, "owner-result.json", result)
            except Exception as error:
                result["cleanup_errors"].append("owner-result-" + type(error).__name__)
                result["state"] = "stopped-needs-reconciliation"
        for descriptor in (root_dir, root_parent, pem_dir):
            if descriptor is not None:
                os.close(descriptor)
    return result
