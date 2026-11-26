import os
import stat
from pathlib import Path

from hook_installer import Stop, read_owned, sha


def open_hooks(checkout):
    root = Path(checkout)
    if not root.is_absolute() or ".." in root.parts:
        raise Stop("anchored checkout required")
    fd = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for part in (*root.parts[1:], ".git", "hooks"):
            child = os.open(
                part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW, dir_fd=fd
            )
            os.close(fd)
            fd = child
        info = os.fstat(fd)
        if info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o022:
            raise Stop("hooks directory not exclusively owned")
        return fd
    except BaseException:
        os.close(fd)
        raise


def replace(checkout, expected_current_sha, replacement, mode, record):
    pass

    hooks = open_hooks(checkout)
    lock_name = ".credit-install.lock"
    temp_name = ".credit-pre-push.pending"
    lock = None
    temp_created = False
    try:
        try:
            lock = os.open(
                lock_name,
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                0o600,
                dir_fd=hooks,
            )
        except FileExistsError:
            raise Stop(
                "installer lock exists, reconcile original/wrapper and process ownership first"
            ) from None
        current = os.open(
            "pre-push", os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=hooks
        )
        try:
            info = os.fstat(current)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or info.st_size > 2 << 20
            ):
                raise Stop("current hook custody")
            raw = os.read(current, (2 << 20) + 1)
            if len(raw) != info.st_size or sha(raw) != expected_current_sha:
                raise Stop("current hook differs from reviewed original")
            original_identity = (info.st_dev, info.st_ino)
        finally:
            os.close(current)
        fd = os.open(
            temp_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            mode,
            dir_fd=hooks,
        )
        temp_created = True
        os.fchmod(fd, mode)
        with os.fdopen(fd, "wb") as out:
            out.write(replacement)
            out.flush()
            os.fsync(out.fileno())
        record(
            "hook_replace_pending",
            {"before": expected_current_sha, "after": sha(replacement)},
        )
        info = os.stat("pre-push", dir_fd=hooks, follow_symlinks=False)
        if (info.st_dev, info.st_ino) != original_identity:
            raise Stop("hook changed before atomic replace")
        os.replace(temp_name, "pre-push", src_dir_fd=hooks, dst_dir_fd=hooks)
        temp_created = False
        os.fsync(hooks)
        current = os.open("pre-push", os.O_RDONLY | os.O_NOFOLLOW, dir_fd=hooks)
        try:
            got = os.read(current, (2 << 20) + 1)
            if (
                sha(got) != sha(replacement)
                or stat.S_IMODE(os.fstat(current).st_mode) != mode
            ):
                raise Stop("installed hook readback differs")
        finally:
            os.close(current)
        record("hook_replace_confirmed", {"sha256": sha(replacement)})
    finally:
        if temp_created:
            os.unlink(temp_name, dir_fd=hooks)
        if lock is not None:
            original = os.fstat(lock)
            current = os.stat(lock_name, dir_fd=hooks, follow_symlinks=False)
            os.close(lock)
            if (original.st_dev, original.st_ino) != (current.st_dev, current.st_ino):
                os.close(hooks)
                raise Stop("installer lock changed, left untouched")
            os.unlink(lock_name, dir_fd=hooks)
        os.close(hooks)


def rollback(checkout, receipt, record):
    original, _mode = read_owned(receipt["saved_original"])
    if sha(original) != receipt["original_sha256"]:
        raise Stop("rollback original source changed")

    replace(
        checkout, receipt["wrapper_sha256"], original, receipt["original_mode"], record
    )
