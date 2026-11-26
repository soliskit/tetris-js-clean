import json
import os
import stat
from pathlib import Path


class Stop(Exception):
    pass


class Journal:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.fd = None
        self.lock_identity = None

    def __enter__(self):

        info = self.directory.lstat()
        if (
            not stat.S_ISDIR(info.st_mode)
            or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700
        ):
            raise Stop("journal directory custody")
        self.lock = self.directory / "publication.lock"
        try:
            fd = os.open(
                self.lock, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
            )
        except FileExistsError:
            raise Stop(
                "publication lock exists, verify owner/quiescence and reconcile before removal"
            ) from None
        info = os.fstat(fd)
        self.lock_identity = (info.st_dev, info.st_ino)
        os.close(fd)
        try:
            self.path = self.directory / "publication.jsonl"
            self.fd = os.open(
                self.path, os.O_RDWR | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW, 0o600
            )
            info = os.fstat(self.fd)
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or info.st_nlink != 1
                or stat.S_IMODE(info.st_mode) != 0o600
                or info.st_size > 8 << 20
            ):
                raise Stop("journal file custody")
            self.assert_no_pending()
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def records(self):
        os.lseek(self.fd, 0, os.SEEK_SET)
        chunks, size = [], 0
        while True:
            chunk = os.read(self.fd, 65536)
            if not chunk:
                break
            size += len(chunk)
            if size > 8 << 20:
                raise Stop("journal size cap")
            chunks.append(chunk)
        raw = b"".join(chunks)
        if raw and not raw.endswith(b"\n"):
            raise Stop("partial journal record, recovery required")
        try:
            records = [json.loads(line) for line in raw.splitlines()]
        except (ValueError, UnicodeDecodeError):
            raise Stop("malformed journal, recovery required") from None
        if any(
            not isinstance(item, dict)
            or set(item) != {"stage", "data"}
            or not isinstance(item["stage"], str)
            or not isinstance(item["data"], dict)
            for item in records
        ):
            raise Stop("journal schema invalid")
        return records

    def assert_no_pending(self):
        records = self.records()
        state = "idle"
        next_states = {
            "idle": {"publication_started": "started"},
            "started": {
                "object_request_pending": "object-pending",
                "check_request_pending": "check-pending",
            },
            "object-pending": {"object_request_confirmed": "started"},
            "check-pending": {"check_confirmed": "checked"},
            "checked": {"push_pending": "push-pending"},
            "push-pending": {"publication_reconciled": "idle"},
        }
        for record in records:
            stage = record["stage"]
            if stage not in next_states[state]:
                raise Stop("journal transition invalid, recovery required")
            state = next_states[state][stage]
        if state != "idle":
            raise Stop("previous publication unresolved, read-only recovery required")

    def sync(self, stage, data):
        if self.fd is None or not isinstance(stage, str) or not isinstance(data, dict):
            raise Stop("journal not open or invalid record")
        raw = (
            json.dumps(
                {"stage": stage, "data": data}, sort_keys=True, separators=(",", ":")
            )
            + "\n"
        ).encode()
        if len(raw) > 65536:
            raise Stop("journal record cap")
        pos = 0
        while pos < len(raw):
            count = os.write(self.fd, raw[pos:])
            if count <= 0:
                raise Stop("journal write incomplete")
            pos += count
        os.fsync(self.fd)
        directory = os.open(
            self.directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
        )
        try:
            os.fsync(directory)
        finally:
            os.close(directory)

    def __exit__(self, *unused):
        try:
            if self.fd is not None:
                os.close(self.fd)
                self.fd = None
        finally:
            if self.lock_identity is not None:
                info = self.lock.lstat()
                if (info.st_dev, info.st_ino) != self.lock_identity:
                    raise Stop("lock ownership changed, not removed")
                self.lock.unlink()
                self.lock_identity = None
