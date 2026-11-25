"""Review draft ordinary trusted-test lifetime. No security sandbox claim."""

import hashlib
import json
import os
import signal
import subprocess
import time
from pathlib import Path


class InterruptedRun(Exception):
    pass


def save(path, value):
    path = Path(path)
    tmp = path.with_name(path.name + ".pending")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "w") as stream:
        json.dump(value, stream, indent=2)
        stream.write("\n")
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(tmp, path)
    fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def exists_group(pgid):
    try:
        os.killpg(pgid, 0)
        return True
    except ProcessLookupError:
        return False


def run(argv, cwd, env, logs, label, seconds):
    """Finite allowance applies to complete unchanged command, no filtering.

    No signal is sent to a group whose directly-owned leader already exited.
    Such leftovers are reported incomplete, not killed by stale numeric ID.
    """
    target = Path(logs) / label
    target.mkdir(mode=0o700)
    record = {
        "status": "INCOMPLETE",
        "argv": argv,
        "cwd": str(cwd),
        "environment_sha256": hashlib.sha256(
            json.dumps(env, sort_keys=True).encode()
        ).hexdigest(),
        "start_unix": time.time(),
        "allowance_seconds": seconds,
        "exit": None,
        "cleanup": None,
    }
    child = None
    handlers = {}
    error = None

    def interrupted(signum, frame):
        # Shield repeat signals BEFORE any receipt or cleanup operation.
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        record["signal"] = signum
        raise InterruptedRun("interrupted")

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        handlers[sig] = signal.signal(sig, interrupted)
    try:
        save(target / "start.json", record)
        save(target / "final.json", record)
        print("Running " + label + ": " + " ".join(argv), flush=True)
        with (
            (target / "stdout.log").open("xb") as out,
            (target / "stderr.log").open("xb") as err,
        ):
            child = subprocess.Popen(
                argv,
                cwd=cwd,
                env=env,
                stdin=subprocess.DEVNULL,
                stdout=out,
                stderr=err,
                start_new_session=True,
            )
            record["pid"] = child.pid
            record["pgid"] = child.pid
            save(target / "launched.json", record)
            record["exit"] = child.wait(timeout=seconds)
            record["group_absent_after_wait"] = not exists_group(child.pid)
            out.flush()
            err.flush()
            os.fsync(out.fileno())
            os.fsync(err.fileno())
            if record["exit"] != 0:
                raise RuntimeError("command returned nonzero")
            if not record["group_absent_after_wait"]:
                record["orphan_warning"] = (
                    "leader exited but group remains; no stale-group signal"
                )
                raise RuntimeError("possible child cleanup incomplete")
            record["status"] = "EXIT_ZERO"
    except BaseException as exc:
        error = exc
        record["error_class"] = type(exc).__name__
        record["status"] = "INCOMPLETE"
    finally:
        # Cleanup precedes and does not depend on successful disk receipts.
        for sig in handlers:
            signal.signal(sig, signal.SIG_IGN)
        try:
            if child is not None:
                cleanup = {"term": False, "kill": False}
                if child.poll() is None:
                    cleanup["owned_live_leader"] = True
                    try:
                        os.killpg(child.pid, signal.SIGTERM)
                        cleanup["term"] = True
                    except ProcessLookupError:
                        pass
                    try:
                        child.wait(timeout=15)
                    except subprocess.TimeoutExpired:
                        if child.poll() is None:
                            try:
                                os.killpg(child.pid, signal.SIGKILL)
                                cleanup["kill"] = True
                            except ProcessLookupError:
                                pass
                        try:
                            child.wait(timeout=5)
                        except subprocess.TimeoutExpired:
                            cleanup["direct_child_wait_incomplete"] = True
                else:
                    cleanup["stale_group_not_signalled"] = True
                cleanup["direct_child_reaped"] = child.returncode is not None
                cleanup["group_absent_readback"] = not exists_group(child.pid)
                record["cleanup"] = cleanup
                record["exit"] = child.returncode
                if (
                    not cleanup["direct_child_reaped"]
                    or not cleanup["group_absent_readback"]
                ):
                    record["status"] = "INCOMPLETE"
                    error = error or RuntimeError("cleanup incomplete")
        except BaseException as exc:
            record["cleanup_error_class"] = type(exc).__name__
            record["status"] = "INCOMPLETE"
            error = error or exc
        record["end_unix"] = time.time()
        try:
            save(target / "final.json", record)
        except BaseException as exc:
            record["receipt_error_class"] = type(exc).__name__
            record["status"] = "INCOMPLETE"
            error = error or exc
        finally:
            for sig, prior in handlers.items():
                signal.signal(sig, prior)
    # Always return record so top-level status captures failed/current command.
    return record, error
