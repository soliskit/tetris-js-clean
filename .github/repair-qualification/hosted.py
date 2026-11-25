"""Fresh-host entrypoint for isolated full qualification and hashed evidence."""

import argparse
import hashlib
import importlib.util
import json
import os
import platform
import signal
import subprocess
import sys
import tarfile
import tempfile
import time
from pathlib import Path


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output-parent", required=True)
    args = parser.parse_args()
    package = Path(__file__).resolve().parent
    pins = json.loads((package / "payload/pins.json").read_text())
    for name, digest in pins.items():
        if hashlib.sha256((package / name).read_bytes()).hexdigest() != digest:
            raise ValueError("hosted package changed")
    if (platform.system(), platform.machine()) != ("Darwin", "arm64"):
        raise ValueError("standard hosted Mac arm64 required")
    output = Path(
        tempfile.mkdtemp(prefix="hosted-qualification-", dir=args.output_parent)
    )
    output.chmod(0o700)
    receipt = {
        "status": "INCOMPLETE",
        "qualification": False,
        "start_unix": time.time(),
    }
    code = 1
    complete = False
    child = None
    handlers = {}

    def write_receipt():
        (output / "hosted.json").write_text(json.dumps(receipt, indent=2))

    def forward(signum, frame):
        receipt["signal"] = signum
        if child is not None and child.poll() is None:
            child.send_signal(signum)

    for sig in (signal.SIGTERM, signal.SIGINT, signal.SIGHUP):
        handlers[sig] = signal.signal(sig, forward)
    try:
        try:
            write_receipt()
            child = subprocess.Popen(
                [
                    sys.executable,
                    "-I",
                    str(package / "setup.py"),
                    "--output-parent",
                    str(output),
                    "--host-deadline-unix",
                    str(float(os.environ["HOST_DEADLINE_UNIX"])),
                ],
            )
            code = child.wait()
        except (OSError, ValueError, RuntimeError) as exc:
            receipt["launch_error_class"] = type(exc).__name__
        evidence = sorted(output.rglob("*.evidence.tar.gz"))
        try:
            results = sorted(output.rglob("result.json"))
            if (
                code == 0
                and "signal" not in receipt
                and len(evidence) == 1
                and len(results) == 1
            ):
                result = json.loads(results[0].read_text())
                complete = (
                    result.get("status") == "COMPLETE"
                    and result.get("qualification") is True
                )
        except (OSError, ValueError, TypeError, AttributeError) as exc:
            receipt["classification_error_class"] = type(exc).__name__
            complete = False
        receipt.update(
            status="COMPLETE" if complete else "INCOMPLETE",
            qualification=complete,
            exit=code,
        )
        try:
            write_receipt()
        except OSError as exc:
            receipt.update(
                status="INCOMPLETE",
                qualification=False,
                receipt_error_class=type(exc).__name__,
            )
            complete = False
        try:
            combined = output / "hosted.evidence.tar.gz"
            with tarfile.open(combined, "w:gz") as archive:
                if (output / "hosted.json").exists():
                    archive.add(output / "hosted.json", arcname="hosted.json")
                for path in evidence:
                    archive.add(path, arcname=str(path.relative_to(output)))
                for name in ("setup.json", "runtime-admission.json"):
                    for path in output.rglob(name):
                        archive.add(path, arcname=str(path.relative_to(output)))
                for path in output.rglob("setup-commands"):
                    if path.is_dir():
                        archive.add(path, arcname=str(path.relative_to(output)))
            spec = importlib.util.spec_from_file_location(
                "log_transport", package / "log_transport.py"
            )
            transport = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(transport)
            transport.encode(combined, sys.stdout)
        except (OSError, ValueError, tarfile.TarError, RuntimeError) as exc:
            complete = False
            receipt.update(
                status="INCOMPLETE",
                qualification=False,
                evidence_error_class=type(exc).__name__,
            )
            try:
                write_receipt()
            except OSError as nested:
                print("HOSTED_RECEIPT_INCOMPLETE " + type(nested).__name__, flush=True)
            print("HOSTED_EVIDENCE_INCOMPLETE " + type(exc).__name__, flush=True)
        finally:
            print("HOSTED_FINAL " + json.dumps(receipt, sort_keys=True), flush=True)
    finally:
        for sig, prior in handlers.items():
            signal.signal(sig, prior)
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
