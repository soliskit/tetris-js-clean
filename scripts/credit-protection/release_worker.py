import json
import os
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

import normal_transport
import production_entry
from scoped_remote import API_VERSION, NoRedirect, Stop


def revoke(token, deadline):
    pass

    remaining = deadline - time.monotonic()
    if remaining <= 0:
        raise Stop("revocation reserve exhausted")
    opener = urllib.request.build_opener(NoRedirect(), urllib.request.ProxyHandler({}))
    request = urllib.request.Request(
        "https://api.github.com/installation/token",
        method="DELETE",
        headers={
            "Authorization": "Bearer " + token,
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
        },
    )
    try:
        with opener.open(request, timeout=min(10, remaining)) as response:
            if response.status != 204 or response.read(1) != b"":
                raise Stop("revocation not confirmed")
    except Stop:
        raise
    except Exception:
        raise Stop("token revocation unverified") from None


def run(launch, pem_path, output):
    import publication_adapter
    from baseline import httpapi
    from hook_installer import read_owned
    from production_policy import issuer

    result = {"state": "stopped", "error_type": None, "token_revocation": "not-issued"}
    token = None
    response = {}
    client = httpapi.Client(budget_seconds=launch["budget_seconds"])
    publication_client = client.split_reserve(15)
    publication_deadline = publication_client.deadline
    try:
        import launch_entry

        launch_entry.assert_integrity(launch)
        expected = launch["approved_envelope_sha256"]
        envelope = launch["envelope"]
        if publication_adapter.digest(envelope) != expected:
            raise Stop("launch/envelope integrity mismatch")
        binding = envelope["binding"]
        if binding["repo"] not in production_entry.TARGETS:
            raise Stop("repository outside selected replacements")
        pem_raw, mode = read_owned(pem_path, 10000)
        if mode != 0o600 or len(pem_raw) < 1000:
            raise Stop("adopted key custody differs")
        del pem_raw
        now = int(time.time())
        head = issuer._b64u(b'{"alg":"RS256","typ":"JWT"}')
        body = issuer._b64u(
            json.dumps(
                {"iat": now - 60, "exp": now + 300, "iss": binding["app_id"]},
                separators=(",", ":"),
            ).encode()
        )
        signature = issuer._run_bounded(
            ["/usr/bin/openssl", "dgst", "-sha256", "-sign", str(pem_path)],
            head + b"." + body,
            min(30, max(0.01, publication_deadline - time.monotonic())),
        )
        jwt = (head + b"." + body + b"." + issuer._b64u(signature)).decode()
        result["token_revocation"] = "unverified-mint-request"
        response = publication_client.request_json(
            "https://api.github.com/app/installations/"
            + str(binding["installation_id"])
            + "/access_tokens",
            method="POST",
            token=jwt,
            body={
                "repository_ids": [binding["repo_id"]],
                "permissions": {"contents": "write", "checks": "write"},
            },
        )
        del jwt, signature

        if not isinstance(response, dict):
            raise Stop("token response malformed")
        token = response.pop("token", None)
        if not isinstance(token, str) or not token:
            token = None
            raise Stop("token absent from response")
        result["token_revocation"] = "pending"
        permissions = response.get("permissions")
        if (
            not isinstance(permissions, dict)
            or permissions.get("contents") != "write"
            or permissions.get("checks") != "write"
            or any(key not in ("contents", "checks", "metadata") for key in permissions)
            or permissions.get("metadata", "read") != "read"
        ):
            raise Stop("installation token permissions differ")
        repos = response.get("repositories")
        if (
            not isinstance(repos, list)
            or len(repos) != 1
            or repos[0].get("id") != binding["repo_id"]
            or repos[0].get("full_name") != binding["repo"]
        ):
            raise Stop("one-repository token selection not confirmed")
        helper = Path(output) / "askpass"
        fd = os.open(
            helper, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o700
        )
        with os.fdopen(fd, "wb") as stream:
            stream.write(normal_transport.ASKPASS_SOURCE)
            stream.flush()
            os.fsync(stream.fileno())
        helper_info = helper.stat()
        receipt = {
            "path": str(helper),
            "dev": helper_info.st_dev,
            "ino": helper_info.st_ino,
        }
        with (Path(output) / "helper-custody.json").open("x") as stream:
            json.dump(receipt, stream)
            stream.flush()
            os.fsync(stream.fileno())
        ack = Path(output) / "helper-adopted"
        ack_due = min(publication_deadline, time.monotonic() + 5)
        while not ack.exists():
            if time.monotonic() >= ack_due:
                raise Stop("outer helper adoption not confirmed")
            time.sleep(0.05)

        def trusted_launch_check(actual, actual_digest):

            return actual_digest == expected and actual == envelope

        result["publication"] = production_entry.run(
            envelope,
            expected,
            trusted_launch_check,
            token,
            launch["checkout"],
            launch["hook_receipt"],
            str(helper),
            launch["journal_directory"],
            absolute_deadline=publication_deadline,
        )
        result["state"] = "published"
    except BaseException as error:
        result["error_type"] = type(error).__name__
    finally:
        if token is not None:
            try:
                revoke(token, client.deadline)
                result["token_revocation"] = "confirmed"
            except BaseException as error:
                result["token_revocation"] = "unverified"
                result["revocation_error_type"] = type(error).__name__
                result["state"] = "stopped-needs-reconciliation"
            token = None
        if isinstance(response, dict):
            response.clear()
    return result


if __name__ == "__main__":
    result = {"state": "stopped", "token_revocation": "not-started"}
    try:
        raw = sys.stdin.buffer.read((4 << 20) + 1)
        if len(raw) > 4 << 20:
            raise Stop("launch size cap")
        launch = json.loads(raw)
        result = run(launch, Path(sys.argv[1]), Path(sys.argv[2]))
    except BaseException as error:
        result["error_type"] = type(error).__name__
    with (Path(sys.argv[2]) / "worker-result.json").open("x") as stream:
        json.dump(result, stream)
        stream.flush()
        os.fsync(stream.fileno())
    sys.exit(0 if result["state"] == "published" else 1)
