import json
import re
import time
import urllib.error
import urllib.request

API_VERSION = "2026-03-10"


class Stop(Exception):
    pass


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, response, code, message, headers, newurl):
        raise Stop("redirect refused")


class ScopedRemote:
    def __init__(
        self, binding, token, admission, normal_push, timeout=600, max_calls=2000
    ):
        self.binding = dict(binding)
        self.token = token
        self.admission = admission
        self.normal_push = normal_push
        self.deadline = time.monotonic() + timeout
        self.max_calls = max_calls
        self.calls = 0
        self.base = "https://api.github.com/repos/" + binding["repo"]
        self.opener = urllib.request.build_opener(
            NoRedirect(), urllib.request.ProxyHandler({})
        )

    def remaining(self):
        left = self.deadline - time.monotonic()
        if left <= 0:
            raise Stop("publication deadline exhausted")
        return left

    def request(self, method, suffix, body=None, allow_absent=False):

        patterns = {
            "GET": [
                r"",
                r"/git/(?:blobs|trees|commits)/[0-9a-f]{40}",
                r"/git/ref/heads/[A-Za-z0-9_./-]+",
                r"/check-runs/[0-9]+",
            ],
            "POST": [r"/git/(?:blobs|trees|commits)", r"/check-runs"],
        }
        if not any(
            re.fullmatch(pattern, suffix) for pattern in patterns.get(method, [])
        ):
            raise Stop("endpoint outside production publication scope")
        self.calls += 1
        if self.calls > self.max_calls:
            raise Stop("publication API call cap")
        request = urllib.request.Request(
            self.base + suffix,
            method=method,
            data=json.dumps(body).encode() if body is not None else None,
            headers={
                "Authorization": "Bearer " + self.token,
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": API_VERSION,
            },
        )
        try:
            with self.opener.open(
                request, timeout=min(30, self.remaining())
            ) as response:
                raw = response.read((4 << 20) + 1)
        except urllib.error.HTTPError as error:
            if allow_absent and error.code == 404:
                return None
            raise Stop("GitHub request failed, HTTP " + str(error.code)) from None
        except Stop:
            raise
        except Exception:
            raise Stop("GitHub transport failure") from None
        if len(raw) > 4 << 20:
            raise Stop("response size cap")
        try:
            result = json.loads(raw)
        except ValueError:
            raise Stop("non-JSON response") from None
        if not isinstance(result, dict):
            raise Stop("unexpected response shape")
        return result

    def assert_identity(self, binding):
        if binding != self.binding:
            raise Stop("publication binding changed")
        repo = self.request("GET", "")
        if (
            repo.get("id") != binding["repo_id"]
            or repo.get("full_name") != binding["repo"]
        ):
            raise Stop("repository identity mismatch")

    def assert_ref(self, ref, expected):

        if (
            not re.fullmatch(r"refs/heads/[A-Za-z0-9_/-]+(?:\.[A-Za-z0-9_-]+)*", ref)
            or ".." in ref
            or "//" in ref
            or ref.endswith(("/", ".lock"))
        ):
            raise Stop("unsupported branch spelling")
        value = self.request(
            "GET", "/git/ref/" + ref[len("refs/") :], allow_absent=True
        )
        actual = "0" * 40 if value is None else (value.get("object") or {}).get("sha")
        if value is not None and (
            value.get("ref") != ref
            or (value.get("object") or {}).get("type") != "commit"
        ):
            raise Stop("ref response differs")
        if actual != expected:
            raise Stop("destination predecessor/head differs")

    def exact_object_state(self, kind, sha):
        groups = {"blob": "blobs", "tree": "trees", "commit": "commits"}
        if kind not in groups or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise Stop("object query outside exact plan")
        result = self.request(
            "GET", "/git/" + groups[kind] + "/" + sha, allow_absent=True
        )
        if result is None:
            return "absent"
        if result.get("sha") != sha:
            raise Stop("object query id differs")
        return "present"

    def upload_object(self, kind, body):
        groups = {"blob": "blobs", "tree": "trees", "commit": "commits"}
        if kind not in groups:
            raise Stop("upload kind outside plan")
        return self.request("POST", "/git/" + groups[kind], body)

    def revalidate_local_admission(self, binding):
        self.receipt = self.admission(binding)
        self.receipt.revalidate()
        if (
            self.receipt.head_sha != binding["head"]
            or self.receipt.repo_id != binding["repo_id"]
        ):
            raise Stop("admission receipt binding differs")
        if (
            self.receipt.policy_sha256 != binding["policy_sha256"]
            or self.receipt.release_source_sha256 != binding["source_sha256"]
        ):
            raise Stop("admission policy/source differs")

    def publish_admitted_check(self, binding):
        if not hasattr(self, "receipt"):
            raise Stop("admission receipt not supplied")
        self.receipt.revalidate()
        if self.receipt.head_sha != binding["head"]:
            raise Stop("head differs after admission")
        result = self.request(
            "POST",
            "/check-runs",
            {
                "name": "Credit ancestry v2-e" + str(self.receipt.epoch),
                "head_sha": binding["head"],
                "status": "completed",
                "conclusion": "success",
                "output": self.receipt.payload(),
            },
        )
        self._validate_check(binding, result)
        return result["id"]

    def _validate_check(self, binding, result):
        if (
            type(result.get("id")) is not int
            or result["id"] <= 0
            or result.get("head_sha") != binding["head"]
            or result.get("name") != "Credit ancestry v2-e" + str(self.receipt.epoch)
            or result.get("status") != "completed"
            or result.get("conclusion") != "success"
            or (result.get("app") or {}).get("id") != binding["app_id"]
            or (result.get("output") or {}).get("summary")
            != self.receipt.payload()["summary"]
        ):
            raise Stop("exact successful check not confirmed")

    def confirm_check(self, binding, check_id):
        result = self.request("GET", "/check-runs/" + str(check_id))
        self._validate_check(binding, result)
        if result["id"] != check_id:
            raise Stop("issued check id differs")

    def normal_hooked_push(self, binding):
        self.normal_push(binding, self.token, self.remaining())
