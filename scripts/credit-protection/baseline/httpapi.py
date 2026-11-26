import json
import time
import urllib.error
import urllib.parse
import urllib.request

MAX_BODY = 4 * 1024 * 1024
TIMEOUT = 30
API_VERSION = "2026-03-10"
ALLOWED_HOST = "api.github.com"


class ApiError(Exception):
    pass


class DeadlineExceeded(ApiError):
    pass


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ApiError(f"refused redirect from {ALLOWED_HOST} (HTTP {code})")


_OPENER = urllib.request.build_opener(urllib.request.ProxyHandler({}), _NoRedirect)


class Client:
    pass

    def __init__(self, budget_seconds=300):
        self.deadline = time.monotonic() + budget_seconds

    def total_remaining(self):
        pass

        left = self.deadline - time.monotonic()
        if left <= 0:
            raise DeadlineExceeded("release deadline exhausted")
        return left

    def call_timeout(self, cap=TIMEOUT):
        pass
        return min(cap, self.total_remaining())

    def _remaining(self):
        return self.call_timeout()

    def split_reserve(self, reserve_seconds):
        pass

        child = type(self).__new__(type(self))
        child.deadline = self.deadline - max(0.0, reserve_seconds)
        return child

    def request_json(self, url, method="GET", token=None, body=None):
        parts = urllib.parse.urlparse(url)
        if parts.scheme != "https" or parts.netloc != ALLOWED_HOST:
            raise ApiError(
                f"refused non-allowlisted URL "
                f"(scheme={parts.scheme!r} host={parts.netloc!r})"
            )
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": API_VERSION,
        }
        if token is not None:
            headers["Authorization"] = f"Bearer {token}"
        data = json.dumps(body).encode() if body is not None else None
        req = urllib.request.Request(url, data=data, method=method, headers=headers)
        try:
            with _OPENER.open(req, timeout=self._remaining()) as r:
                raw = r.read(MAX_BODY + 1)
        except urllib.error.HTTPError as e:
            raise ApiError(f"{method} {ALLOWED_HOST}: HTTP {e.code}") from None
        except ApiError:
            raise
        except Exception:
            raise ApiError(f"{method} {ALLOWED_HOST}: transport error") from None
        if len(raw) > MAX_BODY:
            raise ApiError(f"{method} {ALLOWED_HOST}: response over {MAX_BODY} bytes")
        try:
            return json.loads(raw)
        except ValueError:
            raise ApiError(f"{method} {ALLOWED_HOST}: non-JSON response") from None


def request_json(url, method="GET", token=None, body=None):
    pass

    return Client(budget_seconds=TIMEOUT).request_json(
        url, method=method, token=token, body=body
    )
