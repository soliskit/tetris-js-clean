import sys
from pathlib import Path

import normal_transport
import publication_adapter
from durable_journal import Journal
from scoped_remote import ScopedRemote

BASELINE = Path(__file__).resolve().parent / "baseline"

if str(BASELINE) not in sys.path:
    sys.path.insert(0, str(BASELINE))

TARGETS = frozenset(
    {
        "soliskit/tetris-js-clean",
        "soliskit/foundry-clean",
        "soliskit/soliskit-site-clean",
        "soliskit/profile-clean",
        "soliskit/litmus-clean-v2",
        "soliskit/Tetris-clean",
        "soliskit/Arx-clean",
        "soliskit/salutant-clean",
        "soliskit/pinto-clean",
    }
)


class Authority:
    def __init__(self, expected_digest, verify_original):
        self.expected_digest = expected_digest
        self.verify_original = verify_original

    def assert_approved(self, envelope, actual_digest):
        if actual_digest != self.expected_digest:
            raise ValueError("execution differs from reviewed candidate")

        if self.verify_original(envelope, actual_digest) is not True:
            raise ValueError("original user approval does not cover this publication")


def prepare(binding, checkout):
    if binding["repo"] not in TARGETS:
        raise ValueError("repository outside replacement scope")
    import subprocess

    from production_policy import issuer

    env = {
        "PATH": "/usr/bin:/bin",
        "HOME": checkout,
        "LC_ALL": "C.UTF-8",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_NO_REPLACE_OBJECTS": "1",
    }

    def read_object(sha):

        kind = (
            subprocess.check_output(
                ["/usr/bin/git", "-C", checkout, "cat-file", "-t", sha],
                timeout=30,
                env=env,
            )
            .decode()
            .strip()
        )
        raw = subprocess.check_output(
            ["/usr/bin/git", "-C", checkout, "cat-file", kind, sha], timeout=30, env=env
        )
        return kind, raw

    def admit(head):

        ancestry = issuer.admit(issuer.LocalGitSource(checkout), head)
        from project_bootstrap import publication_gate as project_profile

        for sha in ancestry:
            kind, raw = read_object(sha)
            if kind != "commit":
                raise ValueError("noncommit in admitted ancestry")
            _, separator, message = raw.partition(b"\n\n")
            if not separator:
                raise ValueError("message delimiter absent")
            project_profile.full_message(message)
        return ancestry

    return publication_adapter.prepare(binding, read_object, admit)


def run(
    envelope,
    expected_digest,
    verify_original,
    token,
    checkout,
    hook_receipt,
    askpass_path,
    journal_directory,
    absolute_deadline=None,
):
    if envelope["binding"]["repo"] not in TARGETS:
        raise ValueError("repository outside replacement scope")
    from production_policy import issuer

    binding = envelope["binding"]

    def admission(value):
        return issuer.issue(
            issuer.LocalGitSource(checkout),
            value["head"],
            value["repo_id"],
            value["old"],
            issuer.policy.EPOCH,
        )

    def push(value, selected_token, remaining):
        return normal_transport.push(
            value, selected_token, remaining, checkout, hook_receipt, askpass_path
        )

    authority = Authority(expected_digest, verify_original)
    remote = ScopedRemote(
        binding, token, admission, push, max_calls=2 * len(envelope["objects"]) + 16
    )
    if absolute_deadline is not None:
        remote.deadline = absolute_deadline
    with Journal(journal_directory) as journal:
        return publication_adapter.execute(
            envelope, expected_digest, authority, journal, remote
        )
