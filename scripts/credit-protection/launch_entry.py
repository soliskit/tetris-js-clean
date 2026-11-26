import copy
import json

import installer_entry
import installer_owner
import production_entry
from production_policy import policy
from publication_adapter import digest


class Stop(Exception):
    pass


def prepare(
    envelope, checkout, hook_receipt, journal_directory, budget_seconds, read_repository
):
    envelope = copy.deepcopy(envelope)
    binding = envelope["binding"]
    if binding["repo"] not in production_entry.TARGETS:
        raise Stop("repository outside selected replacement scope")
    if (
        binding["source_sha256"] != policy.source_digest()
        or binding["policy_sha256"] != policy.policy_digest()
    ):
        raise Stop("candidate source/policy differs from current package")
    if type(budget_seconds) is not int or not 30 <= budget_seconds <= 600:
        raise Stop("invalid launch budget")

    inspection = installer_entry.prepare_rollback(
        checkout, binding["repo"], binding["repo_id"], hook_receipt, read_repository
    )
    installer_owner.components(hook_receipt)
    if inspection["head"] != binding["head"]:
        raise Stop("current checkout HEAD differs from candidate")
    canonical, canonical_digest = production_entry.prepare(
        binding, inspection["checkout"]
    )
    if canonical != envelope or canonical_digest != digest(envelope):
        raise Stop("candidate plan differs from current admitted local objects")
    import os
    import stat
    from pathlib import Path

    journal = Path(journal_directory)
    if not journal.is_absolute() or ".." in journal.parts:
        raise Stop("absolute journal path required")
    info = journal.lstat()
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        raise Stop("journal path custody differs")

    launch = {
        "envelope": envelope,
        "approved_envelope_sha256": digest(envelope),
        "checkout": inspection["checkout"],
        "inspection": inspection,
        "hook_receipt": copy.deepcopy(hook_receipt),
        "hook_receipt_sha256": digest(hook_receipt),
        "journal_directory": str(journal),
        "budget_seconds": budget_seconds,
        "source_sha256": policy.source_digest(),
        "policy_sha256": policy.policy_digest(),
    }
    return launch, digest(launch)


def assert_integrity(launch):
    pass
    if (
        launch["source_sha256"] != policy.source_digest()
        or launch["policy_sha256"] != policy.policy_digest()
        or launch["envelope"]["binding"]["source_sha256"] != launch["source_sha256"]
        or launch["envelope"]["binding"]["policy_sha256"] != launch["policy_sha256"]
        or digest(launch["envelope"]) != launch["approved_envelope_sha256"]
        or digest(launch["hook_receipt"]) != launch["hook_receipt_sha256"]
    ):
        raise Stop("launch release or candidate receipt differs")
    installer_owner.components(launch["hook_receipt"])
    if (
        launch["inspection"]["repo"] != launch["envelope"]["binding"]["repo"]
        or launch["inspection"]["repo_id"] != launch["envelope"]["binding"]["repo_id"]
        or launch["inspection"]["checkout"] != launch["checkout"]
        or launch["inspection"]["original_sha256"]
        != launch["hook_receipt"]["wrapper_sha256"]
        or launch["inspection"]["head"] != launch["envelope"]["binding"]["head"]
    ):
        raise Stop("launch installed state binding differs")


def launch_bytes(launch):
    pass

    return json.dumps(launch, sort_keys=True, separators=(",", ":")).encode()
