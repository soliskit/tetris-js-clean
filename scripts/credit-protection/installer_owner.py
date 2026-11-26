import copy
import hashlib
import json
from pathlib import Path

import hook_installer
import installer_entry
from production_policy import policy


class Stop(Exception):
    pass


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def components(receipt):
    original, original_mode = hook_installer.read_owned(receipt["saved_original"])
    validator, validator_mode = hook_installer.read_owned(receipt["validator"])
    if (
        hook_installer.sha(original) != receipt["original_sha256"]
        or hook_installer.sha(validator) != receipt["validator_sha256"]
        or not original_mode & 0o100
        or not validator_mode & 0o100
    ):
        raise Stop("reviewed hook chain components differ")
    wrapper = hook_installer.chain_source(
        receipt["saved_original"],
        receipt["original_sha256"],
        receipt["validator"],
        receipt["validator_sha256"],
    )
    if hook_installer.sha(wrapper) != receipt["wrapper_sha256"]:
        raise Stop("wrapper does not encode reviewed hook chain")
    return wrapper


def prepare(operation, checkout, repo, repo_id, receipt, read_repository):
    if operation not in ("install", "rollback"):
        raise Stop("unsupported installer operation")
    receipt = copy.deepcopy(receipt)
    wrapper = components(receipt)
    if operation == "install":
        current = installer_entry.inspect(checkout, repo, repo_id, read_repository)
        if (
            receipt["hook"] != current["hook"]
            or receipt["original_sha256"] != current["original_sha256"]
            or receipt["original_mode"] != current["original_mode"]
        ):
            raise Stop("staging source does not match selected checkout")

        required = Path(policy.__file__).resolve().with_name("pre-push").read_bytes()
        if receipt["validator_sha256"] != hook_installer.sha(required):
            raise Stop("added validator does not match production policy")
    else:
        current = installer_entry.prepare_rollback(
            checkout, repo, repo_id, receipt, read_repository
        )
    packet = {
        "operation": operation,
        "inspection": current,
        "receipt": receipt,
        "receipt_sha256": digest(receipt),
        "source_sha256": policy.source_digest(),
        "policy_sha256": policy.policy_digest(),
        "replacement_sha256": (
            hook_installer.sha(wrapper)
            if operation == "install"
            else receipt["original_sha256"]
        ),
    }
    return packet, digest(packet)


def execute(packet, expected_digest, verify_original_approval, read_repository, record):
    pass

    packet = copy.deepcopy(packet)
    if digest(packet) != expected_digest:
        raise Stop("installer packet differs from review")
    if verify_original_approval(packet, expected_digest) is not True:
        raise Stop("original approval does not cover exact installer packet")
    if digest(packet) != expected_digest:
        raise Stop("authority callback changed installer packet")
    receipt = packet["receipt"]
    inspection = packet["inspection"]
    now, now_digest = prepare(
        packet["operation"],
        inspection["checkout"],
        inspection["repo"],
        inspection["repo_id"],
        receipt,
        read_repository,
    )
    if now != packet or now_digest != expected_digest:
        raise Stop("installer state or source changed after review")
    record(
        "installer_approved_pending",
        {
            "packet_sha256": expected_digest,
            "receipt_sha256": packet["receipt_sha256"],
            "operation": packet["operation"],
            "repo": inspection["repo"],
            "repo_id": inspection["repo_id"],
            "before": inspection["original_sha256"],
            "after": packet["replacement_sha256"],
        },
    )

    def exact_inner(current, selected_receipt):
        return current == inspection and selected_receipt == receipt

    if packet["operation"] == "install":
        outcome = installer_entry.install(
            inspection,
            receipt,
            components(receipt),
            exact_inner,
            read_repository,
            record,
        )
    else:
        outcome = installer_entry.rollback(
            inspection, receipt, exact_inner, read_repository, record
        )
    record(
        "installer_approved_confirmed",
        {"packet_sha256": expected_digest, "outcome": outcome},
    )
    return outcome
