import hashlib
import json
import re

import object_plan


class Stop(Exception):
    pass


def digest(value):
    return hashlib.sha256(
        json.dumps(value, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def prepare(binding, read_object, admit_head):
    required = {
        "repo",
        "repo_id",
        "ref",
        "head",
        "old",
        "app_id",
        "installation_id",
        "policy_sha256",
        "source_sha256",
    }
    if set(binding) != required:
        raise Stop("publication binding fields differ")
    if (
        not re.fullmatch(r"soliskit/[A-Za-z0-9_.-]+", binding["repo"])
        or not binding["ref"].startswith("refs/heads/")
        or binding["ref"] == "refs/heads/"
    ):
        raise Stop("invalid destination")
    for key in ("head", "old"):
        if not re.fullmatch(r"[0-9a-f]{40}", binding[key]):
            raise Stop("invalid commit binding")
    for key in ("repo_id", "app_id", "installation_id"):
        if type(binding[key]) is not int or binding[key] <= 0:
            raise Stop("invalid numeric identity")
    for key in ("policy_sha256", "source_sha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", binding[key]):
            raise Stop("invalid source/policy binding")
    objects = object_plan.plan(binding["head"], read_object, admit_head)
    envelope = {"binding": dict(binding), "objects": objects}
    return envelope, digest(envelope)


def execute(envelope, approved_digest, authority, journal, remote):
    pass

    envelope = json.loads(json.dumps(envelope))
    if digest(envelope) != approved_digest:
        raise Stop("approved publication bytes changed")
    authority.assert_approved(envelope, approved_digest)
    if digest(envelope) != approved_digest:
        raise Stop("approval callback changed publication bytes")
    binding = envelope["binding"]
    journal.assert_no_pending()
    remote.assert_identity(binding)
    remote.assert_ref(binding["ref"], binding["old"])
    remote.revalidate_local_admission(binding)

    journal.sync("publication_started", {"digest": approved_digest, "binding": binding})
    uploaded = []
    try:
        for item in envelope["objects"]:
            state = remote.exact_object_state(item["kind"], item["sha"])
            if state == "present":
                continue
            if state != "absent":
                raise Stop("object existence unverified")
            journal.sync(
                "object_request_pending", {"sha": item["sha"], "kind": item["kind"]}
            )
            response = remote.upload_object(item["kind"], item["body"])
            if response.get("sha") != item["sha"]:
                raise Stop("uploaded object id mismatch")
            uploaded.append(item["sha"])
            journal.sync("object_request_confirmed", {"sha": item["sha"]})
        remote.assert_identity(binding)
        remote.assert_ref(binding["ref"], binding["old"])
        remote.revalidate_local_admission(binding)
        journal.sync("check_request_pending", {"head": binding["head"]})
        check_id = remote.publish_admitted_check(binding)
        remote.confirm_check(binding, check_id)
        journal.sync("check_confirmed", {"id": check_id})
        journal.sync("push_pending", {"ref": binding["ref"]})
        remote.normal_hooked_push(binding)
        remote.assert_ref(binding["ref"], binding["head"])
        remote.confirm_check(binding, check_id)
        journal.sync(
            "publication_reconciled", {"check_id": check_id, "uploaded": uploaded}
        )
        return {"state": "published", "check_id": check_id, "uploaded": uploaded}
    except BaseException:
        raise
