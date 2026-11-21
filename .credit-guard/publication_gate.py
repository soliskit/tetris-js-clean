"""Inert publication-boundary candidate. No Git invocation, network or credentials.

Pure inputs must be supplied by the trusted controller, never candidate files.
A successful boundary recheck is NOT publication permission or pack custody proof.
This bounded profile supports new own-work, linear SHA1 branch histories only.
No accepted-history exemption, human/platform exception, tags or custom packs.
Unsupported identities/routes STOP FOR REVIEW, they are not declared malicious.
"""

import hashlib
import re
from dataclasses import dataclass

POLICY_SHA256 = "a5436d175209dd86321f84fef08ad58fddf04af1d7548a9d63115c412667a01e"
ACCEPTANCE_SHA256 = "b81696e725698d5e43cf9c5372b727e2185f85dd2e2eb8bf74ae5800623cc45a"
IDENTITY = b"David Solis <doze.inept.0n@icloud.com>"
HEX = re.compile(r"[a-f0-9]{40}")
ORDINARY = frozenset({"why", "how", "tags"})
MAX_OBJECTS = 20000
MAX_BYTES = 32 * 1024 * 1024


class StopForReview(ValueError):
    pass


def require(condition, reason):
    if not condition:
        raise StopForReview(reason)


@dataclass(frozen=True)
class Object:
    kind: str
    raw: bytes


def oid(obj):
    require(type(obj) is Object and type(obj.raw) is bytes, "raw object required")
    require(obj.kind in {"commit", "tree", "blob"}, "unsupported object kind")
    return hashlib.sha1(
        obj.kind.encode() + b" " + str(len(obj.raw)).encode() + b"\0" + obj.raw
    ).hexdigest()


def full_message(message):
    require(
        message.strip() and b"\0" not in message and b"\r" not in message,
        "empty or ambiguous message",
    )
    try:
        text = message.decode("utf-8", "strict")
    except UnicodeError as error:
        raise StopForReview("unqualified message encoding") from error
    marker = r"(?:co[ -]?author(?:ed)?[ -]?by|claude[ -]?session|reviewed[ -]by|signed[ -]off[ -]by|acked[ -]by|tested[ -]by|assisted[ -]by|generated[ -]by)"
    for original in text.splitlines():
        line = original.strip().casefold()
        for _ in range(20):
            match = re.match(r"([a-z][a-z0-9 _-]{0,80})\s*:\s*(.*)$", line)
            if not match or match[1].strip() not in ORDINARY:
                break
            line = match[2].strip()
        else:
            raise StopForReview("excessive nested fields")
        require(
            not re.search(r"(?:^|[\s;])" + marker + r"\b", line),
            "credit marker requires review",
        )
        match = re.match(r"([a-z][a-z0-9 _-]{0,80})\s*[:=]", line)
        require(not match, "unrecognized message field requires review")


def commit(key, obj, expected_message):
    require(
        HEX.fullmatch(key) and oid(obj) == key and obj.kind == "commit",
        "commit object identity",
    )
    require(
        len(obj.raw) <= 65536 and b"\0" not in obj.raw and b"\r" not in obj.raw,
        "commit size/encoding",
    )
    try:
        header, message = obj.raw.split(b"\n\n", 1)
        rows = header.split(b"\n")
        require(
            len(rows) in {3, 4} and rows[0].startswith(b"tree "),
            "unsupported headers/root or single parent required",
        )
        tree = rows[0][5:].decode("ascii")
        require(HEX.fullmatch(tree), "tree id")
        parent = None
        if len(rows) == 4:
            require(rows[1].startswith(b"parent "), "parent header")
            parent = rows.pop(1)[7:].decode("ascii")
            require(HEX.fullmatch(parent), "parent id")
        for prefix, row in zip((b"author ", b"committer "), rows[1:], strict=True):
            require(row.startswith(prefix), "independent identity header order")
            match = re.fullmatch(
                rb"(.+>) ([0-9]{1,12}) ([+-][0-9]{4})", row[len(prefix) :]
            )
            require(match is not None, "identity/timestamp encoding")
            require(match[1] == IDENTITY, "identity not qualified for own-work route")
            require(
                int(match[3][1:3]) <= 23 and int(match[3][3:]) <= 59, "timestamp zone"
            )
        full_message(message)
        require(
            type(expected_message) is bytes and message == expected_message,
            "complete message differs from controller expectation",
        )
        return tree, parent
    except (UnicodeError, ValueError) as error:
        if isinstance(error, StopForReview):
            raise
        raise StopForReview("malformed commit") from error


@dataclass(frozen=True)
class Binding:
    repository_id: int
    account: str
    remote: str
    ref: str
    old_tip: str | None
    tip: str
    policy_sha256: str = POLICY_SHA256
    acceptance_sha256: str = ACCEPTANCE_SHA256


@dataclass(frozen=True)
class DestinationAdmission:
    """Exact controller-held scope, never proof of a user's approval."""

    repository_id: int
    account: str
    remote: str
    ref: str
    tree: str
    profile: str


@dataclass(frozen=True)
class Expectation:
    binding: Binding
    # Exact commit OID, tree OID, complete message. Held outside worker custody.
    commits: tuple[tuple[str, str, bytes], ...]
    denied: frozenset[str]
    # SHA256 of independently reviewed gate source bytes, checked by controller.
    gate_sha256: str
    destination_admission: DestinationAdmission | None = None


@dataclass(frozen=True)
class Receipt:
    fingerprint: str
    commits: tuple[str, ...]
    objects: tuple[str, ...]
    publication_enabled: bool = False


def assess(objects, expected):
    require(type(expected) is Expectation, "trusted expectation required")
    b = expected.binding
    require(
        type(b) is Binding and type(b.repository_id) is int and b.repository_id > 0,
        "repository immutable id",
    )
    admission = expected.destination_admission
    if admission is None:
        require(
            b.account == "soliskit"
            and re.fullmatch(
                r"https://github\.com/soliskit/(?:Arx|Tetris|tetris-js|pinto|salutant|profile|litmus|foundry|soliskit\.github\.io)\.git",
                b.remote,
            ),
            "unsupported account/destination",
        )
    else:
        require(type(admission) is DestinationAdmission, "typed admission required")
        require(
            type(admission.repository_id) is int
            and admission.repository_id > 0
            and all(
                type(value) is str
                for value in (
                    admission.account,
                    admission.remote,
                    admission.ref,
                    admission.tree,
                    admission.profile,
                )
            ),
            "exact admission field types",
        )
        require(
            admission.profile == "fresh-root-exact-destination-v1"
            and admission.account == "soliskit"
            and re.fullmatch(
                r"https://github\.com/soliskit/[A-Za-z0-9_.-]+\.git",
                admission.remote,
            )
            and (
                admission.repository_id,
                admission.account,
                admission.remote,
                admission.ref,
            )
            == (b.repository_id, b.account, b.remote, b.ref)
            and b.old_tip is None
            and type(expected.commits) is tuple
            and len(expected.commits) == 1
            and HEX.fullmatch(admission.tree)
            and expected.commits[0][1] == admission.tree,
            "unsupported exact fresh-root destination admission",
        )
    require(
        re.fullmatch(r"refs/heads/[A-Za-z0-9][A-Za-z0-9/_-]*", b.ref)
        and "//" not in b.ref
        and not b.ref.endswith("/"),
        "branch ref required",
    )
    require(
        HEX.fullmatch(b.tip) and (b.old_tip is None or HEX.fullmatch(b.old_tip)),
        "exact destination/tip OIDs",
    )
    require(
        b.policy_sha256 == POLICY_SHA256 and b.acceptance_sha256 == ACCEPTANCE_SHA256,
        "pinned policy/acceptance changed",
    )
    require(re.fullmatch(r"[a-f0-9]{64}", expected.gate_sha256), "pinned gate source")
    require(
        type(expected.denied) is frozenset
        and all(HEX.fullmatch(x) for x in expected.denied),
        "denied manifest",
    )
    require(type(objects) is dict and 0 < len(objects) <= MAX_OBJECTS, "object bound")
    require(
        sum(len(o.raw) for o in objects.values() if type(o) is Object) <= MAX_BYTES,
        "byte bound",
    )
    for key, obj in objects.items():
        require(
            type(key) is str and HEX.fullmatch(key) and oid(obj) == key,
            "object identity",
        )
    require(
        type(expected.commits) is tuple and 0 < len(expected.commits) <= 256,
        "bounded controller commit set",
    )
    plan = {key: (tree, msg) for key, tree, msg in expected.commits}
    require(len(plan) == len(expected.commits), "duplicate expected commits")
    reached, history, trees_done = set(), [], set()

    def treewalk(key, ancestors, depth=0):
        require(depth <= 64 and key not in ancestors, "tree depth/cycle")
        require(key in objects and objects[key].kind == "tree", "missing tree")
        if key in trees_done:
            return
        reached.add(key)
        raw, offset, names, previous = objects[key].raw, 0, set(), None
        while offset < len(raw):
            end = raw.find(b"\0", offset)
            require(end >= 0 and end + 21 <= len(raw), "truncated tree")
            entry = raw[offset:end].split(b" ", 1)
            require(len(entry) == 2, "tree entry")
            mode, name = entry
            require(
                mode in {b"40000", b"100644", b"100755", b"120000"},
                "unsupported tree mode/submodule",
            )
            require(
                name
                and b"/" not in name
                and name not in {b".", b".."}
                and name not in names,
                "tree name/duplicate",
            )
            names.add(name)
            order = name + (b"/" if mode == b"40000" else b"\0")
            require(previous is None or previous < order, "noncanonical tree order")
            previous = order
            child = raw[end + 1 : end + 21].hex()
            offset = end + 21
            if mode == b"40000":
                treewalk(child, ancestors | {key}, depth + 1)
            else:
                require(
                    child in objects and objects[child].kind == "blob", "missing blob"
                )
                reached.add(child)
        trees_done.add(key)

    cursor = b.tip
    while cursor is not None:
        require(cursor not in expected.denied, "denied commit before any exemption")
        require(cursor not in history and len(history) < 256, "cycle/commit bound")
        require(
            cursor in objects and cursor in plan,
            "incomplete unexempted ancestry/expectations",
        )
        tree, parent = commit(cursor, objects[cursor], plan[cursor][1])
        require(tree == plan[cursor][0], "tree differs from reviewed intent")
        history.append(cursor)
        reached.add(cursor)
        treewalk(tree, set())
        cursor = parent
    require(set(history) == set(plan), "extra/missing expected commits")
    require(
        b.old_tip is None or b.old_tip in history[1:],
        "non-fast-forward/unchanged branch",
    )
    require(reached == set(objects), "extra or missing upload objects")
    # Canonical length-framed binding includes actual object bytes through verified
    # OIDs and all independently held policy/destination/message expectations.
    values = [
        repr(b).encode(),
        expected.gate_sha256.encode(),
        *[k.encode() for k in sorted(expected.denied)],
        *[repr(row).encode() for row in sorted(expected.commits)],
        *[k.encode() for k in sorted(objects)],
    ]
    # Keep legacy fingerprints byte-identical when no admission exists.
    # A new scope is part of the assessed receipt, not only its manifest hash.
    if admission is not None:
        values.append(repr(admission).encode())
    framed = b"".join(str(len(v)).encode() + b":" + v for v in values)
    return Receipt(
        hashlib.sha256(framed).hexdigest(), tuple(history), tuple(sorted(reached))
    )


def boundary_recheck(
    objects, expected, receipt, observed_binding, observed_gate_sha256
):
    """Last offline boundary check. No callout accepts or performs a push.

    A future controlled transport must supply fresh authenticated remote identity
    and ref state, exact raw objects (replacement/graft/shallow bypass disabled),
    and enforce this check plus the exact upload set without reopening worker data.
    These source/transport/custody properties are NOT proved by this pure function.
    """
    require(
        type(receipt) is Receipt and not receipt.publication_enabled,
        "receipt type/state",
    )
    require(observed_binding == expected.binding, "destination state/binding changed")
    require(observed_gate_sha256 == expected.gate_sha256, "gate source changed")
    current = assess(objects, expected)
    require(current == receipt, "candidate/policy/message/ref/object-set changed")
    return current
