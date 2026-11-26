import base64
import datetime
import hashlib
import re


class Refusal(Exception):
    pass


def object_id(kind, raw):
    return hashlib.sha1(
        kind.encode() + b" " + str(len(raw)).encode() + b"\0" + raw
    ).hexdigest()


def identity(value):
    match = re.fullmatch(
        rb"([^<>\n]+) <([^<>\n]+)> ([0-9]+) ([+-])([0-9]{2})([0-9]{2})", value
    )
    if not match:
        raise Refusal("unsupported commit identity serialization")
    name, email, timestamp, sign, hours, minutes = match.groups()
    offset = int(hours) * 60 + int(minutes)
    if int(minutes) >= 60 or offset > 14 * 60:
        raise Refusal("invalid timezone")
    if sign == b"-":
        offset = -offset
    zone = datetime.timezone(datetime.timedelta(minutes=offset))
    date = datetime.datetime.fromtimestamp(int(timestamp), zone).isoformat(
        timespec="seconds"
    )
    return {"name": name.decode("utf-8"), "email": email.decode("utf-8"), "date": date}


def serialize_commit_body(body):
    def ident(person):
        date = datetime.datetime.fromisoformat(person["date"])
        if date.tzinfo is None or date.microsecond:
            raise Refusal("commit date is not an exact zoned second")
        offset = int(date.utcoffset().total_seconds())
        if offset % 60:
            raise Refusal("subminute timezone")
        sign = "+" if offset >= 0 else "-"
        minutes = abs(offset) // 60
        zone = sign + str(minutes // 60).zfill(2) + str(minutes % 60).zfill(2)
        return (
            person["name"]
            + " <"
            + person["email"]
            + "> "
            + str(int(date.timestamp()))
            + " "
            + zone
        ).encode("utf-8")

    lines = [b"tree " + body["tree"].encode("ascii")]
    lines.extend(b"parent " + parent.encode("ascii") for parent in body["parents"])
    lines.extend(
        [b"author " + ident(body["author"]), b"committer " + ident(body["committer"])]
    )
    return b"\n".join(lines) + b"\n\n" + body["message"].encode("utf-8")


def serialize_tree_body(body):
    names, previous, raw = set(), None, bytearray()
    mode_map = {
        "040000": b"40000",
        "100644": b"100644",
        "100755": b"100755",
        "120000": b"120000",
    }
    for entry in body["tree"]:
        name = entry["path"].encode("utf-8")
        if (
            name in names
            or name in (b".", b"..")
            or not name
            or b"/" in name
            or b"\0" in name
        ):
            raise Refusal("noncanonical tree path")
        names.add(name)
        sort_key = name + (b"/" if entry["type"] == "tree" else b"\0")
        if previous is not None and sort_key <= previous:
            raise Refusal("noncanonical tree order")
        previous = sort_key
        raw.extend(
            mode_map[entry["mode"]] + b" " + name + b"\0" + bytes.fromhex(entry["sha"])
        )
    return bytes(raw)


def plan(head, read_object, admit_head, max_objects=10000, max_bytes=64 << 20):
    pass

    admitted = set(admit_head(head))
    if head not in admitted:
        raise Refusal("head missing from admission")
    seen, active, ordered, kinds = set(), set(), [], {}
    total = 0

    def enter(sha, expected_kind=None):
        nonlocal total
        if sha in seen:
            if expected_kind is not None and kinds[sha] != expected_kind:
                raise Refusal("dependency type mismatch")
            return
        if sha in active or not re.fullmatch(r"[0-9a-f]{40}", sha):
            raise Refusal("cycle or invalid object id")
        if len(seen) + len(active) >= max_objects:
            raise Refusal("object count cap")
        active.add(sha)
        kind, raw = read_object(sha)
        if expected_kind is not None and kind != expected_kind:
            raise Refusal("dependency type mismatch")
        kinds[sha] = kind
        if not isinstance(raw, bytes) or object_id(kind, raw) != sha:
            raise Refusal("object content/id mismatch")
        total += len(raw)
        if total > max_bytes:
            raise Refusal("object bytes cap")
        dependencies = []
        if kind == "blob":
            body = {
                "content": base64.b64encode(raw).decode("ascii"),
                "encoding": "base64",
            }
        elif kind == "tree":
            entries, pos = [], 0
            while pos < len(raw):
                space = raw.index(b" ", pos)
                nul = raw.index(b"\0", space + 1)
                mode, name = raw[pos:space], raw[space + 1 : nul]
                oid = raw[nul + 1 : nul + 21]
                if len(oid) != 20 or not name or b"/" in name:
                    raise Refusal("unsupported tree entry")
                modes = {
                    b"40000": ("040000", "tree"),
                    b"100644": ("100644", "blob"),
                    b"100755": ("100755", "blob"),
                    b"120000": ("120000", "blob"),
                }
                if mode not in modes:
                    raise Refusal("unsupported tree mode, including gitlinks")
                rest_mode, entry_kind = modes[mode]
                child = oid.hex()
                child_kind, _ = read_object(child)
                if child_kind != entry_kind:
                    raise Refusal("tree child type mismatch")
                entries.append(
                    {
                        "path": name.decode("utf-8"),
                        "mode": rest_mode,
                        "type": entry_kind,
                        "sha": child,
                    }
                )
                dependencies.append((child, entry_kind))
                pos = nul + 21
            body = {"tree": entries}
            if serialize_tree_body(body) != raw:
                raise Refusal("tree body/raw mismatch before upload")
        elif kind == "commit":
            if sha not in admitted:
                raise Refusal("unadmitted commit")
            header, separator, message = raw.partition(b"\n\n")
            if not separator:
                raise Refusal("commit message delimiter absent")
            fields = [line.split(b" ", 1) for line in header.split(b"\n")]
            if any(len(pair) != 2 for pair in fields):
                raise Refusal("malformed commit")
            names = [key for key, _ in fields]
            if (
                len(names) < 3
                or names[0] != b"tree"
                or names[-2:] != [b"author", b"committer"]
                or any(name != b"parent" for name in names[1:-2])
            ):
                raise Refusal("unsupported canonical commit shape")
            values = dict(fields)
            tree = values[b"tree"].decode("ascii")
            parents = [
                value.decode("ascii") for key, value in fields if key == b"parent"
            ]
            dependencies = [(tree, "tree")] + [(parent, "commit") for parent in parents]
            body = {
                "message": message.decode("utf-8"),
                "tree": tree,
                "parents": parents,
                "author": identity(values[b"author"]),
                "committer": identity(values[b"committer"]),
            }
            if serialize_commit_body(body) != raw:
                raise Refusal("commit body/raw mismatch before upload")
        else:
            raise Refusal("unsupported object kind")
        return dependencies, {
            "sha": sha,
            "kind": kind,
            "body": body,
            "raw_sha256": hashlib.sha256(raw).hexdigest(),
        }

    stack = [("enter", head, "commit", None)]
    try:
        while stack:
            action, sha, expected_kind, item = stack.pop()
            if action == "exit":
                active.remove(sha)
                seen.add(sha)
                ordered.append(item)
                continue
            if sha in seen:
                if kinds[sha] != expected_kind:
                    raise Refusal("dependency type mismatch")
                continue
            dependencies, item = enter(sha, expected_kind)
            stack.append(("exit", sha, expected_kind, item))
            for dependency, dependency_kind in reversed(dependencies):
                stack.append(("enter", dependency, dependency_kind, None))
    except (UnicodeDecodeError, ValueError, OverflowError, IndexError, KeyError):
        raise Refusal("unsupported or malformed object serialization") from None
    return ordered
