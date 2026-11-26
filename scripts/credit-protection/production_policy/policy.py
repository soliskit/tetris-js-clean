import hashlib
import json
import re

ISSUER_VERSION = "credit-issuer production 0.5.0"
EPOCH = 3

REQUIRED_NAME = "David Solis"
REQUIRED_EMAIL = "doze.inept.0n@icloud.com"
REQUIRED_IDENT = (REQUIRED_NAME, REQUIRED_EMAIL)

REQUIRED_SECTIONS = ("Why:", "How:", "Tags:")


PROHIBITED_ALTERNATIVES = [
    ("co-authored-trailer", r"^co-authored-by\s*:", r"^co-authored-by[[:space:]]*:"),
    ("generated-with-trailer", r"^generated-with\s*:", r"^generated-with[[:space:]]*:"),
    ("assisted-by-trailer", r"^assisted-by\s*:", r"^assisted-by[[:space:]]*:"),
    ("generated-phrase", r"generated (with|by)\b", r"generated (with|by)\b"),
    ("bracket-generated", r"\[generated", r"\[generated"),
    (
        "by-agent-name",
        r"\bby (claude|cursor|copilot|chatgpt|openai|anthropic|github copilot)\b",
        r"\bby (claude|cursor|copilot|chatgpt|openai|anthropic|github copilot)\b",
    ),
    (
        "agent-authored",
        r"\b(claude|cursor|copilot|chatgpt)[ -]?(co-?authored|generated)\b",
        r"\b(claude|cursor|copilot|chatgpt)[ -]?(co-?authored|generated)\b",
    ),
    (
        "vendor-noreply",
        r"noreply@(anthropic|openai)\.",
        r"noreply@(anthropic|openai)\.",
    ),
    ("robot-emoji", "\U0001f916", "\U0001f916"),
]

PROHIBITED_CREDIT = re.compile(
    "|".join(f"({p})" for _i, p, _s in PROHIBITED_ALTERNATIVES),
    re.IGNORECASE | re.MULTILINE | re.ASCII,
)


MAX_PARENTS = None
MAX_COMMITS = 10000


HEADER_ORDER = ("tree", "parent", "author", "committer")
OID_RE = re.compile(r"^[0-9a-f]{40}$")
IDENT_LINE_RE = re.compile(r"^(.*?) <([^<>]+)> (\d+) ([+-]\d{4})$")


def context_name(epoch=EPOCH):
    pass
    return f"Credit ancestry v2-e{epoch}"


def policy_config(epoch=EPOCH):
    return {
        "issuer_version": ISSUER_VERSION,
        "epoch": epoch,
        "required_author": list(REQUIRED_IDENT),
        "required_committer": list(REQUIRED_IDENT),
        "required_sections": list(REQUIRED_SECTIONS),
        "prohibited_ids": [i for i, _p, _s in PROHIBITED_ALTERNATIVES],
        "max_parents": MAX_PARENTS,
        "max_commits": MAX_COMMITS,
        "header_order": list(HEADER_ORDER),
        "base_rule": "full-closure-walk-no-baseline-exemption",
    }


def policy_digest(epoch=EPOCH):
    return hashlib.sha256(
        json.dumps(policy_config(epoch), sort_keys=True).encode()
    ).hexdigest()


def code_digest():
    pass

    import pathlib

    return hashlib.sha256(pathlib.Path(__file__).read_bytes()).hexdigest()


def check_message(message):
    pass
    for tag in REQUIRED_SECTIONS:
        lines = [line for line in message.split("\n") if line.startswith(tag)]

        if not lines or not lines[0][len(tag) :].strip(" \t\r\n"):
            raise ValueError(f"message missing or empty {tag}")
    m = PROHIBITED_CREDIT.search(message)
    if m:
        raise ValueError(f"prohibited credit/attribution: {m.group(0)!r}")


def source_digests():
    pass
    import pathlib

    root = pathlib.Path(__file__).resolve().parent.parent
    paths = sorted(root.glob("*.py"))
    for directory in ("baseline", "production_policy", "project_bootstrap"):
        paths.extend(sorted((root / directory).glob("*.py")))
        if (root / directory / "pre-push").is_file():
            paths.append(root / directory / "pre-push")
        paths.extend(sorted((root / directory).glob("*.json")))
    return {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in paths
    }


def source_digest():
    pass
    return hashlib.sha256(
        json.dumps(source_digests(), sort_keys=True).encode()
    ).hexdigest()
