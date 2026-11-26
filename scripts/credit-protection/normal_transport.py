from pathlib import Path


class Stop(Exception):
    pass


ASKPASS_SOURCE = b"""#!/usr/bin/python3
import os, sys
prompt = sys.argv[1].lower() if len(sys.argv) > 1 else ""
if "username" in prompt:
    print("x-access-token")
elif "password" in prompt:
    print(os.environ["CREDIT_EPHEMERAL_TOKEN"])
else:
    sys.exit(1)
"""


def push(binding, token, remaining, checkout, hook_receipt, askpass_path):
    from baseline import httpapi, publisher

    deadline = httpapi.Client(budget_seconds=remaining)
    from hook_installer import read_owned, sha

    root = Path(checkout).resolve(strict=True)
    remote = "https://github.com/" + binding["repo"] + ".git"
    ref = binding["ref"][len("refs/heads/") :]

    helper, mode = read_owned(askpass_path)
    if helper != ASKPASS_SOURCE or mode != 0o700:
        raise Stop("credential helper differs from reviewed source")
    publisher._verify_effective_hook(
        str(root),
        hook_receipt["hook"],
        publisher.approved_env(),
        deadline,
        approved_hook_sha256=hook_receipt["wrapper_sha256"],
    )
    for key, expected in (
        ("saved_original", "original_sha256"),
        ("validator", "validator_sha256"),
    ):
        raw, mode = read_owned(hook_receipt[key])
        if sha(raw) != hook_receipt[expected] or not mode & 0o100:
            raise Stop("installed hook chain differs")
    env = publisher.approved_env(binding["old"], binding["head"], remote, ref)
    env.update(
        GIT_ASKPASS=str(askpass_path),
        GIT_TERMINAL_PROMPT="0",
        GIT_NO_REPLACE_OBJECTS="1",
        CREDIT_EPHEMERAL_TOKEN=token,
    )

    commands = [
        ["rev-parse", binding["ref"]],
        ["merge-base", "--is-ancestor", binding["old"], binding["head"]]
        if binding["old"] != "0" * 40
        else None,
    ]
    for args in commands:
        if args is None:
            continue
        code, output, _ = publisher._git(args, str(root), env, deadline, cap=30)
        if code or (args[0] == "rev-parse" and output.strip() != binding["head"]):
            raise Stop("local approved candidate/predecessor differs")

    code, _, _ = publisher._git(
        [
            "-c",
            "credential.helper=",
            "-c",
            "push.followTags=false",
            "-c",
            "push.mirror=false",
            "push",
            "--no-tags",
            remote,
            binding["ref"] + ":" + binding["ref"],
        ],
        str(root),
        env,
        deadline,
        cap=120,
    )
    if code:
        raise Stop("normal hooked Git push failed")
