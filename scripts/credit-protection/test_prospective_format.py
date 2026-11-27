import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from production_policy import issuer, policy


class Graph:
    def __init__(self, commits):
        self.commits = commits
        self.reads = []

    def commit_json(self, sha):
        self.reads.append(sha)
        return self.commits[sha]


def entry(message, parents=()):
    name, email = policy.REQUIRED_IDENT
    return {
        "author": {"name": name, "email": email},
        "committer": {"name": name, "email": email},
        "message": message,
        "parents": [{"sha": sha} for sha in parents],
    }


class ProspectiveFormatTests(unittest.TestCase):
    def setUp(self):
        self.historical = min(policy.HISTORICAL_FORMAT_OBJECTS)
        self.future = "f" * 40
        self.short = "Preserve the reviewed historical subject\n"
        self.valid = "Check message format\n\nWhy: Prevent drift.\nHow: Check each message.\nTags: tooling\n"

    def test_new_messages_need_each_section_but_allow_following_line_values(self):
        policy.check_message(self.valid, self.future)
        multiline = self.valid
        for section in policy.REQUIRED_SECTIONS:
            multiline = multiline.replace(section + " ", section + "\n")
        policy.check_message(multiline, self.future)
        for separator in ("\r\n", "\u2028", "\u2029", "\x85", "\v"):
            with self.assertRaises(ValueError):
                policy.check_message(self.valid.replace("\n", separator), self.future)
        with self.assertRaises(ValueError):
            policy.check_message(self.short, self.future)
        for section in policy.REQUIRED_SECTIONS:
            line = next(x for x in self.valid.splitlines() if x.startswith(section))
            for changed in (
                self.valid.replace(line, ""),
                self.valid.replace(line, section),
                self.valid + section + " duplicate\n",
            ):
                with (
                    self.subTest(section=section, changed=changed),
                    self.assertRaises(ValueError),
                ):
                    policy.check_message(changed, self.future)

    def test_historical_format_does_not_exempt_attribution_or_project_checks(self):
        policy.check_message(self.short, self.historical)
        for tail in (
            "Co-authored-by: Other <other@example.invalid>\n",
            "Why: Signed-off-by: Other\n",
            "Claude-Session: bad\n",
            "Unknown-credit: bad\n",
        ):
            with self.subTest(tail=tail):
                with self.assertRaises(ValueError):
                    policy.check_message(self.short + tail, self.historical)

    def test_historical_objects_still_have_both_identities_and_parents_checked(self):
        for role in ("author", "committer"):
            graph = Graph(
                {
                    self.future: entry(self.valid, (self.historical,)),
                    self.historical: entry(self.short),
                }
            )
            graph.commits[self.historical][role] = {
                "name": "Other",
                "email": "other@example.invalid",
            }
            with self.assertRaises(issuer.Refusal):
                issuer.admit(graph, self.future)
            self.assertIn(self.historical, graph.reads)
        graph = Graph(
            {
                self.future: entry(self.valid, (self.historical,)),
                self.historical: entry(self.short),
            }
        )
        self.assertEqual(
            set(issuer.admit(graph, self.future)), {self.future, self.historical}
        )
        with self.assertRaises(issuer.Refusal):
            issuer.issue(
                graph, self.future, policy.TARGET_REPOSITORY_ID + 1, self.historical
            )
        with self.assertRaises(issuer.Refusal):
            issuer.issue(
                graph, self.future, policy.TARGET_REPOSITORY_ID, self.historical, 3
            )
        receipt = issuer.issue(
            graph, self.future, policy.TARGET_REPOSITORY_ID, self.historical
        )
        self.assertEqual(receipt.epoch, 4)


if __name__ == "__main__":
    unittest.main()
