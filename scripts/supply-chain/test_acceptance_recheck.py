"""The acceptance recheck (acceptance-recheck.py): an accepted advisory needs an owner and a recheck day
that has not passed, and the repository's own list names both for every entry.

    python3 scripts/supply-chain/test_acceptance_recheck.py
"""
import datetime
import importlib.util
import os
import subprocess
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
TOOL = os.path.join(HERE, "acceptance-recheck.py")
spec = importlib.util.spec_from_file_location("acceptance_recheck", TOOL)
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

DAY = datetime.date(2026, 11, 16)


def config(*entries):
    body = "".join(f"  # ---\n  # {c}\n  \"{i}\",\n" for i, c in entries)
    return f"# header\n[advisories]\nignore = [\n{body}]\n"


class AcceptanceRecheck(unittest.TestCase):
    def test_a_current_acceptance_passes(self):
        text = config(("RUSTSEC-2023-0071", "OWNER: release owner. RECHECK BY: 2026-11-16."))
        self.assertEqual(tool.faults(text, DAY), [])

    def test_a_passed_recheck_day_is_a_fault(self):
        text = config(("RUSTSEC-2023-0071", "OWNER: release owner. RECHECK BY: 2026-11-15."))
        self.assertEqual(
            tool.faults(text, DAY),
            ["RUSTSEC-2023-0071: recheck was due 2026-11-15; assess it again and set a new day"],
        )

    def test_an_acceptance_without_owner_or_day_is_a_fault(self):
        text = config(
            ("RUSTSEC-2023-0071", "RE-ASSESS IF: something changes."),
            ("RUSTSEC-2026-0118", "OWNER: release owner. RECHECK BY: soon."),
        )
        self.assertEqual(
            tool.faults(text, DAY),
            [
                "RUSTSEC-2023-0071: no OWNER",
                "RUSTSEC-2023-0071: no RECHECK BY day",
                "RUSTSEC-2026-0118: RECHECK BY soon is not a day (YYYY-MM-DD)",
            ],
        )

    def test_an_owner_and_day_do_not_carry_to_the_next_entry(self):
        text = config(
            ("RUSTSEC-2023-0071", "OWNER: release owner. RECHECK BY: 2027-01-31."),
            ("RUSTSEC-2026-0118", "RE-ASSESS IF: something changes."),
        )
        self.assertEqual(
            tool.faults(text, DAY),
            ["RUSTSEC-2026-0118: no OWNER", "RUSTSEC-2026-0118: no RECHECK BY day"],
        )

    def test_an_owner_may_contain_a_full_stop(self):
        m = tool.OWNER.search("  # OWNER: release owner, St. Elsewhere. RECHECK BY: 2027-01-31.")
        self.assertEqual(m.group(1), "release owner, St. Elsewhere")
        self.assertEqual(tool.OWNER.search("  # OWNER: release owner.").group(1), "release owner")
        text = config(("RUSTSEC-2023-0071", "OWNER: . RECHECK BY: 2027-01-31."))
        self.assertEqual(tool.faults(text, DAY), ["RUSTSEC-2023-0071: no OWNER"])

    def test_an_id_of_another_form_still_needs_an_owner_and_a_day(self):
        for adv in ("GHSA-3rjw-m598-pq24", "RUSTSEC-2026-12345"):
            text = config((adv, "RE-ASSESS IF: something changes."))
            self.assertEqual(tool.faults(text, DAY), [f"{adv}: no OWNER", f"{adv}: no RECHECK BY day"])
            text = config((adv, "OWNER: release owner. RECHECK BY: 2027-01-31."))
            self.assertEqual(tool.faults(text, DAY), [])

    def test_an_entry_the_comment_reader_cannot_follow_is_a_fault(self):
        current = "  # OWNER: release owner. RECHECK BY: 2027-01-31.\n"
        forms = {
            "a list on one line": 'ignore = ["RUSTSEC-2023-0071"]\n',
            "a comment after the id": 'ignore = [\n' + current + '  "RUSTSEC-2023-0071", # accepted\n]\n',
            "two ids on a line": 'ignore = [\n' + current + '  "RUSTSEC-2023-0071", "RUSTSEC-2026-0118",\n]\n',
            "the bracket on the first id's line": 'ignore = ["RUSTSEC-2023-0071",\n' + current + '  "RUSTSEC-2026-0118",\n]\n',
        }
        for name, body in forms.items():
            with self.subTest(name):
                found = tool.faults("[advisories]\n" + body, DAY)
                self.assertIn("RUSTSEC-2023-0071: not written alone on its line under its own comment", found)

    def test_the_command_exits_1_on_a_fault_and_0_when_current(self):
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, "audit.toml")
            with open(path, "w") as f:
                f.write(config(("RUSTSEC-2023-0071", "OWNER: release owner. RECHECK BY: 2026-12-01.")))
            run = lambda day: subprocess.run(
                [sys.executable, "-I", TOOL, "--today", day, path], capture_output=True, text=True
            )
            self.assertEqual(run("2026-12-01").returncode, 0)
            late = run("2026-12-02")
            self.assertEqual(late.returncode, 1, late.stdout)
            self.assertIn("BLOCKED: accepted advisory RUSTSEC-2023-0071", late.stdout)

    def test_every_acceptance_in_this_repository_is_current(self):
        path = os.path.join(HERE, "..", "..", ".cargo", "audit.toml")
        with open(path, encoding="utf-8") as f:
            text = f.read()
        self.assertEqual(len(list(tool.acceptances(text))), text.count('"RUSTSEC-'))
        # On a fixed day: the list is judged as written, and this test does not
        # start failing by itself when a recheck day arrives.
        self.assertEqual(tool.faults(text, DAY), [])


if __name__ == "__main__":
    unittest.main()
