#!/usr/bin/env python3
"""The published run manifest vectors follow from the reference, and the
check fails on any difference."""

import json
import pathlib
import sys
import unittest

sys.path.insert(0, str(pathlib.Path(__file__).parent))
import run_manifest_reference as ref  # noqa: E402

PUBLISHED = ref.VECTORS.read_text(encoding="utf-8")


class ReferenceTests(unittest.TestCase):
    def test_the_published_vectors_follow_from_the_reference(self):
        self.assertEqual(ref.check(PUBLISHED), [])

    def test_a_changed_digest_is_caught(self):
        changed = json.loads(PUBLISHED)
        changed["vectors"][0]["digest"] = "0" * 64
        problems = ref.check(json.dumps(changed, indent=2) + "\n")
        self.assertEqual(len(problems), 1)
        self.assertIn(changed["vectors"][0]["label"], problems[0])

    def test_a_changed_reason_is_caught(self):
        changed = json.loads(PUBLISHED)
        changed["refused"][0]["reason"] = "malformed"
        self.assertNotEqual(ref.check(json.dumps(changed, indent=2) + "\n"), [])

    def test_a_file_not_written_by_the_reference_is_caught(self):
        self.assertEqual(ref.check(PUBLISHED.replace("\n", "\r\n")), ["the file is not what --write produces"])

    def test_a_lone_surrogate_is_refused(self):
        text = json.dumps(json.loads(PUBLISHED)["vectors"][0]["manifest"])
        self.assertEqual(ref.reason(text.replace("run-2026-11-17-001", "run-\\ud800")), "malformed")
        self.assertEqual(ref.reason("[]"), "malformed")
        self.assertEqual(ref.reason("{"), "malformed")


if __name__ == "__main__":
    unittest.main()
