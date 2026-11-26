"""check_bindgen_syn.py on lockfiles made for the test.

    python3 scripts/supply-chain/test_check_bindgen_syn.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_bindgen_syn as check  # noqa: E402


def lock(bindgen_syn, pretty_version, pretty_syn):
    return f"""version = 4

[[package]]
name = "bindgen"
version = "0.73.2"
dependencies = ["prettyplease {pretty_version}", "syn {bindgen_syn}"]

[[package]]
name = "prettyplease"
version = "{pretty_version}"
dependencies = ["syn {pretty_syn}"]

[[package]]
name = "syn"
version = "2.0.119"

[[package]]
name = "syn"
version = "3.0.10"
"""


class BindgenSyn(unittest.TestCase):
    def test_bindgen_and_prettyplease_on_one_syn_pass(self):
        self.assertEqual(check.mismatches(lock("2.0.119", "0.2.37", "2.0.119")), [])
        self.assertEqual(check.mismatches(lock("3.0.10", "0.3.0", "3.0.10")), [])

    def test_bindgen_on_syn_3_beside_prettyplease_on_syn_2_is_named(self):
        self.assertEqual(
            check.mismatches(lock("3.0.10", "0.2.37", "2.0.119")),
            [("0.73.2", "3", "prettyplease 0.2.37", "2")],
        )

    def test_a_syn_major_that_cannot_be_read_is_named(self):
        text = '''version = 4

[[package]]
name = "bindgen"
version = "0.73.2"
dependencies = ["prettyplease 0.2.37"]

[[package]]
name = "prettyplease"
version = "0.2.37"
'''
        self.assertEqual(
            check.mismatches(text), [("0.73.2", None, "prettyplease 0.2.37", None)]
        )

    def test_the_repository_lockfiles_agree(self):
        self.assertEqual(check.main(), 0)


if __name__ == "__main__":
    unittest.main()
