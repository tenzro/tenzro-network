"""Pure-Python tests for the ts-export harness.

These run without torch/onnx/transformers — they only validate the
target registry parsing and CLI dispatch logic. The actual export
functions need a full ML stack and a network connection to HF, so
they're exercised in CI via the workflow, not in unit tests.

Run with: `python -m unittest test_targets.py` from this directory.
"""

from __future__ import annotations

import unittest
from pathlib import Path

# Import without triggering torch — `export.py` imports torch at top
# level. Pre-import unittest.mock to stub torch if absent so the test
# module loads on any machine.
import sys
import types

if "torch" not in sys.modules:
    sys.modules["torch"] = types.ModuleType("torch")  # type: ignore

import export  # noqa: E402


class LoadTargetsTests(unittest.TestCase):
    def test_loads_default_targets(self) -> None:
        targets = export.load_targets()
        self.assertGreater(len(targets), 0)
        self.assertIn("timesfm-2.5-200m", targets)

    def test_timesfm_fields(self) -> None:
        t = export.load_targets()["timesfm-2.5-200m"]
        self.assertEqual(t.hf_repo, "google/timesfm-2.5-200m-pytorch")
        self.assertEqual(t.arch, "timesfm")
        self.assertEqual(t.license, "Apache-2.0")
        self.assertEqual(t.context_length, 2048)
        self.assertEqual(t.max_horizon, 128)
        self.assertEqual(t.n_quantiles, 10)

    def test_all_targets_have_known_arch(self) -> None:
        targets = export.load_targets()
        for tid, t in targets.items():
            self.assertIn(
                t.arch,
                export.EXPORTERS,
                msg=f"target '{tid}' has arch '{t.arch}' with no exporter",
            )

    def test_all_licenses_are_redistributable(self) -> None:
        # We only export Apache-2.0 / MIT licensed weights. Anything else
        # would land us in murky redistribution territory and is rejected
        # by policy.
        allowed = {"Apache-2.0", "MIT"}
        for tid, t in export.load_targets().items():
            self.assertIn(
                t.license,
                allowed,
                msg=f"target '{tid}' license '{t.license}' is not redistributable",
            )

    def test_horizons_and_contexts_positive(self) -> None:
        for tid, t in export.load_targets().items():
            self.assertGreater(t.context_length, 0, msg=tid)
            self.assertGreater(t.max_horizon, 0, msg=tid)
            self.assertGreaterEqual(t.n_quantiles, 0, msg=tid)


class CliTests(unittest.TestCase):
    def test_unknown_target_returns_2(self) -> None:
        rc = export.main(["nonexistent-target", "--out", "/tmp"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
