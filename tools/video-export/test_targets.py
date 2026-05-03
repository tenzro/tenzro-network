"""Pure-Python tests for the video-export harness.

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
        self.assertIn("videomae-base", targets)

    def test_videomae_base_fields(self) -> None:
        t = export.load_targets()["videomae-base"]
        self.assertEqual(t.hf_repo, "MCG-NJU/videomae-base")
        self.assertEqual(t.arch, "videomae")
        self.assertEqual(t.frame_size, 224)
        self.assertEqual(t.num_frames, 16)
        self.assertEqual(t.embedding_dim, 768)

    def test_vjepa2_fields(self) -> None:
        t = export.load_targets()["vjepa-2-1-base"]
        self.assertEqual(t.hf_repo, "facebook/vjepa2")
        self.assertEqual(t.arch, "vjepa2")
        self.assertEqual(t.frame_size, 224)
        self.assertEqual(t.num_frames, 16)
        self.assertEqual(t.embedding_dim, 1024)

    def test_all_targets_have_known_arch(self) -> None:
        targets = export.load_targets()
        for tid, t in targets.items():
            self.assertIn(
                t.arch,
                export.EXPORTERS,
                msg=f"target '{tid}' has arch '{t.arch}' with no exporter",
            )

    def test_dimensions_positive(self) -> None:
        for tid, t in export.load_targets().items():
            self.assertGreater(t.frame_size, 0, msg=tid)
            self.assertGreater(t.num_frames, 0, msg=tid)
            self.assertGreater(t.fps, 0, msg=tid)
            self.assertGreater(t.embedding_dim, 0, msg=tid)


class CliTests(unittest.TestCase):
    def test_unknown_target_returns_2(self) -> None:
        rc = export.main(["nonexistent-target", "--out", "/tmp"])
        self.assertEqual(rc, 2)


if __name__ == "__main__":
    unittest.main()
