#!/usr/bin/env python3
"""Builds that hand ort-sys a prebuilt ONNX Runtime link it dynamically: python3 scripts/release/test_onnx_runtime_link.py

ort-sys (through praecise-onnx) reads ORT_LIB_LOCATION and, from 2.0.0-rc.11 on, links that prefix statically
unless ORT_PREFER_DYNAMIC_LINK=1 is set; a prefix that holds the shared libraries only (every CUDA ONNX Runtime the
builds use) then fails the build with "ort-sys could not link to the ONNX Runtime build". The dynamic link searches
the directory it is given and nothing under it, so a build that holds a prefix (its libraries in lib/) hands ort-sys
that lib/ directory as ORT_LIB_PATH, which ort-sys reads before ORT_LIB_LOCATION.
"""
import os, re, subprocess, unittest

SRC = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def tracked_files_setting_the_prefix():
    r = subprocess.run(["git", "-C", SRC, "grep", "-l", "-E", r"ORT_LIB_LOCATION=", "--", ":!*.md", ":!*.py"],
                       capture_output=True, text=True)
    return [f for f in r.stdout.split() if f]


class OnnxRuntimeLink(unittest.TestCase):
    def test_the_lockfile_links_an_ort_sys_that_needs_the_dynamic_link_asked_for(self):
        lock = open(os.path.join(SRC, "Cargo.lock")).read()
        m = re.search(r'name = "ort-sys"\nversion = "2\.0\.0-rc\.(\d+)"', lock)
        self.assertIsNotNone(m, "ort-sys 2.0.0-rc.N in Cargo.lock")
        self.assertGreaterEqual(int(m.group(1)), 11)

    def test_every_build_that_sets_the_prefix_asks_for_the_dynamic_link(self):
        files = tracked_files_setting_the_prefix()
        self.assertIn("Dockerfile.cuda", files)
        self.assertIn("scripts/build-cuda-native.sh", files)
        for f in files:
            text = open(os.path.join(SRC, f)).read()
            for line in text.splitlines():
                if re.search(r"(export |-E |^\s*)ORT_LIB_LOCATION=", line) and not line.lstrip().startswith("#"):
                    self.assertTrue("ORT_PREFER_DYNAMIC_LINK=1" in text,
                                    f"{f} sets ORT_LIB_LOCATION without ORT_PREFER_DYNAMIC_LINK=1")
                    self.assertTrue(re.search(r"ORT_LIB_PATH=\S*ORT_LIB_LOCATION\S*/lib|ORT_LIB_PATH=/opt/onnxruntime/lib", text),
                                    f"{f} hands ort-sys the prefix, not its lib/ directory (ORT_LIB_PATH)")


if __name__ == "__main__":
    unittest.main()
