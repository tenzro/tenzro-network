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


def grep_tree(pattern, keep):
    """`path:line:text` for every line of a source file matching pattern; keep(path) picks the files. Reads
    the checkout through git when it is one, else walks the tree (a gate host gets an export with no .git)."""
    if os.path.isdir(os.path.join(SRC, ".git")) or os.path.isfile(os.path.join(SRC, ".git")):
        r = subprocess.run(["git", "-C", SRC, "ls-files"], capture_output=True, text=True)
        paths = r.stdout.split("\n")
    else:
        paths = [os.path.relpath(os.path.join(d, f), SRC) for d, ds, fs in os.walk(SRC)
                 if not any(x in d for x in (".git", "target", ".onnxruntime", "node_modules")) for f in fs]
    out = []
    for path in sorted(p for p in paths if p and keep(p)):
        try:
            with open(os.path.join(SRC, path), "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        if b"\0" in data[:4096]:
            continue
        lines = data.decode("utf-8", "replace").splitlines()
        out += [f"{path}:{n}:{l}" for n, l in enumerate(lines, 1) if re.search(pattern, l)]
    return out


def tracked_files_setting_the_prefix():
    hits = grep_tree(r"ORT_LIB_LOCATION=", lambda p: not p.endswith((".md", ".py")))
    return sorted({h.split(":", 1)[0] for h in hits})


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
            text = open(os.path.join(SRC, f), errors="replace").read()
            for line in text.splitlines():
                if re.search(r"(export |-E |^\s*)ORT_LIB_LOCATION=", line) and not line.lstrip().startswith("#"):
                    self.assertTrue("ORT_PREFER_DYNAMIC_LINK=1" in text,
                                    f"{f} sets ORT_LIB_LOCATION without ORT_PREFER_DYNAMIC_LINK=1")
                    self.assertTrue(re.search(r"ORT_LIB_PATH=\S*ORT_LIB_LOCATION\S*/lib|ORT_LIB_PATH=/opt/onnxruntime/lib", text),
                                    f"{f} hands ort-sys the prefix, not its lib/ directory (ORT_LIB_PATH)")

    def test_the_runtime_is_linked_from_the_pinned_library_never_downloaded_by_the_build(self):
        manifest = open(os.path.join(SRC, "Cargo.toml")).read()
        line = next(l for l in manifest.splitlines() if l.startswith("praecise-onnx = "))
        self.assertIn("default-features = false", line, "praecise-onnx's download-binaries is off")
        hits = grep_tree(r"download-binaries|tls-rustls", lambda p: p.endswith("Cargo.toml"))
        live = [l for l in hits if not l.split(":", 2)[2].lstrip().startswith("#")]
        self.assertEqual(live, [], "no crate asks for the build-time download again")
        lock = open(os.path.join(SRC, "Cargo.lock")).read()
        self.assertNotRegex(lock, r'name = "ureq"', "the download client left the build graph")

    def test_the_cuda_image_links_the_pinned_cuda_runtime_and_ships_its_providers_beside_the_node(self):
        text = open(os.path.join(SRC, "Dockerfile.cuda")).read()
        self.assertIn("--feature cuda13,tensorrt,nvrtx", text)
        self.assertNotIn("github.com/microsoft/onnxruntime", text, "upstream no longer exists; nothing is built from it")
        self.assertNotIn("ORT_PREFER_DYNAMIC_LINK", text)
        self.assertIn("! ldd target/release/tenzro-node | grep -q 'libonnxruntime\\.so'", text)
        for p in ("shared", "cuda", "tensorrt"):
            self.assertIn(f"/build/target/release/libonnxruntime_providers_{p}.so", text)
        self.assertRegex(text, r"libonnxruntime_providers_nv_tensorrt_rtx\.so /usr/local/bin/")


if __name__ == "__main__":
    unittest.main()
