#!/usr/bin/env python3
"""fetch-onnxruntime.py unpacks only the pinned bytes: python3 scripts/release/test_fetch_onnxruntime.py

Archives are made here in the format the pinned ones use (a raw LZMA2 tar), so no network is needed.
"""
import hashlib, importlib.util, io, lzma, os, tarfile, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("fetch", os.path.join(HERE, "fetch-onnxruntime.py"))
fetch = importlib.util.module_from_spec(spec)
spec.loader.exec_module(fetch)
TRIPLE = "x86_64-unknown-linux-gnu"


def archive(members):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as t:
        for name, data, kind in members:
            info = tarfile.TarInfo(name)
            info.type = kind
            info.size = len(data) if kind == tarfile.REGTYPE else 0
            t.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
    return lzma.compress(buf.getvalue(), format=lzma.FORMAT_RAW, filters=[{"id": lzma.FILTER_LZMA2}])


class Fetch(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.dir = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def pinned(self, data):
        path = os.path.join(self.dir, "a.tar.lzma2")
        with open(path, "wb") as f:
            f.write(data)
        pins = os.path.join(self.dir, "pins.tsv")
        with open(pins, "w") as f:
            f.write(f"# test\nversion\t9.9.9\n{TRIPLE}\tnone\thttps://example.invalid/a\t{hashlib.sha256(data).hexdigest()}\n"
                    f"{TRIPLE}\tmigraphx\thttps://example.invalid/b\t{hashlib.sha256(b'other').hexdigest()}\n")
        return path, pins

    def test_the_pinned_archive_unpacks_where_ort_lib_location_points(self):
        path, pins = self.pinned(archive([("libonnxruntime.a", b"lib", tarfile.REGTYPE)]))
        dest = fetch.fetch(TRIPLE, self.dir, path, pins)
        self.assertEqual(dest, os.path.join(self.dir, "9.9.9", TRIPLE))
        with open(os.path.join(dest, "libonnxruntime.a"), "rb") as f:
            self.assertEqual(f.read(), b"lib")
        # Already in place: reused, the archive is not read again.
        os.remove(path)
        self.assertEqual(fetch.fetch(TRIPLE, self.dir, path, pins), dest)

    def test_other_bytes_are_refused_and_nothing_is_unpacked(self):
        _, pins = self.pinned(archive([("libonnxruntime.a", b"lib", tarfile.REGTYPE)]))
        other = os.path.join(self.dir, "other")
        with open(other, "wb") as f:
            f.write(archive([("libonnxruntime.a", b"evil", tarfile.REGTYPE)]))
        with self.assertRaises(fetch.Refused) as e:
            fetch.fetch(TRIPLE, self.dir, other, pins)
        self.assertIn("not the pinned", str(e.exception))
        self.assertFalse(os.path.exists(os.path.join(self.dir, "9.9.9")))

    def test_a_pinned_archive_with_a_path_a_link_or_no_library_is_refused(self):
        for members in ([("../libonnxruntime.a", b"x", tarfile.REGTYPE)],
                        [("sub/libonnxruntime.a", b"x", tarfile.REGTYPE)],
                        [("libonnxruntime.a", b"", tarfile.SYMTYPE)],
                        [("README", b"x", tarfile.REGTYPE)]):
            with self.subTest(members=members[0][0]):
                path, pins = self.pinned(archive(members))
                with self.assertRaises(fetch.Refused):
                    fetch.fetch(TRIPLE, self.dir, path, pins)

    def test_a_feature_picks_its_own_row_and_lands_apart(self):
        _, pins = self.pinned(archive([("libonnxruntime.a", b"lib", tarfile.REGTYPE)]))
        with self.assertRaises(fetch.Refused) as e:
            fetch.fetch(TRIPLE, self.dir, os.path.join(self.dir, "a.tar.lzma2"), pins, feature="migraphx")
        self.assertIn("not the pinned", str(e.exception), "the migraphx row's own hash is checked")
        with self.assertRaises(fetch.Refused) as e:
            fetch.fetch(TRIPLE, self.dir, None, pins, feature="cuda")
        self.assertIn("no pinned cuda build", str(e.exception))

    def test_a_target_with_no_pin_is_refused(self):
        _, pins = self.pinned(archive([("libonnxruntime.a", b"lib", tarfile.REGTYPE)]))
        with self.assertRaises(fetch.Refused) as e:
            fetch.fetch("riscv64gc-unknown-linux-gnu", self.dir, None, pins)
        self.assertIn("no pinned ONNX Runtime", str(e.exception))

    @unittest.skipIf(os.name == "nt", "a junction is made by cmd on Windows")
    def test_the_checkout_link_points_at_the_fetched_runtime_and_moves_with_it(self):
        at = os.path.join(self.dir, "checkout", ".onnxruntime", "host")
        a, b = os.path.join(self.dir, "a"), os.path.join(self.dir, "b")
        os.makedirs(a), os.makedirs(b)
        fetch.link(a, at)
        self.assertEqual(os.path.realpath(at), os.path.realpath(a))
        fetch.link(b, at)
        self.assertEqual(os.path.realpath(at), os.path.realpath(b))
        os.unlink(at)
        os.makedirs(at)
        with self.assertRaises(fetch.Refused):
            fetch.link(a, at)

    def test_cargo_links_what_the_fetch_places(self):
        with open(os.path.join(HERE, "..", "..", ".cargo", "config.toml")) as f:
            config = f.read()
        self.assertIn('ORT_LIB_LOCATION = { value = ".onnxruntime/host", relative = true }', config)
        self.assertEqual(os.path.normpath(fetch.CHECKOUT_LINK),
                         os.path.normpath(os.path.join(HERE, "..", "..", ".onnxruntime", "host")))

    def test_the_repository_pins_every_cpu_release_target_once(self):
        version, rows = fetch.pins()
        self.assertEqual(version, "1.31.0")
        self.assertEqual({t: [c[0] for c in r] for t, r in rows.items()}, {
            "x86_64-unknown-linux-gnu": ["none", "migraphx", "cuda13,tensorrt,nvrtx"],
            "aarch64-unknown-linux-gnu": ["none", "cuda13,tensorrt,nvrtx"],
            "aarch64-apple-darwin": ["coreml"],
            "x86_64-pc-windows-msvc": ["directml", "cuda13,tensorrt,nvrtx,directml"]})
        for _, url, sha in (c for r in rows.values() for c in r):
            self.assertTrue(url.startswith("https://"))
            self.assertRegex(sha, r"^[0-9a-f]{64}$")


if __name__ == "__main__":
    unittest.main()
