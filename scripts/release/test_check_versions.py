#!/usr/bin/env python3
"""One release, one version: python3 scripts/release/test_check_versions.py

The repository itself passes check-versions.py, and the check refuses each way a tree can disagree.
"""
import importlib.util, json, os, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SRC = os.path.dirname(os.path.dirname(HERE))
spec = importlib.util.spec_from_file_location("check_versions", os.path.join(HERE, "check-versions.py"))
cv = importlib.util.module_from_spec(spec)
spec.loader.exec_module(cv)


def write(root, path, text):
    path = os.path.join(root, path)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def tree(root, crate_version='version = "0.2.2"', sdk="0.9.0", core=None, guest='version = "0.2.0"',
         py="0.2.2", order_inject="0.2.2"):
    write(root, "Cargo.toml", '[workspace.package]\nversion = "0.2.0"\n')
    write(root, "crates/tenzro-node/Cargo.toml", '[package]\nname = "tenzro-node"\nversion = "0.2.2"\n')
    write(root, "crates/tenzro-cli/Cargo.toml", f'[package]\nname = "tenzro-cli"\n{crate_version}\n')
    write(root, "crates/tenzro-types/Cargo.toml", f'[package]\nname = "tenzro-types"\n{guest}\n')
    write(root, "sdk/tenzro-sdk/Cargo.toml", f'[package]\nname = "tenzro-sdk"\nversion = "{sdk}"\n')
    write(root, "sdk/tenzro-ts-sdk/package.json", json.dumps({"name": "tenzro-sdk", "version": sdk}))
    write(root, "sdk/tenzro-ts-sdk/packages/core/package.json", json.dumps({"name": "@tenzro/core", "version": core or sdk}))
    write(root, "sdk/tenzro-inject/package.json", json.dumps({"name": "@tenzro/inject", "version": "0.2.2"}))
    write(root, "sdk/tenzro-py/pyproject.toml", f'[project]\nname = "tenzro"\nversion = "{py}"\n')
    write(root, "sdk/tenzro-py/tenzro/__init__.py", '__version__ = "0.2.2"\n')
    write(root, "scripts/release/run/publish.sh",
          f'NPM_ORDER="tenzro-core-{sdk}.tgz tenzro-inject-{order_inject}.tgz"\nPYPI_ORDER="tenzro-0.2.2"\n')


class CheckVersions(unittest.TestCase):
    def run_on(self, **kw):
        with tempfile.TemporaryDirectory() as d:
            tree(d, **kw)
            return cv.check(d)[1]

    def test_this_repository_agrees(self):
        ws, bad = cv.check(SRC)
        self.assertEqual(bad, [], f"release {ws}")

    def test_a_tree_that_agrees_passes(self):
        self.assertEqual(self.run_on(), [])

    def test_a_crate_on_another_version_is_named(self):
        bad = self.run_on(crate_version='version = "0.2.0"')
        self.assertEqual(len(bad), 1)
        self.assertIn("crate tenzro-cli is 0.2.0, the release is 0.2.2", bad[0])

    def test_a_python_package_on_another_version_is_named(self):
        bad = self.run_on(py="0.2.0")
        self.assertTrue(any("python tenzro is 0.2.0" in b for b in bad), bad)

    def test_the_sdk_line_keeps_its_own_version_but_must_agree_with_itself(self):
        self.assertEqual(self.run_on(sdk="0.9.0"), [])
        bad = self.run_on(sdk="0.9.0", core="0.8.0")
        self.assertTrue(any(b.startswith("the SDK line disagrees") for b in bad), bad)

    def test_the_other_crates_keep_their_own_line(self):
        self.assertEqual(self.run_on(guest='version = "0.2.0"'), [])
        self.assertEqual(self.run_on(guest='version = "0.4.0"'), [])

    def test_an_operated_service_keeps_its_own_line(self):
        with tempfile.TemporaryDirectory() as d:
            tree(d)
            write(d, "sdk/tenzro-mailbox-service/Cargo.toml", '[package]\nname = "tenzro-mailbox-service"\nversion = "0.1.0"\n')
            self.assertEqual(cv.check(d)[1], [])

    def test_a_publish_list_naming_another_version_is_refused(self):
        bad = self.run_on(order_inject="0.2.0")
        self.assertEqual(bad, ["scripts/release/run/publish.sh: NPM_ORDER names tenzro-inject-0.2.0, the tree has 0.2.2"])

    def test_the_exit_status_follows_the_result(self):
        with tempfile.TemporaryDirectory() as d:
            tree(d)
            self.assertEqual(cv.main(["check-versions.py", d]), 0)
            tree(d, crate_version='version = "0.1.0"')
            self.assertEqual(cv.main(["check-versions.py", d]), 1)


if __name__ == "__main__":
    unittest.main()
