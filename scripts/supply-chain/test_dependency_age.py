"""The minimum-age rule (dependency_age.py) on lock files and registry answers made for the test.

No network: the registry is a table. Run from anywhere:

    python3 scripts/supply-chain/test_dependency_age.py
"""
import datetime
import io
import json
import os
import sys
import unittest
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dependency_age as age  # noqa: E402

NOW = datetime.datetime(2026, 11, 16, tzinfo=datetime.timezone.utc)
GIT = {"https://github.com/Praecise/praecise-engine"}
REGISTRY = "https://registry.npmjs.org/"


def cargo_lock(*packages):
    out = "version = 4\n"
    for name, version, source in packages:
        out += f'\n[[package]]\nname = "{name}"\nversion = "{version}"\n'
        if source:
            out += f'source = "{source}"\n'
    return out


def npm_lock(version=3, **packages):
    entries = {"": {"name": "root", "version": "1.0.0"}}
    for path, fields in packages.items():
        entries[path] = fields
    return json.dumps({"lockfileVersion": version, "packages": entries})


def registry_entry(name, version):
    return {"version": version, "resolved": f"{REGISTRY}{name}/-/x-{version}.tgz"}


PNPM = """lockfileVersion: '9.0'

importers:

  .:
    devDependencies:
      typescript:
        specifier: ^5.9.3
        version: 5.9.3

packages:

  '@types/node@24.0.1':
    resolution: {integrity: sha512-AAAA==}

  typescript@5.9.3:
    resolution: {integrity: sha512-BBBB==}
    hasBin: true

snapshots:

  typescript@5.9.3: {}
"""


def published(days_ago):
    return lambda *_: NOW - datetime.timedelta(days=days_ago, hours=1)


class LockFiles(unittest.TestCase):
    def test_cargo_new_registry_versions_only(self):
        base = cargo_lock(("serde", "1.0.0", age.CRATES_IO))
        now = cargo_lock(
            ("serde", "1.0.0", age.CRATES_IO),
            ("serde", "1.0.1", age.CRATES_IO),
            ("tenzro-types", "0.2.0", None),
            ("praecise-runtime", "0.1.0", "git+https://github.com/Praecise/praecise-engine?rev=abc#abc"),
        )
        self.assertEqual(age.new_versions([("Cargo.lock", now, base)], GIT), [("cargo", "serde", "1.0.1")])
        self.assertEqual(age.new_versions([("fuzz/Cargo.lock", base, None)], GIT), [("cargo", "serde", "1.0.0")])

    def test_a_cargo_package_from_an_unlisted_source_stops_the_check(self):
        for source in (
            "git+https://github.com/someone/serde?rev=1#1",
            "registry+https://example.com/index",
            "sparse+https://example.com/index/",
        ):
            with self.assertRaises(age.CannotCheck, msg=source):
                age.cargo_versions(cargo_lock(("serde", "1.0.1", source)), GIT)

    def test_npm_names_come_from_the_innermost_node_modules_path(self):
        now = npm_lock(**{
            "node_modules/@noble/hashes": registry_entry("@noble/hashes", "1.5.0"),
            "node_modules/a/node_modules/left-pad": registry_entry("left-pad", "1.3.0"),
            "node_modules/@tenzro/core": {"resolved": "packages/core", "link": True},
            "packages/core": {"version": "0.9.0"},
        })
        self.assertEqual(
            age.new_versions([("sdk/package-lock.json", now, npm_lock())], GIT),
            [("npm", "@noble/hashes", "1.5.0"), ("npm", "left-pad", "1.3.0")],
        )

    def test_an_npm_package_not_from_the_registry_stops_the_check(self):
        for resolved in (
            "https://evil.example.com/left-pad-1.3.0.tgz",
            "git+ssh://git@github.com/someone/left-pad.git#abc",
            "file:../left-pad",
            "",
        ):
            lock = npm_lock(**{"node_modules/left-pad": {"version": "1.3.0", "resolved": resolved}})
            with self.assertRaises(age.CannotCheck, msg=resolved):
                age.npm_versions(lock)

    def test_an_old_or_unexpected_package_lock_stops_the_check(self):
        with self.assertRaises(age.CannotCheck):
            age.npm_versions(json.dumps({"lockfileVersion": 1, "dependencies": {"left-pad": {"version": "1.3.0"}}}))
        with self.assertRaises(age.CannotCheck):
            age.npm_versions(json.dumps({"lockfileVersion": 3}))

    def test_pnpm_registry_packages_are_read_and_others_stop_the_check(self):
        self.assertEqual(
            age.pnpm_versions(PNPM), {("npm", "@types/node", "24.0.1"), ("npm", "typescript", "5.9.3")}
        )
        tarball = PNPM.replace("{integrity: sha512-BBBB==}", "{tarball: https://evil.example.com/t.tgz}")
        with self.assertRaises(age.CannotCheck):
            age.pnpm_versions(tarball)
        with self.assertRaises(age.CannotCheck):
            age.pnpm_versions(PNPM.replace("'9.0'", "'6.0'"))

    def test_go_sum_lines_name_module_versions(self):
        text = (
            "github.com/consensys/gnark v0.16.3 h1:abc=\n"
            "github.com/consensys/gnark v0.16.3/go.mod h1:def=\n"
            "github.com/BurntSushi/toml v1.4.0/go.mod h1:ghi=\n"
        )
        self.assertEqual(
            age.go_versions(text),
            {("go", "github.com/consensys/gnark", "v0.16.3"), ("go", "github.com/BurntSushi/toml", "v1.4.0")},
        )
        self.assertEqual(age.go_escape("github.com/BurntSushi/toml"), "github.com/!burnt!sushi/toml")
        with self.assertRaises(age.CannotCheck):
            age.go_versions("not a go.sum line\n")

    def test_a_name_or_version_that_could_reach_another_address_is_refused(self):
        for ecosystem, name, version in (
            ("cargo", "serde", "1.0.0/../../other/1.0.0"),
            ("cargo", "../serde", "1.0.0"),
            ("npm", "left-pad/../evil", "1.3.0"),
            ("npm", "left-pad", "1.3.0?x"),
            ("go", "github.com/a/../b", "v1.0.0"),
        ):
            with self.assertRaises(age.CannotCheck, msg=(name, version)):
                age.checked(ecosystem, name, version)
        lock = cargo_lock(("serde", "1.0.0/../../other/1.0.0", age.CRATES_IO))
        with self.assertRaises(age.CannotCheck):
            age.cargo_versions(lock, GIT)


class Rule(unittest.TestCase):
    def test_a_version_younger_than_the_minimum_is_refused_and_an_older_one_is_not(self):
        new = [("cargo", "serde", "1.0.1")]
        self.assertEqual(age.too_young(new, published(7), NOW, 7, set()), [])
        self.assertEqual(age.too_young(new, published(6), NOW, 7, set()), [("cargo", "serde", "1.0.1", 6)])

    def test_an_excepted_version_is_admitted_without_asking_the_registry(self):
        def unreachable(*_):
            raise AssertionError("the registry was asked about an excepted version")

        new = [("npm", "left-pad", "1.3.0")]
        self.assertEqual(age.too_young(new, unreachable, NOW, 7, {("npm", "left-pad", "1.3.0")}), [])
        self.assertEqual(
            age.too_young(new, published(0), NOW, 7, {("cargo", "left-pad", "1.3.0")}),
            [("npm", "left-pad", "1.3.0", 0)],
        )

    def test_the_minimum_age_is_the_base_commits_and_exceptions_are_the_changes(self):
        base = '[new_versions]\nmin_age_days = 7\n[sources]\ngit = []\n'
        change = (
            '[new_versions]\nmin_age_days = 0\n[sources]\ngit = ["https://github.com/Praecise/praecise-engine"]\n'
            '[[new_versions.exception]]\necosystem = "cargo"\nname = "x"\nversion = "1.0.0"\nreason = "CVE fix"\n'
        )
        self.assertEqual(age.load_policy(base, change), (7, GIT, {("cargo", "x", "1.0.0")}))

    def test_only_the_change_that_introduces_the_rule_is_held_to_its_own_minimum(self):
        change = '[new_versions]\nmin_age_days = 7\n[sources]\ngit = []\n'
        self.assertEqual(age.load_policy('[sources]\ngit = []\n', change)[0], 7)
        self.assertEqual(age.load_policy(change, change.replace("= 7", "= 0"))[0], 7)

    def test_an_exception_needs_a_reason_and_a_known_ecosystem(self):
        base = '[new_versions]\nmin_age_days = 7\n[sources]\ngit = []\n'
        entry = '[[new_versions.exception]]\necosystem = "cargo"\nname = "x"\nversion = "1.0.0"\n'
        with self.assertRaises(age.CannotCheck):
            age.load_policy(base, base + entry)
        with self.assertRaises(age.CannotCheck):
            age.load_policy(base, base + entry.replace('"cargo"', '"gem"') + 'reason = "CVE fix"\n')

    def test_the_repository_policy_parses_against_itself(self):
        with open(os.path.join(age.ROOT, age.POLICY)) as f:
            text = f.read()
        days, git, _ = age.load_policy(text, text)
        self.assertGreaterEqual(days, 1)
        self.assertIn("https://github.com/Praecise/praecise-engine", git)


class Registry(unittest.TestCase):
    def test_a_limited_or_failing_registry_is_asked_again_after_a_pause_then_given_up(self):
        pauses, calls = [], []

        def limited(times):
            def opener(request, timeout):
                calls.append(request.full_url)
                if len(calls) <= times:
                    raise urllib.error.HTTPError(request.full_url, 429, "Too Many Requests", {"Retry-After": "3"}, None)
                return io.BytesIO(b'{"ok": true}')
            return opener

        self.assertEqual(age.fetch("https://x/a", sleep=pauses.append, opener=limited(2)), {"ok": True})
        self.assertEqual(pauses, [3.0, 3.0])
        calls.clear()
        pauses.clear()
        with self.assertRaises(urllib.error.HTTPError):
            age.fetch("https://x/a", attempts=3, sleep=pauses.append, opener=limited(10))
        self.assertEqual(len(calls), 3)

    def test_a_missing_version_is_not_asked_again(self):
        calls = []

        def missing(request, timeout):
            calls.append(1)
            raise urllib.error.HTTPError(request.full_url, 404, "Not Found", {}, None)

        with self.assertRaises(urllib.error.HTTPError):
            age.fetch("https://x/a", sleep=lambda _: None, opener=missing)
        self.assertEqual(len(calls), 1)


if __name__ == "__main__":
    unittest.main()
