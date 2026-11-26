"""check_tls_provider.py on cargo metadata made for the test.

    python3 scripts/supply-chain/test_check_tls_provider.py
"""
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import check_tls_provider as check  # noqa: E402

INSTALLS = """fn main() {
    rustls::crypto::aws_lc_rs::default_provider()
        .install_default()
        .expect("no TLS provider is installed before main");
}
"""


def metadata(dep_kind):
    """A workspace binary `app` that depends on `net`, which depends on rustls."""
    edge = {"pkg": "net", "dep_kinds": [{"kind": dep_kind}]}
    return {
        "workspace_members": ["app", "tool"],
        "packages": [
            {"id": "app", "name": "app", "targets": [{"kind": ["bin"], "name": "app", "src_path": "app.rs"}]},
            {"id": "tool", "name": "tool", "targets": [{"kind": ["bin"], "name": "tool", "src_path": "tool.rs"}]},
            {"id": "net", "name": "net", "targets": [{"kind": ["lib"], "name": "net", "src_path": "net.rs"}]},
            {"id": "rustls", "name": "rustls", "targets": [{"kind": ["lib"], "name": "rustls", "src_path": "r.rs"}]},
        ],
        "resolve": {
            "nodes": [
                {"id": "app", "deps": [edge]},
                {"id": "tool", "deps": []},
                {"id": "net", "deps": [{"pkg": "rustls", "dep_kinds": [{"kind": None}]}]},
                {"id": "rustls", "deps": []},
            ]
        },
    }


class TlsProvider(unittest.TestCase):
    def test_a_binary_linking_rustls_without_the_install_is_named(self):
        bad = check.missing(metadata(None), read=lambda path: "fn main() {}")
        self.assertEqual(bad, [("app", "app", "app.rs")])

    def test_a_binary_that_installs_aws_lc_rs_passes(self):
        self.assertEqual(check.missing(metadata(None), read=lambda path: INSTALLS), [])

    def test_a_binary_that_does_not_link_rustls_needs_no_install(self):
        self.assertEqual(check.missing(metadata("dev"), read=lambda path: "fn main() {}"), [])
        self.assertEqual(check.missing(metadata("build"), read=lambda path: "fn main() {}"), [])


    def test_every_workspace_in_the_tree_is_checked_vendored_crates_aside(self):
        manifests = {
            "Cargo.toml": '[workspace]\nmembers = ["crates/*"]\n',
            "crates/net/Cargo.toml": '[package]\nname = "net"\n',
            "sdk/service/Cargo.toml": '[package]\nname = "service"\n\n[workspace]\n',
            "sdk/service/nested/Cargo.toml": "[workspace]\nresolver = \"3\"\n",
            "vendor/iroh/Cargo.toml": "[workspace]\n",
            "docs/Cargo.toml": '[package]\nname = "x"\n# [workspace] is mentioned, not declared\n',
        }
        self.assertEqual(
            check.workspaces(list(manifests), read=manifests.__getitem__),
            ["Cargo.toml", "sdk/service/Cargo.toml", "sdk/service/nested/Cargo.toml"],
        )


if __name__ == "__main__":
    unittest.main()
