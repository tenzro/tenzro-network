"""The release advisory gate (advisory-gate.sh) against lockfiles that differ only in the advisories they carry.

Each case is a one-package lockfile, so the verdict depends on that package alone and not on what the
repository's Cargo.lock holds today. Uses cargo-audit and its advisory database on this host (no fetch).

    python3 scripts/supply-chain/test_advisory_gate.py
"""
import os
import shutil
import subprocess
import tempfile
import unittest

GATE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "advisory-gate.sh")


def lockfile(name, version):
    return (
        "version = 4\n\n[[package]]\n"
        f'name = "{name}"\nversion = "{version}"\n'
        'source = "registry+https://github.com/rust-lang/crates.io-index"\n'
    )


@unittest.skipUnless(shutil.which("cargo-audit"), "cargo-audit is not installed on this host")
class AdvisoryGate(unittest.TestCase):
    def gate(self, name, version):
        with tempfile.TemporaryDirectory() as d:
            lock = os.path.join(d, "Cargo.lock")
            with open(lock, "w") as f:
                f.write(lockfile(name, version))
            r = subprocess.run(["bash", GATE, "--no-fetch", lock], capture_output=True, text=True)
        return r.returncode, r.stdout + r.stderr

    def test_a_release_carrying_a_known_advisory_is_blocked(self):
        # rustls 0.23.45: RUSTSEC-2026-0349, not accepted in .cargo/audit.toml.
        rc, out = self.gate("rustls", "0.23.45")
        self.assertEqual(rc, 1, out)
        self.assertIn("BLOCKED: RUSTSEC-2026-0349", out)

    def test_the_patched_version_passes(self):
        rc, out = self.gate("rustls", "0.23.46")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("RUSTSEC-2026-0349", out)

    def test_an_advisory_accepted_in_audit_toml_does_not_block(self):
        # rsa 0.9.10: RUSTSEC-2023-0071, accepted with a reachability analysis.
        rc, out = self.gate("rsa", "0.9.10")
        self.assertEqual(rc, 0, out)
        self.assertNotIn("RUSTSEC-2023-0071", out)

    def test_a_missing_lockfile_refuses(self):
        r = subprocess.run(["bash", GATE, "--no-fetch", "/nonexistent/Cargo.lock"], capture_output=True, text=True)
        self.assertEqual(r.returncode, 2, r.stdout)


if __name__ == "__main__":
    unittest.main()
