"""llm-review.py: only committed, public, scanned text reaches a provider; the ledger is charged before
the call and caps spend whatever the provider answers; a provider that is unknown or fails is not replaced.

    python3 scripts/supply-chain/test_llm_review.py
"""
import importlib.util
import json
import os
import subprocess
import sys
import tempfile
import threading
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("llm_review", os.path.join(HERE, "llm-review.py"))
tool = importlib.util.module_from_spec(spec)
spec.loader.exec_module(tool)

# Put together here so this file itself holds nothing the scanner looks for.
SECRET = "sk-" + "ant-" + "a" * 24

# Put together here for the same reason: an address, a host name and a credential of a private network.
PRIVATE_ADDRESS = "10." + "20.30.40"
INTERNAL_HOST = "build-7.corp" + ".internal"
PASSWORD = "pass" + "word = " + "hunter2hunter2"

ADAPTER = """
import json, sys, time
request = json.load(sys.stdin)
open(sys.argv[1], "a").write(json.dumps(request) + "\\n")
mode = sys.argv[2]
if mode == "fail":
    sys.exit(3)
if mode == "hang":
    time.sleep(30)
if mode == "slow":
    time.sleep(1)
answer = {"text": "no findings", "input_tokens": 100, "output_tokens": 50}
if mode.startswith("reply:"):
    answer = json.loads(mode[6:])
if mode == "env":
    import os
    answer["text"] = json.dumps(sorted(os.environ))
print(json.dumps(answer))
"""


class Review(unittest.TestCase):
    def setUp(self):
        tool._SCANNERS.clear()
        tool._KNOWN.clear()
        d = tempfile.TemporaryDirectory()
        self.addCleanup(d.cleanup)
        self.root = os.path.join(os.path.realpath(d.name), "repo")
        self.outside = os.path.realpath(d.name)
        os.makedirs(os.path.join(self.root, "tools", "sync"))
        os.makedirs(os.path.join(self.root, "crates", "x"))
        os.makedirs(os.path.join(self.root, "internal"))
        self.write("tools/sync/public-root.txt", "# the list\ncrates/\nREADME.md\n")
        self.write("crates/x/lib.rs", "pub fn add(a: u8, b: u8) -> u8 { a + b }\n")
        self.write("README.md", "A node.\n")
        self.write("internal/plan.md", "Nothing wrong with the words in here.\n")
        self.write("READMEX.md", "Not listed.\n")
        with open(os.path.join(HERE, "..", "..", "tools", "sync", "scan-public.py")) as f:
            self.write("tools/sync/scan-public.py", f.read())
        self.git("init", "-q", ".")
        self.commit()
        self.calls = os.path.join(self.outside, "calls")
        self.adapter = os.path.join(self.outside, "adapter.py")
        with open(self.adapter, "w") as f:
            f.write(ADAPTER)
        self.config = {
            "cap_usd": 1.0,
            "ledger": os.path.join(self.outside, "ledger.jsonl"),
            "providers": {"good": self.provider("ok"), "broken": self.provider("fail")},
        }

    def git(self, *args):
        subprocess.run(["git", "-C", self.root, "-c", "core.hooksPath=/dev/null", "-c", "user.name=t",
                        "-c", "user.email=t@example.org", "-c", "commit.gpgsign=false", *args],
                       check=True, capture_output=True)

    def commit(self):
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "c")

    def provider(self, mode, **more):
        return {"command": [sys.executable, self.adapter, self.calls, mode],
                "usd_per_mtok_in": 4.0, "usd_per_mtok_out": 20.0, "max_output_tokens": 1000, **more}

    def write(self, rel, text):
        with open(os.path.join(self.root, rel), "w") as f:
            f.write(text)

    def path(self, rel):
        return os.path.join(self.root, rel)

    def review(self, provider, *rels, instruction="review"):
        return tool.review(self.config, provider, instruction, [self.path(r) for r in rels], root=self.root)

    def provider_calls(self):
        if not os.path.exists(self.calls):
            return []
        with open(self.calls) as f:
            return [json.loads(line) for line in f]

    def ledger(self):
        if not os.path.exists(self.config["ledger"]):
            return []
        with open(self.config["ledger"]) as f:
            return [json.loads(line) for line in f if line.strip()]

    def total(self):
        with open(self.config["ledger"]) as f:
            return tool.spent(f.readlines())

    def refused(self, provider, *rels, **kw):
        with self.assertRaises(tool.Refused) as e:
            self.review(provider, *rels, **kw)
        return str(e.exception)

    def test_public_files_are_reviewed_and_the_call_is_charged_before_and_settled_after(self):
        self.assertEqual(self.review("good", "crates/x/lib.rs", "README.md"), "no findings")
        (call,) = self.provider_calls()
        self.assertEqual([f["path"] for f in call["files"]], ["crates/x/lib.rs", "README.md"])
        pending, settled = self.ledger()
        self.assertEqual((pending["status"], settled["status"], pending["id"]), ("pending", "ok", settled["id"]))
        # The provider's own count is recorded, and never lowers what the cap counts.
        self.assertAlmostEqual(settled["reported_usd"], (100 * 4.0 + 50 * 20.0) / 1e6)
        self.assertEqual(settled["usd"], pending["usd"])
        self.assertGreater(settled["usd"], settled["reported_usd"])
        self.assertAlmostEqual(self.total(), pending["usd"])

    def test_a_provider_that_reports_one_token_for_a_large_request_lowers_nothing(self):
        self.config["providers"]["tiny"] = self.provider("reply:" + json.dumps({"text": "x", "input_tokens": 1, "output_tokens": 1}))
        self.review("tiny", "crates/x/lib.rs", "README.md")
        pending, settled = self.ledger()[-2:]
        self.assertEqual(settled["usd"], pending["usd"])
        self.assertAlmostEqual(self.total(), pending["usd"])

    def test_the_provider_sees_path_and_only_the_variables_its_config_names(self):
        os.environ["LLM_REVIEW_TEST_KEPT"] = "1"
        os.environ["LLM_REVIEW_TEST_SECRET"] = "2"
        try:
            self.config["providers"]["env"] = self.provider("env", env=["LLM_REVIEW_TEST_KEPT", "NOT_SET_ANYWHERE"])
            seen = set(json.loads(self.review("env", "README.md")))
        finally:
            del os.environ["LLM_REVIEW_TEST_KEPT"], os.environ["LLM_REVIEW_TEST_SECRET"]
        self.assertIn("LLM_REVIEW_TEST_KEPT", seen)
        self.assertNotIn("LLM_REVIEW_TEST_SECRET", seen)
        self.assertLessEqual(seen - {"PATH", "LLM_REVIEW_TEST_KEPT"}, {"LC_CTYPE", "__CF_USER_TEXT_ENCODING"})
        self.config["providers"]["badenv"] = self.provider("ok", env="HOME")
        self.assertIn("list of variable names", self.refused("badenv", "README.md"))

    def test_a_file_outside_the_public_list_stops_the_request_before_the_provider_runs(self):
        for rel in ("internal/plan.md", "READMEX.md", "tools/sync/public-root.txt"):
            with self.subTest(rel):
                self.assertIn("not on the public allow-list", self.refused("good", "crates/x/lib.rs", rel))
        self.assertEqual((self.provider_calls(), self.ledger()), ([], []))

    def test_a_secret_in_a_public_file_stops_the_request_before_the_provider_runs(self):
        self.write("crates/x/lib.rs", f'const KEY: &str = "{SECRET}";\n')
        self.commit()
        why = self.refused("good", "README.md", "crates/x/lib.rs")
        self.assertIn("secret", why)
        self.assertIn("crates/x/lib.rs:1", why)
        self.assertEqual((self.provider_calls(), self.ledger()), ([], []))

    def test_an_untracked_file_under_an_allowed_directory_does_not_leave(self):
        self.write("crates/x/notes.rs", "// never committed\n")
        self.assertIn("not a regular file in the HEAD commit", self.refused("good", "crates/x/notes.rs"))
        self.assertEqual(self.provider_calls(), [])

    def test_what_leaves_is_the_committed_text_not_an_uncommitted_edit(self):
        self.write("crates/x/lib.rs", "// an edit that was never committed\n")
        self.review("good", "crates/x/lib.rs")
        (call,) = self.provider_calls()
        self.assertEqual(call["files"][0]["text"], "pub fn add(a: u8, b: u8) -> u8 { a + b }\n")

    def test_a_private_address_an_internal_host_and_a_password_are_refused(self):
        for label, text in (("private address", PRIVATE_ADDRESS), ("internal host name", INTERNAL_HOST),
                            ("password assignment", PASSWORD)):
            with self.subTest(label):
                # The instruction first: once a file of the tree holds the same words, they are
                # words the tree uses, which is the stated limit of the rule.
                self.assertIn(label, self.refused("good", "crates/x/lib.rs", instruction=f"look at {text}"))
                self.write("README.md", f"A node.\nSee {text} for more.\n")
                self.commit()
                tool._KNOWN.clear()
                why = self.refused("good", "README.md")
                self.assertIn(f"README.md:2: {label}", why)
        self.assertEqual((self.provider_calls(), self.ledger()), ([], []))

    ORDINARY = [
        "    secret: X25519StaticSecret,",
        "    pub fn from_secret_bytes(secret: &[u8]) -> Result<Self> {",
        "// first token: routers bill it apart from the rest",
        "fn seal(secret: &[u8; 32], nonce: u64) -> Vec<u8> {",
        "/// The first token: the reply starts here, and the token count follows.",
        "let token = parse_token(&header)?;",
        "let password = password_from_environment();",
        'let api_key: Option<String> = config.api_key.clone();',
        '{"token": "string", "secret": "<your secret>"}',
        "    pub secret: X25519StaticSecret",
        "    auth: &AuthContext,",
        "        Token => handler(request),",
        "    let token = issued_token;",
        "use soroban_sdk::token::{StellarAssetClient, TokenClient};",
        "    pass: !washing.is_empty() && ran.is_none(),",
        "    pass: worst.0 >= 0.99,",
        "let compass: Direction = north_east_heading;",
        "    let auth = ActAuth {",
        "    let access_token = result",
        "pub fn clear(data_dir: &Path, secret: Secret) -> Result<bool, String> {",
        "    credentials: vec![],",
        '    "KycCredential": "https://tenzro.com/ns/did#KycCredential",',
        "    credential: AccessCredential | None = None,",
        '        serde_json::json!({ "credential": credential }),',
        "    token: TokenClient<'static>,",
        "cargo test -p tenzro_node --lib",
        'mkdir -p "$out/traces" "$out/device_keys"',
        "the password protects the keystore",
        "    token_count = 12,",
        "    secret:",
        "    next_field: X25519StaticSecret,",
        'curl -u "$USER:$PASS" https://example.org/x',
        "docker run -u 1000:1000 image",
        "sort -u -p",
    ]

    def know_the_ordinary_words(self):
        """The names the ordinary lines use, as the rest of a real tree would hold them: each
        on two other lines."""
        words = sorted({w for line in self.ORDINARY for w in tool.WORD.findall(line) if len(w) >= 6})
        self.write("crates/x/known.rs", "\n".join(words) + "\n")
        self.commit()
        tool._KNOWN.clear()

    def test_ordinary_source_that_says_secret_or_token_leaves(self):
        self.know_the_ordinary_words()
        for line in self.ORDINARY:
            with self.subTest(line=line):
                self.assertEqual(tool.credential_lines(self.root, line), [])
        self.write("crates/x/lib.rs", "\n".join(self.ORDINARY) + "\n")
        self.commit()
        tool._KNOWN.clear()
        self.assertEqual(self.review("good", "crates/x/lib.rs"), "no findings")

    def test_a_name_is_known_only_when_another_line_of_the_tree_uses_it(self):
        line = "    secret: X25519StaticSecret,"
        self.assertEqual(tool.credential_lines(self.root, line), [1])
        # However often the file under review repeats the word, no other file has it.
        self.write("crates/x/lib.rs", (line + "\n") * 3 + "// X25519StaticSecret again\n")
        self.commit()
        tool._KNOWN.clear()
        why = self.refused("good", "crates/x/lib.rs")
        self.assertIn("crates/x/lib.rs:1: password assignment", why)
        self.assertIn("crates/x/lib.rs:3: password assignment", why)
        self.write("crates/x/types.rs", "pub struct X25519StaticSecret([u8; 32]);\n")
        self.commit()
        tool._KNOWN.clear()
        self.assertEqual(self.review("good", "crates/x/lib.rs"), "no findings")

    def test_a_literal_value_given_to_a_credentials_name_does_not_leave(self):
        # Each put together here so this file holds no line the scanners look for.
        pw, tok, sec = "pass" + "word", "to" + "ken", "sec" + "ret"
        h2 = "hunter2" + "hunter2"
        three_double, three_single = '"' * 3, "'" * 3
        lines = [
            tok + "=" + "ghp_" + "ABCdef123456ghi789",
            "API_KEY=" + "sk_live_" + "4f9a8b7c6d5e",
            pw + " = hunter2-hunter2-xyz9",
            "export " + pw.upper() + "=Sup3rS3cret!!",
            pw + "=p@ssw0rd!x",
            pw + ": !!str " + h2,
            tok + ': "abcdefgh"',
            pw + '="correct horse battery staple"',
            pw + ' = f"hunter2{suffix}"',
            sec + ' = b"0123456789abcdef"',
            pw + " = \\\n    " + '"' + h2 + '"',
            pw + " = \\\r\n    " + '"' + h2 + '"',
            "let " + pw + ' = "' + "hunter2!hunter2" + '";',
            sec + ": " + "a1b2c3d4e5f6a7b8",
            "api" + '_key = "' + "0123456789abcdef" + '"',
            tok.upper() + "=" + "Zx81Qp77Lm42Rt09",
            sec + "=abcdefghij",
            tok + "=abcdefghijkl",
            "private" + "_key = a" + "0f" * 31 + "b",
            pw.capitalize() + ": Hunter2Hunter2",
            "pa" + "ss=hunter2x",
            "pw" + "d: hunter2x9",
            "pass" + "_word=" + h2,
            "pass" + "-word=" + h2,
            "creden" + 'tials = "user:hunter2"',
            sec + 's: ["s3cr3t-one", "s3cr3t-two"]',
            sec + 's = ["s3cr3t-one", "s3cr3t-two"]',
            "au" + 'th = "Basic abc123xyz"',
            "pass" + "​" + "word=" + h2,
            pw + "＝" + h2,
            pw + ' => "literal-value"',
            pw.upper() + ' = os.environ["X"] or "literal"',
            pw + "=abc123",
            pw + " = hunter2(x)",
            sec + " = " + h2 + ".to_string()",
            tok + " = abc.def123",
            tok.upper() + "=Zm9vYmFy.Zm9vYmFy",
            sec + " = Hunter2::Hunter2",
            pw + " = &Sup3rS3cret",
            tok + " = [" + h2 + "]",
            pw + " = `" + h2 + "`",
            sec + ": Hunter2Hunter2,",
            "pub " + pw + ": Hunter2Hunter2",
            tok + ' = env("X", "' + h2 + '")',
            pw + " = " + three_double + h2 + three_double,
            pw + " = " + three_single + "\n" + h2 + "\n" + three_single,
            pw.upper() + "=${X:-" + h2 + "}",
            "machine example.org login someone " + pw + " " + h2,
            "mysql -u root -p " + h2,
            "tool --" + pw + " " + h2 + " run",
            "tool --" + tok + "=" + h2,
            tok + " = 12345678",
            pw + ": 0000111122223333",
            pw + ": |\n  " + h2,
            pw + ": >-\n    " + h2 + "\n    more",
            '"' + pw + '":\n\n    "' + h2 + '"',
            "ENV DB_PASS" + "WORD " + h2,
            "ARG API_TO" + "KEN " + h2,
            "mysql -u root -p" + "hunt2 mydb",
            "sshpass -p" + "hunt2 ssh host",
            "curl -u someone:" + "hunt2 https://example.org/x",
            "curl --user someone:" + h2 + " https://example.org/x",
        ]
        for line in lines:
            with self.subTest(line=line):
                self.assertEqual(tool.credential_lines(self.root, "fn ok() {}\n" + line + "\n"), [2])
        self.write("crates/x/lib.rs", lines[0] + "\n")
        self.commit()
        tool._KNOWN.clear()
        self.assertIn("crates/x/lib.rs:1: password assignment", self.refused("good", "crates/x/lib.rs"))
        self.assertIn("password assignment", self.refused("good", "README.md", instruction=lines[3]))
        self.assertEqual(self.provider_calls(), [])

    def test_a_private_key_block_does_not_leave(self):
        self.write("README.md", "A node.\n-----BEGIN " + "PRIVATE KEY-----\nMIIB\n-----END " + "PRIVATE KEY-----\n")
        self.commit()
        why = self.refused("good", "README.md")
        self.assertIn("README.md:2", why)
        self.assertIn("private key block", why)
        self.assertEqual(self.provider_calls(), [])

    def test_a_credential_with_no_name_beside_it_does_not_leave(self):
        jwt = "eyJ" + "hbGciOiJFUzI1NiJ9" + "." + "eyJ" + "zdWIiOiJhIn0" + "." + "c2lnbmF0dXJl"
        for label, text in (("JSON web token", "Authorization header: " + jwt),
                            ("credential prefix", "use " + "ghs_" + "Ab12Cd34Ef"),
                            ("credential prefix", "bot: " + "xoxb-" + "12345678-abc"),
                            ("credential prefix", "sk_" + "test_" + "4f9a8b7c6d"),
                            ("basic authorization", "Authori" + "zation: Basic " + "dXNlcjpodW50ZXIy")):
            with self.subTest(label=label, text=text):
                self.write("README.md", "A node.\n" + text + "\n")
                self.commit()
                self.assertIn(f"README.md:2: {label}", self.refused("good", "README.md"))
        self.assertEqual(self.provider_calls(), [])

    def test_the_scanner_that_judges_is_the_committed_one(self):
        # An edit of the working copy that would wave everything through changes nothing.
        self.write("tools/sync/scan-public.py", "def scan_text(rel, text, hosts_only, out):\n    pass\n")
        self.write("crates/x/secret.rs", f'const KEY: &str = "{SECRET}";\n')
        self.git("add", "crates/x/secret.rs")
        self.git("commit", "-q", "-m", "c")
        tool._SCANNERS.clear()
        self.assertIn("secret", self.refused("good", "crates/x/secret.rs"))
        self.git("rm", "-q", "--cached", "tools/sync/scan-public.py")
        self.git("commit", "-q", "-m", "c")
        tool._SCANNERS.clear()
        self.assertIn("the public scanner", self.refused("good", "README.md"))
        self.assertEqual(self.provider_calls(), [])

    def test_a_ledger_that_cannot_be_written_after_the_call_leaves_the_worst_case_charged(self):
        self.config["providers"]["locker"] = {**self.provider("ok"), "command": [
            sys.executable, "-c",
            "import json,os,sys; json.load(sys.stdin); os.chmod(sys.argv[1], 0o400); "
            "print(json.dumps({'text': 'done', 'input_tokens': 1, 'output_tokens': 1}))",
            self.config["ledger"]]}
        if os.geteuid() == 0:
            self.skipTest("the file owner's write bit does not stop root")
        self.assertEqual(self.review("locker", "README.md"), "done")
        (pending,) = self.ledger()
        self.assertEqual(pending["status"], "pending")
        self.assertAlmostEqual(self.total(), pending["usd"])

    def test_text_that_is_not_utf8_a_link_and_an_oversized_request_are_refused(self):
        with open(self.path("crates/x/blob.rs"), "wb") as f:
            f.write(b"\xff\xfe not text")
        os.symlink(self.path("internal/plan.md"), self.path("crates/x/link.rs"))
        self.write("crates/x/big.rs", "// x\n" * (tool.MAX_REQUEST_BYTES // 4))
        self.commit()
        self.assertIn("not UTF-8 text", self.refused("good", "crates/x/blob.rs"))
        self.assertIn("not a regular file in the HEAD commit", self.refused("good", "crates/x/link.rs"))
        self.assertIn("leave in one call", self.refused("good", "crates/x/big.rs"))
        self.assertIn("not inside this repository", self.refused("good", "../adapter.py"))
        self.assertEqual((self.provider_calls(), self.ledger()), ([], []))

    def test_a_call_that_could_pass_the_cap_is_refused(self):
        # One call's worst case: its request bytes as input tokens and the whole output allowance.
        self.config["cap_usd"] = tool.cost(self.config["providers"]["good"], 0, 1000)
        self.assertIn("this call could cost", self.refused("good", "README.md"))
        self.assertEqual((self.provider_calls(), self.ledger()), ([], []))

    def test_the_cap_counts_what_the_ledger_already_holds(self):
        worst = tool.cost(self.config["providers"]["good"], 200, 1000)
        self.config["cap_usd"] = worst * 1.5
        self.review("good", "README.md")
        with self.assertRaises(tool.Refused) as e:
            for _ in range(200):
                self.review("good", "README.md")
        self.assertIn("USD cap is spent", str(e.exception))
        self.assertLessEqual(self.total(), self.config["cap_usd"])
        self.assertEqual(len(self.provider_calls()) * 2, len(self.ledger()))

    def test_two_runs_at_once_cannot_both_pass_the_cap(self):
        self.config["providers"]["slow"] = self.provider("slow")
        self.config["cap_usd"] = tool.cost(self.config["providers"]["slow"], 400, 1000) * 1.5
        results = []

        def run():
            try:
                self.review("slow", "README.md")
                results.append("ok")
            except tool.Refused:
                results.append("refused")

        threads = [threading.Thread(target=run) for _ in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        self.assertEqual(sorted(results), ["ok", "refused"])
        self.assertEqual(len(self.provider_calls()), 1)

    def test_a_call_is_in_the_ledger_at_its_worst_case_while_it_runs(self):
        self.config["providers"]["hang"] = self.provider("hang", timeout_secs=1)
        self.assertIn("TimeoutExpired", self.refused("hang", "README.md"))
        pending, settled = self.ledger()
        self.assertEqual((pending["status"], settled["status"]), ("pending", "failed"))
        self.assertEqual(pending["usd"], settled["usd"])
        self.assertAlmostEqual(self.total(), pending["usd"])

    def test_an_answer_with_counts_that_cannot_be_right_keeps_the_worst_case_charge(self):
        bad = [
            {"text": "x", "input_tokens": -5, "output_tokens": 1},
            {"text": "x", "input_tokens": 1, "output_tokens": 10**30},
            {"text": "x", "input_tokens": 1.5, "output_tokens": 1},
            {"text": "x", "input_tokens": True, "output_tokens": 1},
            {"text": "x", "input_tokens": 1, "output_tokens": 1001},
            # A request is at least one token and an answer with text at least one: zero is not a count.
            {"text": "x", "input_tokens": 0, "output_tokens": 1},
            {"text": "x", "input_tokens": 1, "output_tokens": 0},
            {"text": "x", "input_tokens": 0, "output_tokens": 0},
            {"text": "x", "input_tokens": 1},
            {"text": 7, "input_tokens": 1, "output_tokens": 1},
            ["not", "an", "object"],
        ]
        for i, reply in enumerate(bad):
            with self.subTest(reply=reply):
                self.config["providers"][f"p{i}"] = self.provider("reply:" + json.dumps(reply))
                before = self.total() if self.ledger() else 0.0
                self.assertIn("failed", self.refused(f"p{i}", "README.md"))
                pending, settled = self.ledger()[-2:]
                self.assertEqual((settled["status"], settled["usd"]), ("failed", pending["usd"]))
                self.assertAlmostEqual(self.total(), before + pending["usd"])

    def test_a_provider_allowed_no_output_tokens_is_refused_before_it_runs(self):
        self.config["providers"]["none"] = self.provider("ok", max_output_tokens=0)
        self.assertIn("max_output_tokens", self.refused("none", "README.md"))
        self.assertEqual(self.provider_calls(), [])
        self.assertEqual(self.ledger(), [])

    def test_a_ledger_or_a_cap_that_cannot_be_read_refuses_every_call(self):
        for cap in (float("nan"), float("inf"), -1, "10", True, None):
            with self.subTest(cap=cap):
                self.config["cap_usd"] = cap
                self.assertIn("cap_usd must be a finite number", self.refused("good", "README.md"))
        self.config["cap_usd"] = 1.0
        for line in ("not json\n", '{"id": "a", "usd": NaN}\n', '{"id": "a", "usd": -1}\n', '{"usd": 1}\n'):
            with self.subTest(line=line):
                with open(self.config["ledger"], "w") as f:
                    f.write(line)
                self.assertIn("ledger line 1 cannot be read", self.refused("good", "README.md"))
        os.remove(self.config["ledger"])
        self.config["ledger"] = os.path.join(self.outside, "no-such-dir", "ledger.jsonl")
        self.assertIn("the ledger cannot be written", self.refused("good", "README.md"))
        self.assertEqual(self.provider_calls(), [])

    def test_no_cap_is_no_call(self):
        del self.config["cap_usd"]
        self.assertIn("names no cap_usd", self.refused("good", "README.md"))
        self.assertEqual(self.provider_calls(), [])

    def test_an_unknown_provider_is_refused_and_no_other_is_tried(self):
        self.assertIn("nothing else is tried", self.refused("other", "README.md"))
        self.assertEqual((self.provider_calls(), self.ledger()), ([], []))

    def test_a_failed_provider_is_not_replaced_and_its_worst_case_is_charged(self):
        self.assertIn("'broken' failed", self.refused("broken", "README.md"))
        self.assertEqual(len(self.provider_calls()), 1)
        pending, settled = self.ledger()
        self.assertEqual((settled["status"], settled["provider"], settled["usd"]), ("failed", "broken", pending["usd"]))

    def test_the_command_exits_1_on_a_refusal_and_2_on_a_bad_config(self):
        config = os.path.join(self.outside, "config.json")
        with open(config, "w") as f:
            json.dump(self.config, f)
        argv = ["llm-review.py", "--config", config, "--provider", "good"]
        self.assertEqual(tool.main(argv + [os.path.join(tool.ROOT, "tools", "sync", "stage.sh")]), 1)
        self.assertEqual(tool.main(["llm-review.py", "--config", os.path.join(self.outside, "none.json"), "--provider", "good", "x"]), 2)


if __name__ == "__main__":
    unittest.main()
