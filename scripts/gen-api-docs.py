#!/usr/bin/env python3
"""Generate docs/RPC.md (JSON-RPC), docs/MCP.md (MCP tools) and docs/NODE.md
(tenzro-node flags and subcommands) from the node's own source, plus
docs/rpc-methods.json (every served method and its access class) and
docs/cli-commands.json (every CLI command and its flags, from docs/CLI.md) for
sites and clients that check the names they use.

    python3 scripts/gen-api-docs.py            # write all three
    python3 scripts/gen-api-docs.py --check    # exit 1 if any is stale

Every method the node serves is named in exactly one of the three tables in
crates/tenzro-node/src/rpc_gates.rs; that is the method list. For each method
the entry is assembled from the code that defines it:

- access: the table it is in (and, for an open write, the reason it is open);
- summary: the MCP mirror table (crates/tenzro-node/src/mcp/rpc_tools.rs), else
  the doc comment of its SDK binding;
- params: the object the TypeScript SDK sends, plus the keys the handler reads;
- returns: the TypeScript SDK's result type and its @returns line;
- errors: the access refusal for its class, plus the messages its handler
  returns;
- bindings: the TypeScript, Rust and Python SDK functions that call it;
- example: a JSON-RPC request built from the params.

The test `api_docs` in tenzro-types fails when a served method or MCP tool has
no entry, or an entry names one the node no longer serves.
"""
import json
import os
import re
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
NODE = os.path.join(ROOT, "crates/tenzro-node/src")
OUT = os.path.join(ROOT, "docs/RPC.md")


def read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


def walk(base, exts):
    out = []
    for d, dirs, files in os.walk(base):
        dirs[:] = [x for x in dirs if x not in ("node_modules", "dist", "target", "__pycache__", "tests", "test")]
        for f in sorted(files):
            if f.endswith(exts):
                out.append(os.path.join(d, f))
    return sorted(out)


def strip_tests(text):
    """Drop a trailing `#[cfg(test)] mod tests` block (Rust)."""
    i = text.find("#[cfg(test)]\nmod tests")
    return text if i < 0 else text[:i]


# --- method tables -----------------------------------------------------------

gates = read(os.path.join(NODE, "rpc_gates.rs"))


def table(name):
    start = gates.index(f"pub const {name}")
    body = gates[start:gates.index("];", start)]
    out = []
    for line in body.splitlines()[1:]:
        code = line.split("//")[0]
        out.extend(re.findall(r'"([^"]+)"', code))
    return out


CLASS = {}
for cls, tbl in (("admin", "ADMIN_METHODS"), ("owner", "OWNER_METHODS"), ("open", "OPEN_METHODS")):
    for m in table(tbl):
        CLASS[m] = cls

OPEN_WRITES = {}
start = gates.index("pub const OPEN_WRITES")
body = gates[start:gates.index("];", start)]
for m, reason in re.findall(r'\(\s*"([^"]+)",\s*"((?:[^"\\]|\\.)*)"', body, re.S):
    OPEN_WRITES[m] = reason

METHODS = sorted(CLASS)

# --- MCP mirror descriptions ---------------------------------------------------

TOOLS = {}
rt = read(os.path.join(NODE, "mcp/rpc_tools.rs"))
for m, name, desc in re.findall(
    r'method:\s*"([^"]+)",\s*name:\s*"([^"]+)",\s*access:\s*Access::\w+,\s*description:\s*"((?:[^"\\]|\\.)*)"', rt, re.S
):
    TOOLS[m] = (name, desc.replace('\\"', '"'))

# --- helpers -------------------------------------------------------------------


def match_close(text, i, open_ch="(", close_ch=")", quotes='"'):
    """Index just past the bracket that closes text[i] (which is open_ch)."""
    depth = 0
    in_str = None
    j = i
    while j < len(text):
        c = text[j]
        if in_str:
            if c == "\\":
                j += 2
                continue
            if c == in_str:
                in_str = None
        elif c in quotes:
            in_str = c
        elif c == open_ch:
            depth += 1
        elif c == close_ch:
            depth -= 1
            if depth == 0:
                return j + 1
        j += 1
    return len(text)


def clean_doc(lines):
    text = " ".join(l.strip() for l in lines if l.strip())
    return re.sub(r"\s+", " ", text).strip()


# --- TypeScript SDK bindings ----------------------------------------------------

TS_SIG = re.compile(r"^\s*(?:public\s+|static\s+|private\s+)*(?:async\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*(?:<[^>]*>)?\s*\(")
TS = {}
for path in walk(os.path.join(ROOT, "sdk/tenzro-ts-sdk/src"), (".ts",)):
    text = read(path)
    lines = text.splitlines()
    offsets = [0]
    for l in lines:
        offsets.append(offsets[-1] + len(l) + 1)
    for mo in re.finditer(r"""\.call(?:<((?:[^<>]|<[^<>]*>)*)>)?\(\s*["']([A-Za-z0-9_]+)["']\s*(,)?""", text):
        method = mo.group(2)
        if method not in CLASS or method in TS:
            continue
        rtype = (mo.group(1) or "").strip()
        params = ""
        if mo.group(3):
            open_paren = text.rfind("(", 0, mo.start(2))
            end = match_close(text, open_paren, quotes="\"'`")
            params = text[mo.end():end - 1].strip().rstrip(",").strip()
        line_no = text.count("\n", 0, mo.start())
        fn, sig, doc = None, "", []
        for k in range(line_no, max(-1, line_no - 80), -1):
            s = TS_SIG.match(lines[k])
            if s and s.group(1) not in ("if", "for", "while", "switch", "catch", "return", "function"):
                fn = s.group(1)
                sig = lines[k].strip().rstrip("{").strip()
                # JSDoc directly above
                j = k - 1
                if j >= 0 and lines[j].strip().endswith("*/"):
                    block = []
                    while j >= 0:
                        block.insert(0, lines[j].strip())
                        if lines[j].strip().startswith("/**"):
                            break
                        j -= 1
                    doc = [b.lstrip("/*").rstrip("*/").strip() for b in block]
                break
        TS[method] = {
            "fn": fn,
            "sig": sig,
            "params": params,
            "rtype": rtype,
            "doc": doc,
            "file": os.path.relpath(path, ROOT),
        }

# --- Rust SDK bindings -----------------------------------------------------------

RS = {}
for path in walk(os.path.join(ROOT, "sdk/tenzro-sdk/src"), (".rs",)):
    text = strip_tests(read(path))
    lines = text.splitlines()
    for i, l in enumerate(lines):
        for method in re.findall(r'"([A-Za-z0-9_]+)"', l):
            if method not in CLASS or method in RS:
                continue
            for k in range(i, max(-1, i - 60), -1):
                s = re.match(r"\s*pub(?:\(crate\))?\s+(?:async\s+)?fn\s+([a-z0-9_]+)", lines[k])
                if s:
                    doc = []
                    j = k - 1
                    while j >= 0 and lines[j].strip().startswith(("///", "#[")):
                        if lines[j].strip().startswith("///"):
                            doc.insert(0, lines[j].strip()[3:].strip())
                        j -= 1
                    RS[method] = {"fn": s.group(1), "doc": doc, "file": os.path.relpath(path, ROOT)}
                    break

# --- Python SDK bindings ---------------------------------------------------------

PY = {}
py_base = os.path.join(ROOT, "sdk/tenzro-py/tenzro")
if os.path.isdir(py_base):
    for path in walk(py_base, (".py",)):
        text = read(path)
        lines = text.splitlines()
        for i, l in enumerate(lines):
            for method in re.findall(r'"([A-Za-z0-9_]+)"', l):
                if method not in CLASS or method in PY:
                    continue
                for k in range(i, max(-1, i - 60), -1):
                    s = re.match(r"\s*(?:async\s+)?def\s+([a-z0-9_]+)\s*\(", lines[k])
                    if s and not s.group(1).startswith("_"):
                        PY[method] = {"fn": s.group(1), "file": os.path.relpath(path, ROOT)}
                        break

# --- Node handlers: params read and errors returned ------------------------------

FN_BODIES = {}
FN_DOCS = {}
NODE_FILES = {}
for path in walk(NODE, (".rs",)):
    text = strip_tests(read(path))
    NODE_FILES[path] = text
    for mo in re.finditer(r"\bfn\s+([a-z0-9_]+)\s*(?:<[^>]*>)?\s*\(", text):
        brace = text.find("{", mo.end())
        semi = text.find(";", mo.end())
        if brace < 0 or (0 <= semi < brace):
            continue
        end = match_close(text, brace, "{", "}")
        mod = os.path.splitext(os.path.basename(path))[0]
        FN_BODIES.setdefault(mo.group(1), []).append((mod, text[brace:end]))
        before = text[:mo.start()].splitlines()
        doc = []
        k = len(before) - 1
        while k >= 0 and before[k].strip().startswith(("///", "#[", "pub", "async")) or (k >= 0 and before[k].strip() == "" and not doc and k == len(before) - 1):
            line = before[k].strip()
            if line.startswith("///"):
                doc.insert(0, line[3:].strip())
            elif not line.startswith("#[") and line not in ("", "pub", "pub(crate)", "async", "pub(crate) async", "pub async"):
                break
            k -= 1
        if doc:
            FN_DOCS.setdefault(mo.group(1), clean_doc(doc[:6]))


def arm_text(method):
    pat = re.compile(r'"' + re.escape(method) + r'"(?:\s*\|\s*"[^"]+")*\s*=>')
    for path, text in NODE_FILES.items():
        mo = pat.search(text)
        if not mo:
            continue
        rest = text[mo.end():]
        stripped = rest.lstrip()
        off = mo.end() + (len(rest) - len(stripped))
        if stripped.startswith("{"):
            return text[off:match_close(text, off, "{", "}")]
        # expression arm: up to the next top-level comma
        depth = 0
        j = off
        while j < len(text):
            c = text[j]
            if c in "({[":
                depth += 1
            elif c in ")}]":
                depth -= 1
                if depth < 0:
                    break
            elif c == "," and depth == 0:
                break
            j += 1
        return text[off:j]
    return ""


SKIP_CALLS = {
    "ok_or_else", "map_err", "unwrap_or", "get", "as_str", "as_u64", "as_array", "to_string", "json", "format",
    "Ok", "Err", "Some", "clone", "await", "map", "and_then", "into", "iter", "collect", "len", "is_empty",
}


def handler_bodies(arm):
    bodies = [arm]
    for qual, name in re.findall(r"\b((?:[a-z_]+::)*)([a-z_][a-z0-9_]*)\s*\(", arm):
        if name in SKIP_CALLS or name not in FN_BODIES:
            continue
        cands = FN_BODIES[name]
        mod = qual.rstrip(":").split("::")[-1] if qual else None
        pick = [b for m, b in cands if m == mod] or ([cands[0][1]] if len(cands) == 1 else [])
        bodies.extend(pick[:1])
    # A handler that forwards to a provider first serves the rest on this
    # node in `<name>_here`, which the light build replaces with a refusal;
    # the facts are the standard build's, the longest of the definitions.
    for body in list(bodies[1:]):
        for name in re.findall(r"\b([a-z_][a-z0-9_]*_here)\s*\(", body):
            cands = FN_BODIES.get(name, [])
            if cands:
                bodies.append(max((b for _, b in cands), key=len))
    return bodies


ERR_PATTERNS = [
    re.compile(r'message:\s*"((?:[^"\\]|\\.){4,})"'),
    re.compile(r'message:\s*format!\(\s*"((?:[^"\\]|\\.){4,})"'),
    re.compile(r'\b(?:bad|invalid_params|invalid|not_found|internal|refuse|denied|forbidden)\(\s*"((?:[^"\\]|\\.){4,})"'),
    re.compile(r'\b(?:bad|invalid_params|invalid|not_found|internal|refuse|denied|forbidden)\(\s*format!\(\s*"((?:[^"\\]|\\.){4,})"'),
]
PARAM_PATTERNS = [
    re.compile(r'\b(?:params|p|obj|args|req|body)\s*\.get\(\s*"([A-Za-z0-9_]+)"\s*\)'),
    re.compile(r'\b(?:params|p|obj|args|req|body)\s*\[\s*"([A-Za-z0-9_]+)"\s*\]'),
    re.compile(r'\b(?:req_str|opt_str|req_u64|opt_u64|req_bool|opt_bool|req_hex|opt_hex|param_[a-z_]+|parse_[a-z0-9_]+)\(\s*&?[a-z_]+\s*,\s*"([A-Za-z0-9_]+)"'),
]


def handler_facts(method):
    arm = arm_text(method)
    if not arm:
        return [], [], []
    params, errors, codes = [], [], []
    for body in handler_bodies(arm):
        for pat in PARAM_PATTERNS:
            for k in pat.findall(body):
                if k not in params:
                    params.append(k)
        for pat in ERR_PATTERNS:
            for e in pat.findall(body):
                e = e.replace('\\"', '"')
                e = re.sub(r"\{[^}]*\}", "…", e)
                if e not in errors:
                    errors.append(e)
        for c in re.findall(r"code:\s*(-32\d{3})", body):
            if c not in codes:
                codes.append(c)
    return params[:16], errors[:10], codes


# --- Typed MCP tools ----------------------------------------------------------------


def rust_string(expr):
    """Join the string literals of a Rust expression (handles `concat!`)."""
    parts = re.findall(r'"((?:[^"\\]|\\.)*)"', expr, re.S)
    joined = "".join(parts)
    joined = re.sub(r"\\\n\s*", "", joined)
    return joined.replace('\\"', '"').replace("\\n", " ")


PARAM_STRUCTS = {}
for path in walk(os.path.join(NODE, "mcp"), (".rs",)):
    text = strip_tests(read(path))
    for mo in re.finditer(r"pub struct ([A-Za-z0-9_]+)\s*\{", text):
        end = match_close(text, mo.end() - 1, "{", "}")
        body = text[mo.end():end - 1]
        fields, doc, optional = [], [], False
        # An attribute rustfmt wraps over several lines is read as one line.
        lines, pending = [], None
        for line in body.splitlines():
            s = line.strip()
            if pending is not None:
                pending += " " + s
                if pending.endswith("]"):
                    lines.append(pending)
                    pending = None
            elif s.startswith("#[") and not s.endswith("]"):
                pending = s
            else:
                lines.append(s)
        for s in lines:
            if s.startswith("///"):
                doc.append(s[3:].strip())
            elif s.startswith("#[schemars(") and "description" in s:
                doc.append(rust_string(s))
            elif s.startswith("#[serde(") and "default" in s:
                optional = True
            elif s.startswith("#["):
                continue
            else:
                f = re.match(r"pub\s+(?:r#)?([a-z0-9_]+)\s*:\s*(.+?),?$", s)
                if f:
                    ty = f.group(2).rstrip(",")
                    fields.append({
                        "name": f.group(1),
                        "type": ty,
                        "optional": optional or ty.startswith("Option<"),
                        "doc": clean_doc(doc),
                    })
                    doc, optional = [], False
        PARAM_STRUCTS[mo.group(1)] = fields

MCP_TYPED = []
server_src = strip_tests(read(os.path.join(NODE, "mcp/server.rs")))
for mo in re.finditer(r"#\[tool\(", server_src):
    attr_end = match_close(server_src, mo.end() - 1)
    attr = server_src[mo.end():attr_end - 1]
    dm = re.search(r"description\s*=\s*(.*)", attr, re.S)
    desc = rust_string(dm.group(1)) if dm else ""
    nm = re.search(r'\bname\s*=\s*"([^"]+)"', attr)
    fn = re.search(r"async\s+fn\s+([a-z0-9_]+)\s*\(", server_src[attr_end:attr_end + 400])
    if not fn:
        continue
    fn_start = attr_end + fn.start()
    brace = server_src.find("{", fn_start)
    sig = server_src[fn_start:brace]
    ptype = re.search(r"Parameters<([A-Za-z0-9_]+)>", sig)
    body_end = match_close(server_src, brace, "{", "}")
    body = server_src[brace:body_end]
    methods = [m for m in dict.fromkeys(re.findall(r'"([A-Za-z0-9_]+)"', body)) if m in CLASS]
    MCP_TYPED.append({
        "name": nm.group(1) if nm else fn.group(1),
        "desc": re.sub(r"\s+", " ", desc).strip(),
        "params": PARAM_STRUCTS.get(ptype.group(1), []) if ptype else [],
        "ptype": ptype.group(1) if ptype else None,
        "methods": methods,
        "read_only": "read_only_hint = true" in attr or "readOnlyHint" in attr,
    })

MCP_BY_METHOD = {}
for t in MCP_TYPED:
    for m in t["methods"]:
        MCP_BY_METHOD.setdefault(m, t)

# --- rendering ----------------------------------------------------------------------

ACCESS_TEXT = {
    "admin": "Admin: the caller must be the operator DID or an admin named in the node's access policy; "
    "anyone else is refused before the handler runs.",
    "owner": "Owner: any caller reaches the handler, which checks a proof from the owner of what is changed "
    "(a signed DID envelope, an address signature, a passkey assertion or a DPoP-bound access token).",
    "open": "Open: a read or stateless computation; no credentials needed beyond the node's access policy for the surface.",
}
GATE_ERRORS = {
    "admin": "Refused before dispatch when the caller is not the operator or a policy admin.",
    "owner": "Refused by the handler when the owner's proof is missing, malformed or does not verify.",
    "open": None,
}


def placeholder(key):
    k = key.lower()
    if k.endswith("did") or k == "did":
        return "did:tenzro:human:…"
    if "address" in k or k in ("from", "to", "payer", "payee", "owner", "account"):
        return "0x…"
    if "hash" in k or k.endswith("_id") or k == "id":
        return "0x…"
    if k in ("amount", "value", "fee", "max_fee", "limit", "offset", "height", "nonce", "count", "seq", "epoch"):
        return 0
    if k.startswith(("is_", "enable", "include")):
        return False
    return "…"


def ts_sig_types(sig):
    """Map each parameter of a TS method signature to its type."""
    m = re.search(r"\((.*)\)", sig)
    out = {}
    if not m:
        return out
    depth, token, parts = 0, "", []
    for c in m.group(1):
        if c in "<({[":
            depth += 1
        elif c in ">)}]":
            depth -= 1
        if c == "," and depth == 0:
            parts.append(token)
            token = ""
        else:
            token += c
    parts.append(token)
    for part in parts:
        nm = re.match(r"\s*([A-Za-z0-9_]+)(\??)\s*:\s*(.+?)\s*(?:=.*)?$", part)
        if nm:
            out[nm.group(1)] = (nm.group(3).strip(), nm.group(2) == "?")
    return out


def ts_param_values(expr):
    """Map each key of a TS object literal to the identifier it is set from."""
    out = {}
    for k, v in re.findall(r"([A-Za-z0-9_]+)\s*:\s*([A-Za-z0-9_.]+)", expr):
        out.setdefault(k, v)
    for k in re.findall(r"[{,]\s*([A-Za-z0-9_]+)\s*(?=[,}])", expr):
        out.setdefault(k, k)
    return out


def ts_param_keys(expr):
    if not expr.startswith("{"):
        return []
    keys = []
    depth = 0
    token = ""
    for c in expr[1:]:
        if c in "{[(":
            depth += 1
        elif c in "}])":
            depth -= 1
        if depth == 0 and c in ",}":
            t = token.strip()
            if t.startswith("..."):
                token = ""
                continue
            name = re.match(r"([A-Za-z0-9_]+)\s*(:|$)", t)
            if name:
                keys.append(name.group(1))
            token = ""
            continue
        token += c
    return keys


def example(method, keys, ts_expr):
    if keys:
        params = {k: placeholder(k) for k in keys}
    elif ts_expr.startswith("["):
        params = ["…"]
    else:
        params = []
    req = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params}
    return json.dumps(req, ensure_ascii=False)


def summary(method):
    if method in TOOLS:
        return TOOLS[method][1]
    typed = MCP_BY_METHOD.get(method)
    if typed and len(typed["methods"]) == 1 and typed["desc"]:
        return typed["desc"]
    ts = TS.get(method)
    if ts and ts["doc"]:
        lines = [l for l in ts["doc"] if l and not l.startswith("@")]
        if lines:
            return clean_doc(lines)
    rs = RS.get(method)
    if rs and rs["doc"]:
        return clean_doc(rs["doc"][:6])
    for qual, name in re.findall(r"\b((?:[a-z_]+::)*)([a-z_][a-z0-9_]*)\s*\(", arm_text(method)):
        if name in FN_DOCS and name not in SKIP_CALLS:
            return FN_DOCS[name]
    if method.startswith(("eth_", "net_", "web3_")):
        return "Ethereum JSON-RPC method, served for EVM wallets and libraries with the standard semantics; `eth_chainId` returns the chain id the network's genesis sets."
    if not method.startswith("tenzro_"):
        return "Solana JSON-RPC method, served for Solana wallets and libraries with the standard semantics."
    return ""


def namespace(method):
    if method.startswith("tenzro_"):
        return "tenzro"
    if "_" in method:
        return method.split("_", 1)[0]
    return "solana"


def render():
    out = []
    counts = {"admin": 0, "owner": 0, "open": 0}
    for m in METHODS:
        counts[CLASS[m]] += 1
    out.append("# JSON-RPC reference")
    out.append("")
    out.append("<!-- Generated by scripts/gen-api-docs.py from the node's source. Do not edit by hand. -->")
    out.append("")
    out.append(
        f"The node serves {len(METHODS)} JSON-RPC methods as `POST /` on its RPC listener "
        f"({counts['open']} open, {counts['owner']} owner-proved, {counts['admin']} admin). "
        "Every request is a JSON-RPC 2.0 object; `params` is an object unless an entry says otherwise. "
        "Who may reach the endpoint at all is the node's access policy (see [ACCESS.md](ACCESS.md)); "
        "each entry below says what the method itself requires on top of that."
    )
    out.append("")
    out.append("Common errors on every method:")
    out.append("")
    out.append("| Code | Meaning |")
    out.append("|---|---|")
    out.append("| -32700 | The body is not valid JSON. |")
    out.append("| -32600 | The request is not a JSON-RPC 2.0 object. |")
    out.append("| -32601 | Method not found: the node does not serve this name. |")
    out.append("| -32602 | Invalid params: a required field is missing or malformed. |")
    out.append("| -32000 | The node could not complete the call; the message says why. |")
    out.append("")
    out.append(
        "The SDKs bind these methods by name: TypeScript `tenzro-sdk`, Rust `tenzro-sdk`, Python `tenzro`. "
        "The CLI reference is [CLI.md](CLI.md) and the MCP tools are listed in [MCP.md](MCP.md)."
    )
    out.append("")
    groups = {}
    for m in METHODS:
        groups.setdefault(namespace(m), []).append(m)
    out.append("## Contents")
    out.append("")
    for ns in sorted(groups):
        out.append(f"- [{ns}](#namespace-{ns}) ({len(groups[ns])})")
    out.append("")
    for ns in sorted(groups):
        out.append(f"## Namespace {ns}")
        out.append("")
        for m in groups[ns]:
            cls = CLASS[m]
            ts = TS.get(m, {})
            rs = RS.get(m)
            py = PY.get(m)
            hparams, herrors, _codes = handler_facts(m)
            ts_expr = ts.get("params", "")
            keys = ts_param_keys(ts_expr)
            for k in hparams:
                if k not in keys:
                    keys.append(k)
            out.append(f"### `{m}`")
            out.append("")
            s = summary(m)
            if s:
                out.append(s)
                out.append("")
            access = ACCESS_TEXT[cls]
            if m in OPEN_WRITES:
                access = "Open write: " + OPEN_WRITES[m]
            out.append(f"**Access.** {access}")
            out.append("")
            out.append("**Params.**")
            if keys:
                out.append("")
                types = ts_sig_types(ts.get("sig", ""))
                values = ts_param_values(ts_expr)
                for k in keys:
                    v = values.get(k, "")
                    t = types.get(v.split(".")[0]) if v else None
                    if t:
                        out.append(f"- `{k}` ({'optional ' if t[1] else ''}`{t[0]}`)")
                    else:
                        out.append(f"- `{k}`")
            elif ts_expr.startswith("["):
                out.append(f" Positional: `{ts_expr}`.")
            elif not m.startswith("tenzro_"):
                out.append(" Positional, as the " + ("Ethereum" if namespace(m) in ("eth", "net", "web3") else "Solana") + " JSON-RPC specification defines them.")
            else:
                out.append(" None.")
            out.append("")
            rtype = ts.get("rtype", "")
            ret_doc = [l for l in ts.get("doc", []) if l.startswith("@returns")]
            ret = []
            if rtype:
                ret.append(f"`{rtype}`")
            if ret_doc:
                ret.append(ret_doc[0][len("@returns"):].strip(" -"))
            if not ret and not m.startswith("tenzro_"):
                ret.append("As the " + ("Ethereum" if namespace(m) in ("eth", "net", "web3") else "Solana") + " JSON-RPC specification defines it.")
            out.append("**Returns.** " + (" ".join(ret) if ret else "The method's result object; see the SDK binding for its type."))
            out.append("")
            errs = []
            if GATE_ERRORS[cls]:
                errs.append(GATE_ERRORS[cls])
            errs.extend(herrors)
            out.append("**Errors.**" + ("" if errs else " Only the common errors above."))
            if errs:
                out.append("")
                for e in errs:
                    out.append(f"- {e}")
            out.append("")
            b = []
            if ts.get("fn"):
                b.append(f"TypeScript `{ts['fn']}`")
            if rs:
                b.append(f"Rust `{rs['fn']}`")
            if py:
                b.append(f"Python `{py['fn']}`")
            if m in TOOLS:
                b.append(f"MCP `{TOOLS[m][0]}`")
            if b:
                out.append("**Bindings.** " + ", ".join(b) + ".")
                out.append("")
            out.append("**Example.**")
            out.append("")
            out.append("```json")
            out.append(example(m, keys, ts_expr))
            out.append("```")
            out.append("")
    return "\n".join(out).rstrip() + "\n"


MCP_OUT = os.path.join(ROOT, "docs/MCP.md")
NODE_OUT = os.path.join(ROOT, "docs/NODE.md")
# Hand-written sections appended to NODE.md, in order.
NODE_PROSE = ["docs/operations/light-build.md"]
METHODS_OUT = os.path.join(ROOT, "docs/rpc-methods.json")
CLI_OUT = os.path.join(ROOT, "docs/cli-commands.json")


def cli_commands():
    """Every `tenzro` command path in docs/CLI.md with the flags it takes."""
    text = read(os.path.join(ROOT, "docs/CLI.md"))
    out = {}
    for mo in re.finditer(r"^#{2,6} `(tenzro(?: [a-z0-9-]+)*)`\n+```\n(.*?)```", text, re.S | re.M):
        flags = sorted(set(re.findall(r"^\s+(?:-[A-Za-z], )?(--[a-z0-9-]+)", mo.group(2), re.M)))
        shorts = sorted(set(re.findall(r"^\s+(-[A-Za-z])[, ]", mo.group(2), re.M)))
        out[mo.group(1)] = flags + shorts
    return out


def clap_fields(body):
    """Fields of a clap derive struct or enum variant: docs and #[arg] attributes."""
    out, doc, attrs = [], [], []
    pending = None  # an attribute whose parentheses span several lines
    for line in body.splitlines():
        s = line.strip()
        if pending is not None:
            pending += " " + s
            if pending.count("(") <= pending.count(")"):
                attrs.append(pending)
                pending = None
            continue
        if (s.startswith("#[arg(") or s.startswith("#[clap(")) and s.count("(") > s.count(")"):
            pending = s
            continue
        if s.startswith("///"):
            doc.append(s[3:].strip())
        elif s.startswith("#[arg(") or s.startswith("#[clap("):
            attrs.append(s)
        elif s.startswith("#[command(subcommand"):
            doc, attrs = [], []
        elif s.startswith("#["):
            continue
        else:
            f = re.match(r"(?:pub\s+)?([a-z_][a-z0-9_]*)\s*:\s*(.+?),?$", s)
            if f and attrs is not None:
                attr = " ".join(attrs)
                if "subcommand" in attr:
                    doc, attrs = [], []
                    continue
                long = re.search(r'long\s*=\s*"([^"]+)"', attr)
                name = long.group(1) if long else f.group(1).replace("_", "-")
                short = re.search(r"short\s*=\s*'(.)'", attr)
                if re.search(r"\bshort\b(?!\s*=)", attr) and not short:
                    short_flag = name[0]
                else:
                    short_flag = short.group(1) if short else None
                positional = not re.search(r"\blong\b", attr)
                env = re.search(r'env\s*=\s*"([^"]+)"', attr)
                default = re.search(r'default_value(?:_t)?\s*=\s*("?[^",)]+"?)', attr)
                value = re.search(r'value_name\s*=\s*"([^"]+)"', attr)
                out.append({
                    "flag": (f"<{f.group(1).upper()}>" if positional else f"--{name}"),
                    "short": short_flag,
                    "value": value.group(1) if value else None,
                    "env": env.group(1) if env else None,
                    "default": default.group(1).strip('"') if default else None,
                    "type": f.group(2).rstrip(","),
                    "doc": clean_doc(doc),
                })
                doc, attrs = [], []
    return out


def render_node():
    src = read(os.path.join(NODE, "main.rs"))
    start = src.index("struct Cli {")
    cli_body = src[start + len("struct Cli {"):match_close(src, start + len("struct Cli "), "{", "}") - 1]
    estart = src.index("enum Command {")
    enum_body = src[estart + len("enum Command {"):match_close(src, estart + len("enum Command "), "{", "}") - 1]
    out = ["# tenzro-node reference", "",
           "<!-- Generated by scripts/gen-api-docs.py from crates/tenzro-node/src/main.rs. Do not edit by hand. -->", "",
           "Every flag and subcommand of the `tenzro-node` binary, from its own argument definitions. "
           "Run `tenzro-node --help` for the same text on your build. The CLI (`tenzro`) is in [CLI.md](CLI.md); "
           "how to deploy a node is in [GUIDE.md](GUIDE.md).", "", "## Flags", "",
           "| Flag | Value | Environment | Default | Description |", "|---|---|---|---|---|"]

    def row(f):
        flag = f"`{f['flag']}`" + (f" / `-{f['short']}`" if f["short"] else "")
        val = f"`{f['value']}`" if f["value"] else ("" if f["type"] == "bool" else f"`{f['type']}`")
        env = f"`{f['env']}`" if f["env"] else ""
        dflt = f"`{f['default']}`" if f["default"] else ""
        return f"| {flag} | {val} | {env} | {dflt} | {f['doc'].replace('|', '\\|')} |"

    for f in clap_fields(cli_body):
        out.append(row(f))
    out += ["", "## Subcommands", ""]
    # variants: doc comments, attributes, then `Name {` or `Name,`
    i = 0
    lines = enum_body.splitlines()
    doc, attrs = [], []
    while i < len(lines):
        s = lines[i].strip()
        if s.startswith("///"):
            doc.append(s[3:].strip())
        elif s.startswith("#[command("):
            attrs.append(s)
        elif re.match(r"[A-Z][A-Za-z0-9]*\s*(\{|,|\()", s):
            vname = re.match(r"([A-Z][A-Za-z0-9]*)", s).group(1)
            named = re.search(r'name\s*=\s*"([^"]+)"', " ".join(attrs))
            cmd = named.group(1) if named else re.sub(r"(?<!^)([A-Z])", r"-\1", vname).lower()
            fields_body = ""
            if s.endswith("{"):
                depth, j, buf = 1, i + 1, []
                while j < len(lines) and depth:
                    depth += lines[j].count("{") - lines[j].count("}")
                    if depth:
                        buf.append(lines[j])
                    j += 1
                fields_body = "\n".join(buf)
                i = j - 1
            out.append(f"### `tenzro-node {cmd}`")
            out.append("")
            if doc:
                out.append(clean_doc(doc))
                out.append("")
            fields = clap_fields(fields_body) if fields_body else []
            if fields:
                out += ["| Flag | Value | Environment | Default | Description |", "|---|---|---|---|---|"]
                out += [row(f) for f in fields]
                out.append("")
            doc, attrs = [], []
        i += 1
    # Prose that is not in the argument definitions, kept beside this page and
    # carried into it verbatim.
    for part in NODE_PROSE:
        out += ["", read(os.path.join(ROOT, part)).rstrip()]
    return "\n".join(out).rstrip() + "\n"

ACCESS_MIRROR = {
    "Read": "Read-only.",
    "OpenWrite": "Open write: permissionless by design.",
    "Owner": "Owner: the method checks the owner's proof carried in `params`.",
    "Operator": "Operator: the node's operator DID or a policy admin.",
}


def mcp_placeholder(field):
    t = field["type"]
    inner = re.sub(r"^Option<(.*)>$", r"\1", t)
    if inner in ("bool",):
        return False
    if re.match(r"^(u|i)(8|16|32|64|128|size)$|^f(32|64)$", inner):
        return 0
    if inner.startswith("Vec<"):
        return []
    if inner in ("Value", "serde_json::Value", "JsonObject") or inner.endswith("Map<String, Value>"):
        return {}
    return placeholder(field["name"])


def render_mcp():
    out = []
    mirror_rows = re.findall(
        r'method:\s*"([^"]+)",\s*name:\s*"([^"]+)",\s*access:\s*Access::(\w+),\s*description:\s*"((?:[^"\\]|\\.)*)"', rt, re.S
    )
    typed = sorted(MCP_TYPED, key=lambda t: t["name"])
    total = len(typed) + len(mirror_rows)
    out.append("# MCP tools")
    out.append("")
    out.append("<!-- Generated by scripts/gen-api-docs.py from the node's source. Do not edit by hand. -->")
    out.append("")
    out.append(
        f"The node serves {total} Model Context Protocol tools over Streamable HTTP at `/mcp`: "
        f"{len(typed)} typed tools with their own input schema, and {len(mirror_rows)} mirror tools that each "
        "forward a `params` object to one JSON-RPC method. Every tool runs under the caller's own credentials: "
        "the method's gate applies exactly as on JSON-RPC (see [RPC.md](RPC.md)), and no tool signs with a user key. "
        "Who may reach `/mcp` at all is the node's access policy for the `mcp` surface (see [ACCESS.md](ACCESS.md))."
    )
    out.append("")
    out.append(
        "`/mcp/compact` serves the same tools behind two: `search` finds tools by words in their name, "
        "description or JSON-RPC method and returns each match with its exact input and output schema, and "
        "`call` invokes one by name, its arguments checked against that schema first. A `call` takes the same "
        "path as calling the tool on `/mcp`: the same credentials, agent terms, spend limits, receipts and audit. "
        "An unknown tool or arguments the schema refuses are invalid params, with `data.reason` "
        "`unknown_tool` or `invalid_arguments`."
    )
    out.append("")
    out.append(
        "Protocol revision. The node speaks MCP revision 2026-07-28 and no other, and `server/discover` lists "
        "exactly that. The revision has no `initialize` handshake and no session: a client opens with "
        "`server/discover`, or with any request, and every request carries `_meta` with "
        "`io.modelcontextprotocol/protocolVersion` and `io.modelcontextprotocol/clientCapabilities` "
        "(`io.modelcontextprotocol/clientInfo` is optional). A request missing either key is invalid params "
        "(-32602) naming the missing keys. A request whose `_meta` names another revision, and an `initialize` "
        "request naming any revision, is refused with -32022 `Unsupported protocol version`; its `data` carries "
        "`requested`, `supported` (the revisions listed above) and, for `initialize`, `opener` (`server/discover`). "
        "Clients that only speak an earlier revision, which opens with `initialize`, are not served."
    )
    out.append("")
    out.append(
        "Two transports carry the same protocol. Streamable HTTP at `/mcp` is stateless with JSON replies; each "
        "POST sends `MCP-Protocol-Version` and `Mcp-Method` (and `Mcp-Name` for `tools/call`) and is gated by the "
        "node's access policy. The iroh ALPN `tenzro/mcp` runs one session per bidirectional stream as "
        "newline-delimited JSON-RPC 2.0; the first line may be `server/discover` or any request with the `_meta` "
        "above, and every later line carries it too. The stream has no credential and no verified caller, so "
        "over iroh only the read-only tools are listed and callable; any other tool, including one that changes "
        "state, is refused with -32600 `not authorized over the iroh MCP transport` before it runs. For gated "
        "inference use the `tenzro/infer` ALPN."
    )
    out.append("")
    out.append(
        "Resources are the one template `tenzro://events{?filter,from_cursor}` (`resources/templates/list`); "
        "`resources/list` is empty, `resources/read` returns the next page of chain events with proofs, and "
        "`resources/subscribe` sends `notifications/resources/updated`. The agent surface (A2A 1.0) is separate: "
        "JSON-RPC at `/a2a` over HTTPS with the `A2A-Version: 1.0` header, and over the iroh ALPN `tenzro/a2a` "
        "(unary methods only; `SendStreamingMessage` needs HTTPS). `SendMessage` and `CancelTask` need the DID "
        "envelope on both."
    )
    out.append("")
    out.append(
        "Errors come back as MCP tool errors carrying the JSON-RPC error of the method the tool called "
        "(code and message), or an invalid-params error when the arguments do not match the input schema."
    )
    out.append("")
    out.append("## Typed tools")
    out.append("")
    for t in typed:
        out.append(f"### `{t['name']}`")
        out.append("")
        if t["desc"]:
            out.append(t["desc"])
            out.append("")
        out.append("**Input.**" + ("" if t["params"] else " None."))
        if t["params"]:
            out.append("")
            out.append("| Field | Type | Required | Description |")
            out.append("|---|---|---|---|")
            for f in t["params"]:
                doc = f["doc"].replace("|", "\\|")
                out.append(f"| `{f['name']}` | `{f['type']}` | {'no' if f['optional'] else 'yes'} | {doc} |")
        out.append("")
        if t["methods"]:
            out.append("**Calls.** " + ", ".join(f"`{m}`" for m in t["methods"]) + " (see [RPC.md](RPC.md)).")
            out.append("")
        args = {f["name"]: mcp_placeholder(f) for f in t["params"] if not f["optional"]}
        call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": t["name"], "arguments": args}}
        out.append("**Example.**")
        out.append("")
        out.append("```json")
        out.append(json.dumps(call, ensure_ascii=False))
        out.append("```")
        out.append("")
    out.append("## Mirror tools")
    out.append("")
    out.append(
        "Each mirror tool takes one argument, `params` (object or array), passes it to its method unchanged and "
        "returns `{ \"result\": ... }`. The params, result and errors are the method's own; follow the link."
    )
    out.append("")
    for method, name, access, desc in sorted(mirror_rows, key=lambda r: r[1]):
        out.append(f"### `{name}`")
        out.append("")
        out.append(desc.replace('\\"', '"'))
        out.append("")
        out.append(f"**Access.** {ACCESS_MIRROR.get(access, access)} **Calls.** [`{method}`](RPC.md#{method.lower()}).")
        out.append("")
        call = {"jsonrpc": "2.0", "id": 1, "method": "tools/call", "params": {"name": name, "arguments": {"params": {}}}}
        out.append("```json")
        out.append(json.dumps(call, ensure_ascii=False))
        out.append("```")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def main():
    text = render()
    mcp = render_mcp()
    node = render_node()
    methods_json = json.dumps({m: CLASS[m] for m in METHODS}, indent=1, sort_keys=True) + "\n"
    cli_json = json.dumps(cli_commands(), indent=1, sort_keys=True) + "\n"
    if "--check" in sys.argv:
        stale = []
        for path, body in ((OUT, text), (MCP_OUT, mcp), (NODE_OUT, node), (METHODS_OUT, methods_json), (CLI_OUT, cli_json)):
            current = read(path) if os.path.exists(path) else ""
            if current != body:
                stale.append(os.path.relpath(path, ROOT))
        if stale:
            print(f"stale: {', '.join(stale)}; run scripts/gen-api-docs.py", file=sys.stderr)
            sys.exit(1)
        return
    if "--stats" in sys.argv:
        n = len(METHODS)
        have = lambda d: sum(1 for m in METHODS if m in d)
        print(json.dumps({
            "methods": n,
            "summary": sum(1 for m in METHODS if summary(m)),
            "ts": have(TS), "rust": have(RS), "python": have(PY), "mcp_mirror": have(TOOLS), "mcp_typed_tools": len(MCP_TYPED),
            "mcp_typed_with_desc": sum(1 for t in MCP_TYPED if t["desc"]),
            "mcp_typed_fields_undocumented": sum(1 for t in MCP_TYPED for f in t["params"] if not f["doc"]),
            "rpc_without_params_info": sum(1 for m in METHODS if not ts_param_keys(TS.get(m, {}).get("params", "")) and not handler_facts(m)[0] and TS.get(m, {}).get("params", "") == "" and m in TS),
        }))
        return
    with open(OUT, "w", encoding="utf-8") as f:
        f.write(text)
    with open(MCP_OUT, "w", encoding="utf-8") as f:
        f.write(mcp)
    with open(NODE_OUT, "w", encoding="utf-8") as f:
        f.write(node)
    with open(METHODS_OUT, "w", encoding="utf-8") as f:
        f.write(methods_json)
    with open(CLI_OUT, "w", encoding="utf-8") as f:
        f.write(cli_json)
    print(f"wrote docs/RPC.md ({len(METHODS)} methods) and docs/MCP.md ({len(MCP_TYPED)} typed tools)")


if __name__ == "__main__":
    main()
