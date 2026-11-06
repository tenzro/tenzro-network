#!/bin/bash
# Generate docs/CLI.md from the binary's own help.
#
#   scripts/gen-cli-docs.sh [path-to-tenzro]
#
# WHY THIS IS GENERATED
#
# The CLI reached 124 command groups against a README naming 26 and a guide
# naming 9. No single commit was wrong — each added a command and moved on —
# and nothing ever reported that the reference had fallen behind. A
# hand-maintained list of 124 groups is stale the week it is written.
#
# So it is derived from the thing it describes. `cli_documentation_tests` in
# tenzro-cli fails when the two disagree in either direction: a command with no
# entry, or an entry for a command that has been removed.
#
# WHAT IT DOES NOT DO
#
# It does not replace prose. The guides explain how to run a node, what a
# delegation is, why a model is gated; this is the reference they point at for
# exact flags. Generated pages are good at completeness and bad at judgement,
# and mixing the two produces a document that is accurate and useless.
set -uo pipefail

BIN="${1:-}"
if [ -z "$BIN" ]; then
    for candidate in ./target/release/tenzro ./target/debug/tenzro "$(command -v tenzro)"; do
        [ -x "$candidate" ] && BIN="$candidate" && break
    done
fi
[ -x "$BIN" ] || { echo "usage: $0 <path-to-tenzro>  (none found in target/)" >&2; exit 1; }

OUT="docs/CLI.md"
VERSION=$("$BIN" --version 2>/dev/null | head -1)

# The subcommand names a help text lists, `help` excluded.
subcommands() {
    sed -n '/^Commands:/,/^$/p' \
        | grep -oE '^  [a-z0-9][a-z0-9-]*' \
        | tr -d ' ' \
        | grep -v '^help$' \
        | sort -u
}

# document <path> <depth>: the entries for every subcommand under `tenzro <path>`.
document() {
    local path=$1 depth=$2 sub hashes
    hashes=$(printf '%*s' $((depth + 1 > 6 ? 6 : depth + 1)) '' | tr ' ' '#')
    # shellcheck disable=SC2086
    "$BIN" $path --help 2>&1 | subcommands | while read -r sub; do
        local full="${path:+$path }$sub"
        echo "$hashes \`tenzro $full\`"
        echo
        echo '```'
        # shellcheck disable=SC2086
        "$BIN" $full --help 2>&1
        echo '```'
        echo
        document "$full" $((depth + 1))
    done
}

{
    echo "# Tenzro CLI reference"
    echo
    echo "Every command \`tenzro\` accepts, generated from the binary."
    echo
    echo "Generated from \`$VERSION\` by \`scripts/gen-cli-docs.sh\`. Do not edit by"
    echo "hand — \`cargo test -p tenzro-cli\` fails when this file and the binary"
    echo "disagree, and a hand edit is how they start to."
    echo
    echo "For how to *use* the network rather than what each flag is called, start"
    echo "with [GUIDE.md](GUIDE.md)."
    echo
    echo '```'
    "$BIN" --help 2>&1
    echo '```'
    echo

    # One section per command at every depth: each group, then its
    # subcommands, then theirs, down to the leaves, so every command path and
    # its flags has an entry. Headings deepen with the path (## for a group,
    # ### for its subcommands, and so on, at most ######).
    document "" 1
} > "$OUT"

# Deliberately no count here.
#
# A summary line reporting how many commands were written is the sort of thing
# that drifts from what the file contains — it did, reporting 1000 groups for a
# file holding 123 — and a status line nobody can reproduce is worse than none.
# What enforces correctness is `cli_documentation_tests` in tenzro-cli, which
# compares this file against clap in both directions and fails on either.
printf 'wrote %s from %s\n' "$OUT" "$VERSION"
printf 'verify with: cargo test -p tenzro-cli cli_documentation\n'
