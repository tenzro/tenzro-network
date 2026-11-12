#!/usr/bin/env bash
# Sign a Tenzro release manifest with an ECDSA P-256 key that lives in a TPM, producing files that
#   cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS
# accepts. Needs only tpm2-tools, openssl, coreutils, xxd (jq only for --full). No cosign, no network.
#
# This script is INTERACTIVE ON PURPOSE. The key passphrase is typed at the terminal, held in a shell
# variable only, handed to tpm2-tools on stdin (never in argv, never in the environment, never on disk).
#
#   (no flag)   handle absent  -> create the key once, then sign.   handle present -> REFUSE (use --use)
#   --use       handle must exist -> sign only (the re-run path, e.g. for the sixth archive)
#   --full      also sign each archive digest and build provenance.dsse.json (needs --provenance FILE)
#   --expect-sha256 HEX   refuse unless SHA256SUMS has exactly this SHA-256 (the value the wrapper printed)
#   --dist DIR  directory holding SHA256SUMS (default: ./dist next to this script)
#   --provenance FILE   in-toto statement whose .predicate is attested (--full only)
# Environment (non-secret): TPM_HANDLE (default 0x8100A110), RELSIGN_TCTI (default device:/dev/tpmrm0;
#   the rehearsal sets a swtpm TCTI). The raw device /dev/tpm0 is refused.
set -euo pipefail
umask 077

HANDLE=${TPM_HANDLE:-0x8100A110}
TCTI=${RELSIGN_TCTI:-device:/dev/tpmrm0}
HERE=$(cd "$(dirname "$0")" && pwd)
DIST=$HERE/dist; USE=0; FULL=0; EXPECT=""; PROV=""
while [ $# -gt 0 ]; do
  case $1 in
    --use) USE=1;; --full) FULL=1;;
    --expect-sha256) EXPECT=${2:?}; shift;;
    --dist) DIST=${2:?}; shift;;
    --provenance) PROV=${2:?}; shift;;
    -h|--help) sed -n '2,19p' "$0"; exit 0;;
    *) echo "unknown argument: $1"; exit 2;;
  esac; shift
done
die() { echo; echo "STOP: $*"; exit 1; }

# ---- preflight (nothing below writes to the TPM until the key holder has approved) ----
case $TCTI in *tpm0*) [ "$TCTI" = "device:/dev/tpmrm0" ] || die "raw /dev/tpm0 is refused; use the resource manager /dev/tpmrm0";; esac
export TPM2TOOLS_TCTI=$TCTI
tools="tpm2_sign tpm2_readpublic tpm2_getcap tpm2_flushcontext openssl base64 sha256sum xxd awk"
[ "$USE" = 1 ] || tools="$tools tpm2_createprimary tpm2_create tpm2_load tpm2_evictcontrol"
[ "$FULL" = 1 ] && tools="$tools jq"
for t in $tools; do command -v "$t" >/dev/null || die "need $t"; done
[ -t 0 ] && [ -t 1 ] || die "needs an interactive terminal (run it with ssh -t); the passphrase is typed by a person"
cd "$DIST" 2>/dev/null || die "no such directory: $DIST"
[ -f SHA256SUMS ] || die "no SHA256SUMS in $DIST"
if [ "$FULL" = 1 ]; then [ -n "$PROV" ] && [ -f "$PROV" ] || die "--full needs --provenance FILE"; fi

# SHA256SUMS must be exactly: 64 hex, two spaces, a plain file name. No paths, no oddities.
lines=$(wc -l < SHA256SUMS)
grep -Eq '^[0-9a-f]{64}  tenzro-node-[A-Za-z0-9._-]+\.(tar\.gz|zip)$' SHA256SUMS || die "SHA256SUMS has no valid lines"
[ "$(grep -Evc '^[0-9a-f]{64}  tenzro-node-[A-Za-z0-9._-]+\.(tar\.gz|zip)$' SHA256SUMS || true)" = 0 ] || die "SHA256SUMS has lines of an unexpected shape"
[ "$(tail -c1 SHA256SUMS | xxd -p)" = 0a ] || die "SHA256SUMS does not end with a newline"
SUMS_SHA=$(sha256sum SHA256SUMS | cut -d' ' -f1)
if [ -n "$EXPECT" ] && [ "$EXPECT" != "$SUMS_SHA" ]; then die "SHA256SUMS is $SUMS_SHA but the wrapper announced $EXPECT"; fi

caps=$(tpm2_getcap handles-persistent 2>&1) || die "cannot read the TPM (tpm2_getcap failed): $caps"
if printf '%s\n' "$caps" | grep -qix -- "- $HANDLE"; then EXISTS=1; else EXISTS=0; fi
props=$(tpm2_getcap properties-variable 2>&1) || die "cannot read TPM properties"
INLOCK=$(printf '%s\n' "$props" | awk '/inLockout:/{print $2}')
LCNT=$(printf '%s\n' "$props" | awk '/TPM2_PT_LOCKOUT_COUNTER:/{print $2}')
LMAX=$(printf '%s\n' "$props" | awk '/TPM2_PT_MAX_AUTH_FAIL:/{print $2}')
[ "$INLOCK" = 0 ] || die "the TPM is in lockout; do not retry. Stop and report it to the release owner."
if [ "$EXISTS" = 1 ] && [ "$USE" = 0 ]; then die "handle $HANDLE already exists. Refusing to create. Re-run with --use to sign with it."; fi
if [ "$EXISTS" = 0 ] && [ "$USE" = 1 ]; then die "handle $HANDLE does not exist, nothing to use."; fi
if [ "$EXISTS" = 1 ]; then
  tpm2_readpublic -c "$HANDLE" -f pem -o /dev/stdout 2>/dev/null | openssl pkey -pubin -noout -text 2>/dev/null | grep -q prime256v1 \
    || die "the object at $HANDLE is not a P-256 key"
fi

echo "=============================================================="
echo " Tenzro release signing   host: $(hostname)   user: $(id -un)   $(date -u +%FT%TZ)"
echo " TPM interface : $TCTI"
echo " Key handle    : $HANDLE   ($([ "$EXISTS" = 1 ] && echo 'EXISTS: signing only' || echo 'ABSENT: this run CREATES it, once'))"
echo " TPM lockout   : failed-auth counter $LCNT of max $LMAX (a wrong passphrase adds 1; do not guess)"
echo "=============================================================="
echo
echo "The manifest to be signed ($lines lines), $DIST/SHA256SUMS:"
echo
awk '{printf "  %s  %s\n", $1, $2}' SHA256SUMS
echo
echo "SHA-256 of SHA256SUMS: $SUMS_SHA"
echo "Compare each line with RELEASE-NOTES.md / reproducible-*.txt and the hash above with the"
echo "hash shown before the script started (the wrapper prints it). If anything differs, answer 'no' below."
echo
[ "$LCNT" = "0x0" ] || { echo "NOTE: the failed-auth counter is not zero. Something failed earlier. Continue only if you know why."; echo; }
read -r -p "Type the first 12 characters of the SHA-256 above to approve signing this exact file (anything else aborts): " ans
[ "$ans" = "${SUMS_SHA:0:12}" ] || die "not approved"
if [ "$EXISTS" = 0 ]; then
  read -r -p "This creates the one persistent release key $HANDLE in this machine's TPM. Type CREATE to proceed: " ans
  [ "$ans" = CREATE ] || die "not approved"
fi

# ---- passphrase: terminal only, a shell variable only ----
bytes() { printf '%s' "$1" | LC_ALL=C wc -c | tr -d ' '; }
read -r -s -p "Release key passphrase: " P; echo
if [ "$EXISTS" = 0 ]; then
  read -r -s -p "Again, to confirm: " P2; echo
  [ "$P" = "$P2" ] || { unset P P2; die "the two entries differ; nothing was written to the TPM"; }
  unset P2
  n=$(bytes "$P")
  { [ "$n" -ge 16 ] && [ "$n" -le 64 ]; } || { unset P; die "passphrase must be 16 to 64 bytes (it is $n); nothing was written to the TPM"; }
fi
[ -n "$P" ] || die "empty passphrase"

work=$(mktemp -d /tmp/relsign.XXXXXXXX); chmod 700 "$work"
cleanup() { unset P 2>/dev/null || true; tpm2_flushcontext -t >/dev/null 2>&1 || true
  [ -d "$work" ] && { find "$work" -type f -exec shred -u {} + 2>/dev/null || true; rm -rf "$work"; } ; }
trap cleanup EXIT
auth() { printf '%s' "$P"; }   # builtin: the passphrase never appears in a process argument list

# ---- create (once) ----
if [ "$EXISTS" = 0 ]; then
  echo "creating the key ..."
  tpm2_createprimary -C o -G ecc256 -c "$work/primary.ctx" >/dev/null || die "createprimary failed; STOP, do not loop"
  tpm2_flushcontext -t >/dev/null 2>&1 || true
  auth | tpm2_create -C "$work/primary.ctx" -G ecc256:ecdsa-sha256 -p file:- \
      -a "sign|fixedtpm|fixedparent|sensitivedataorigin|userwithauth" -u "$work/k.pub" -r "$work/k.priv" >/dev/null \
      || die "tpm2_create failed; STOP, do not loop"
  tpm2_flushcontext -t >/dev/null 2>&1 || true
  tpm2_load -C "$work/primary.ctx" -u "$work/k.pub" -r "$work/k.priv" -c "$work/k.ctx" >/dev/null || die "tpm2_load failed; STOP"
  # no -f: evictcontrol must fail rather than replace anything
  tpm2_evictcontrol -C o -c "$work/k.ctx" "$HANDLE" >/dev/null || die "tpm2_evictcontrol failed; STOP"
  tpm2_flushcontext -t >/dev/null 2>&1 || true
  echo "key persisted at $HANDLE"
fi

tpm2_readpublic -c "$HANDLE" -f pem -o "$work/pub.pem" >/dev/null || die "cannot read the public key at $HANDLE"
openssl pkey -pubin -in "$work/pub.pem" -noout -text | grep -q prime256v1 || die "key is not P-256"
tpm2_flushcontext -t >/dev/null 2>&1 || true
if [ -f tenzro-release.pub ] && ! cmp -s tenzro-release.pub "$work/pub.pem"; then
  die "tenzro-release.pub in $DIST differs from the key at $HANDLE; refusing to overwrite"
fi
cp "$work/pub.pem" tenzro-release.pub
FPR=$(openssl pkey -pubin -in tenzro-release.pub -outform DER | sha256sum | cut -d' ' -f1)
printf '%s\n' "$FPR" > tenzro-release.fingerprint

# ECDSA-SHA256 over a file == ECDSA over its SHA-256 digest; the TPM sees only the 32-byte digest.
sign_digest() {  # sign_digest <digest.bin> <out.der>   ONE attempt, no retry (wrong guesses count toward lockout)
  auth | tpm2_sign -c "$HANDLE" -p file:- -g sha256 -s ecdsa -d -f plain -o "$2" "$1" >/dev/null 2>"$work/err" \
    || { cat "$work/err" >&2; die "tpm2_sign failed (wrong passphrase or TPM error). STOP. Do NOT retry in a loop."; }
  tpm2_flushcontext -t >/dev/null 2>&1 || true
  openssl pkeyutl -verify -pubin -inkey tenzro-release.pub -in "$1" -sigfile "$2" >/dev/null 2>&1 \
    || die "the signature does not verify against the public key"
}
sign_file() {  # sign_file <input> <output.sig base64>
  openssl dgst -sha256 -binary "$1" > "$work/d.bin"
  sign_digest "$work/d.bin" "$work/s.der"
  openssl dgst -sha256 -verify tenzro-release.pub -signature "$work/s.der" "$1" >/dev/null || die "signature on $1 does not verify"
  base64 -w0 < "$work/s.der" > "$2"
}
sign_file SHA256SUMS SHA256SUMS.sig; echo "signed SHA256SUMS"
if [ "$FULL" = 1 ]; then
  while read -r hex name; do
    printf '%s' "$hex" | xxd -r -p > "$work/d.bin"
    sign_digest "$work/d.bin" "$work/s.der"; base64 -w0 < "$work/s.der" > "$name.sig"; echo "signed $name"
  done < SHA256SUMS
  subj=$(awk '{printf "{\"name\":\"%s\",\"digest\":{\"sha256\":\"%s\"}}\n",$2,$1}' SHA256SUMS | jq -sc .)
  jq -c --argjson s "$subj" '{_type:"https://in-toto.io/Statement/v0.1",subject:$s,predicateType:"https://slsa.dev/provenance/v1",predicate:.predicate}' "$PROV" > "$work/stmt.json"
  T=application/vnd.in-toto+json
  { printf 'DSSEv1 %d %s %d ' "${#T}" "$T" "$(stat -c %s "$work/stmt.json")"; cat "$work/stmt.json"; } > "$work/pae.bin"
  sign_file "$work/pae.bin" "$work/pae.sig"
  jq -nc --arg t "$T" --arg p "$(base64 -w0 < "$work/stmt.json")" --arg s "$(cat "$work/pae.sig")" \
    '{payloadType:$t,payload:$p,signatures:[{keyid:"",sig:$s}]}' > provenance.dsse.json
  echo "wrote provenance.dsse.json"
fi
unset P

LOGLINE=$(printf '%s\t%s\t%s\t%s\t%s\t%s\t%s' "$(date -u +%FT%TZ)" "${RELEASE_COMMIT:-unknown}" "$SUMS_SHA" "$FPR" "$(hostname)" "$(id -un)" "$([ "$FULL" = 1 ] && echo full || echo sums)")
printf '%s\n' "$LOGLINE" > signing-log-line.tsv
echo
echo "=============================================================="
echo " DONE. Public key SHA-256 fingerprint (SPKI DER):"
echo "   $FPR"
echo " Files in $DIST:"
echo "   SHA256SUMS.sig  tenzro-release.pub  tenzro-release.fingerprint  signing-log-line.tsv"
echo " Checklist:"
echo "   1. Write the fingerprint down from THIS screen and again from the verification summary; they must match."
echo "   2. Copy SHA256SUMS.sig and tenzro-release.pub next to the archives and run: cosign verify-blob --key tenzro-release.pub --insecure-ignore-tlog=true --signature SHA256SUMS.sig SHA256SUMS."
echo "   3. Record the passphrase in your own password manager now (not on any server)."
echo "=============================================================="
