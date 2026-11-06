#!/bin/sh
# Start tenzro-node only with the machine's TPM. The node's identity and keys
# come from the TPM and nothing else; without it the container stops here
# instead of running a node with no hardware identity.
set -eu

refuse() {
    echo "tenzro-node: $*" >&2
    echo "See https://tenzro.com/docs/run-a-node/docker for the docker run flags." >&2
    exit 78
}

case "${1:-}" in
    # Read-only commands that need no identity.
    --version|-V|--help|-h|help|hardware) exec /usr/local/bin/tenzro-node "$@" ;;
esac

[ -c /dev/tpmrm0 ] \
    || refuse "no TPM: /dev/tpmrm0 is not in this container. Pass the host's TPM with --device /dev/tpmrm0."
[ -r /dev/tpmrm0 ] && [ -w /dev/tpmrm0 ] \
    || refuse "the TPM at /dev/tpmrm0 is not readable and writable by uid $(id -u). Add the device's group with --group-add \$(stat -c %g /dev/tpmrm0)."

exec /usr/local/bin/tenzro-node "$@"
