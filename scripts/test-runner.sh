#!/bin/sh
# Cargo runner for every binary cargo runs or tests on Unix (see .cargo/config.toml).
#
# A node test binary runs hundreds of tests in parallel threads, each opening
# RocksDB instances, sockets and files. The common default soft open-file limit
# of 1024 is too low for that, and the failures land on whichever test runs out
# first. Raise the soft limit to the hard limit, then run the binary.
hard=$(ulimit -Hn)
if [ "$hard" = "unlimited" ]; then
    target=65536
else
    target=$hard
fi
ulimit -n "$target" || { echo "test-runner: cannot raise the open-file limit to $target" >&2; exit 1; }
exec "$@"
