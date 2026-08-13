# Tenzro machine-class base: static binaries.
#
# For apps that ship a fully-static server binary (Go, Rust musl, Zig, ...). No
# language runtime — just BusyBox for a shell + coreutils and the minimal system
# layout. The smallest usable base; a truly self-contained static app can even
# deploy with `base = none` and skip this.
#
# See base-node20.Dockerfile for the base contract.
FROM busybox:1.36-uclibc

# BusyBox has no adduser group parity with distro tools; write the accounts
# directly. app = uid/gid 10001.
RUN mkdir -p /app /proc /sys /dev /tmp /run /sbin /etc \
 && echo 'root:x:0:0:root:/root:/bin/sh' > /etc/passwd \
 && echo 'app:x:10001:10001:app:/app:/sbin/nologin' >> /etc/passwd \
 && echo 'root:x:0:' > /etc/group \
 && echo 'app:x:10001:' >> /etc/group \
 && chmod 1777 /tmp

WORKDIR /app
