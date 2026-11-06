# Tenzro machine-class base: Node.js 20.
#
# The base provides only the language runtime and a minimal system layout the
# guest init expects; it deliberately does NOT contain the app or the run spec —
# `tenzro-machine-builder` overlays the built app at /app, installs the static
# `tenzro-initagent` at /sbin/tenzro-initagent, and writes /etc/tenzro/run.json.
#
# Contract every Tenzro machine base must satisfy:
#   * an unprivileged `app` user (uid/gid 10001) in /etc/passwd, for run.json `user`
#   * empty mountpoint dirs the init mounts pseudo-fs onto: /proc /sys /dev /tmp /run
#   * an /app working directory
#   * /sbin exists (init is installed there by the builder)
#
# Pinned by digest after `docker buildx build` + push (see build-and-publish.sh);
# machine deploys reference `registry/repo@sha256:...`, never a mutable tag.
FROM node:20-bookworm-slim

# Unprivileged runtime user.
RUN groupadd -g 10001 app \
 && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin app \
 && mkdir -p /app /proc /sys /dev /tmp /run /sbin \
 && chown app:app /app \
 && chmod 1777 /tmp

# No ENTRYPOINT/CMD: the microVM boots `init=/sbin/tenzro-initagent`, which
# execs the app per /etc/tenzro/run.json. Any entrypoint here is ignored.
WORKDIR /app
