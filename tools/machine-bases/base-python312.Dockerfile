# Tenzro machine-class base: Python 3.12.
#
# See base-node20.Dockerfile for the base contract. The builder overlays the app
# at /app, installs /sbin/tenzro-initagent, and writes /etc/tenzro/run.json; this
# base carries only the runtime + minimal system layout.
FROM python:3.12-slim-bookworm

RUN groupadd -g 10001 app \
 && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin app \
 && mkdir -p /app /proc /sys /dev /tmp /run /sbin \
 && chown app:app /app \
 && chmod 1777 /tmp

WORKDIR /app
