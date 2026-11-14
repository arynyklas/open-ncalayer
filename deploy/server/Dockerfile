#
# oncl-server as a container image, built from the RELEASE ARCHIVE (never from source, and
# nothing is downloaded): the build context holds the file
#   oncl-server-<VERSION>-linux-x64.tar.gz
# made by `cargo xtask package platform --flavor linux-x64` (glibc 2.28 build).
#
#   docker build -f Dockerfile --build-arg VERSION=<version> -t oncl-server:<version> <dir with the archive>
#
# The image enables nothing: it contains no configuration, so a container started without
# the operator's private config mount refuses to start, and a configuration with
# `enabled = false` (the example) makes the process exit at once without a listener.
# Run it as docs/user/server.md ("Контейнер") describes: read-only root file system, all
# capabilities dropped, memory and process limits, explicit config / secret / scratch /
# audit mounts. Never `--privileged`, never a mount of a home directory.

# The base image by digest (debian 12 slim); update both together.
ARG BASE_IMAGE=debian:12-slim@sha256:99c0b25c46d0214d5a2091092e7908907dcaecd6a962cde0ac700acee222b6f3

FROM ${BASE_IMAGE} AS unpack
ARG VERSION
COPY oncl-server-${VERSION}-linux-x64.tar.gz /tmp/package.tar.gz
RUN mkdir /package \
 && tar -xzf /tmp/package.tar.gz -C /package --strip-components=1 \
 && test -x /package/oncl-server

FROM ${BASE_IMAGE}
ARG VERSION
LABEL org.opencontainers.image.title="oncl-server" \
      org.opencontainers.image.description="OpenNCALayer standalone signing service; the HTTP API is off until the operator enables it" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.licenses="Apache-2.0"

# One non-root service account with a fixed id, so bind mounts can be prepared for it
# (`chown 10001:10001`, mode 0700). The directories below are owner-only: oncl-server
# refuses a private mount that anyone else can reach. They are the explicit mount points:
#   /etc/oncl-server         the private configuration (server.toml, key containers)
#   /run/oncl-secrets        passwords, TLS key, tokens' files (optional)
#   /var/lib/oncl-server     the state: the durable audit journal `audit/` and the
#                            transient document snapshots `scratch/`, both created by the
#                            server at its first start (an EXISTING empty `audit/` is
#                            refused: the journal must outlive the container, so mount a
#                            volume here)
RUN groupadd --system --gid 10001 oncl \
 && useradd --system --uid 10001 --gid 10001 --no-create-home --home-dir /nonexistent \
        --shell /usr/sbin/nologin oncl \
 && install -d -m 0700 -o 10001 -g 10001 \
        /etc/oncl-server /run/oncl-secrets /var/lib/oncl-server

COPY --from=unpack --chmod=0755 /package/oncl-server /usr/local/bin/oncl-server
COPY --from=unpack --chmod=0644 /package/LICENSE /package/NOTICE /package/THIRD-PARTY.txt /usr/share/doc/oncl-server/

USER 10001:10001
WORKDIR /var/lib/oncl-server
# oncl-server drains admitted operations on SIGINT (SIGTERM would end it at once).
STOPSIGNAL SIGINT
ENTRYPOINT ["/usr/local/bin/oncl-server"]
CMD ["serve", "--config", "/etc/oncl-server/server.toml"]

# HONEST HEALTHCHECK: only that the configured port accepts a TCP connection from inside
# the container. The service's own `GET /health` needs a bearer token, which the image
# must not hold, so it is not used here: probe it from your monitoring with a token that
# has the hash right. Set ONCL_HEALTH_PORT when `bind` is not port 13579.
HEALTHCHECK --interval=30s --timeout=3s --start-period=10s --retries=3 \
    CMD ["bash", "-c", "exec 3<>/dev/tcp/127.0.0.1/${ONCL_HEALTH_PORT:-13579}"]
