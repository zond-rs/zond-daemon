# syntax=docker/dockerfile:1

# The daemon, in a container, built against the engine beside it.
#
# The build context is the directory holding both repositories rather than this
# one. `Cargo.toml` names the engine at `../zond-engine`, so a context of this
# repository alone has nothing to build against:
#
#   docker build -f zond-daemon/Dockerfile -t zond-daemon:0.1.0 .
#
# run from the directory that holds `zond-daemon` and `zond-engine`. What is
# left out of that context is in `Dockerfile.dockerignore`, which is the ignore
# file buildkit reads for a named dockerfile, the context root here belonging to
# neither repository.

FROM rust:1.93-slim-bookworm AS build

# The engine puts frames on the wire through libpcap and reads them back the
# same way, so it links against it. Headers here, the library itself in the
# stage below.
RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY zond-engine zond-engine
COPY zond-daemon zond-daemon

# `--locked` because a container built from a resolution nobody committed is a
# container nobody can build twice.
WORKDIR /src/zond-daemon
RUN cargo build --release --locked

FROM debian:bookworm-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends libpcap0.8 \
 && rm -rf /var/lib/apt/lists/*

COPY --from=build /src/zond-daemon/target/release/zondd /usr/local/bin/zondd

# Root, because a scan is raw sockets and the capability to open them is granted
# to a user. Everything a person touches is the other container, which holds no
# capabilities at all — see `deploy/compose.yaml`.
#
# No arguments: which transport it serves, where it records, and where it may be
# pointed are things an operator says on purpose, and a default would be this
# image deciding one of them for them.
ENTRYPOINT ["zondd"]
