# 40.02 "Release artifacts": finalwisp in a container image. Draft: no image is pushed anywhere.
# Build context: a directory with the static release binary `finalwisp` (bench/release.sh, or the release tarball's
# top directory) and BUILDINFO. Example (from the repo root):
#   bench/release.sh && bench/package.sh "$VER" && tar -xzf pkg/finalwisp-$VER-x86_64-linux.tar.gz -C pkg
#   docker build -f contrib/docker/Dockerfile -t finalwisp:$VER pkg/finalwisp-$VER-x86_64-linux
# Run (--stop-timeout must be longer than --drain-timeout + 2 s; the default drain is 30 s, docker's stop 10 s):
#   docker run -d --name finalwisp -p 6001:6001 --stop-timeout 35 --memory 1g finalwisp:$VER
# wss:// with kTLS: the HOST needs the tls module (modprobe tls; a container cannot load it), then mount the pair
# readable by uid 65532: -v /etc/finalwisp/tls:/tls:ro ... finalwisp:$VER --host 0.0.0.0 --port 6001
#   --tls-cert /tls/fullchain.pem --tls-key /tls/privkey.pem  (CMD is replaced, so repeat --host/--port)
# Nothing else is needed in the image: the binary is static; its hosts lookups use built-in files+dns, which read the
# /etc/hosts and /etc/resolv.conf that docker mounts into every container; the memory budget reads the container's
# cgroup v2 limit (--memory).
FROM scratch
ARG REVISION=unknown
LABEL org.opencontainers.image.title="finalwisp" \
      org.opencontainers.image.description="Wisp v1/v2 server (static Linux x86_64 binary)" \
      org.opencontainers.image.revision="${REVISION}"
COPY --chmod=0555 finalwisp /finalwisp
COPY --chmod=0444 BUILDINFO /BUILDINFO
# a numeric uid/gid: scratch has no /etc/passwd (65532 = the "nonroot" id of distroless images)
USER 65532:65532
EXPOSE 6001
STOPSIGNAL SIGTERM
ENTRYPOINT ["/finalwisp"]
# inside a container the default 127.0.0.1 would be unreachable from the published port
CMD ["--host", "0.0.0.0", "--port", "6001"]
