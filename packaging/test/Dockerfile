# A host for qsh's end-to-end tests: one distribution image with sshd on port 2222 and a user
# `test`. qsh-server and the client's public key arrive at run time through the bind mount
# /qsh-in (see e2e.sh), so one image per distribution serves every build.
#
#   docker build --build-arg BASE=fedora:latest -t qsh-e2e:fedora packaging/test
ARG BASE=debian:12
FROM ${BASE}
COPY setup.sh entrypoint.sh /qsh-test/
RUN sh /qsh-test/setup.sh
EXPOSE 2222
ENTRYPOINT ["/bin/sh", "/qsh-test/entrypoint.sh"]
