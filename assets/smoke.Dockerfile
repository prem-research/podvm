ARG BUILDER
FROM ${BUILDER}
# kata-runtime's CLI requires a local syslog socket, even with --log set.
RUN apt-get update && apt-get install --yes --no-install-recommends busybox \
    && rm -rf /var/lib/apt/lists/*
ENTRYPOINT ["sh", "-ec", "busybox syslogd -O /work/syslog.log; exec \"$@\"", "--"]
