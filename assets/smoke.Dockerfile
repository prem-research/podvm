ARG BUILDER
FROM ${BUILDER}
# Run the pinned Kata shim through a private containerd inside this container.
RUN apt-get update && apt-get install --yes --no-install-recommends busybox containerd e2fsprogs util-linux python3 \
    && rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/kata/bin:${PATH}"
COPY smoke-blocks.py /usr/local/bin/smoke-blocks.py
COPY smoke-entrypoint.sh /usr/local/bin/podvm-smoke
ENTRYPOINT ["sh", "/usr/local/bin/podvm-smoke"]
