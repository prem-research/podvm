#!/bin/sh
set -eu

cleanup() {
    # Loop detachment is deferred while QEMU still holds the input. Docker
    # terminates remaining VM processes when this entrypoint exits.
    python3 /usr/local/bin/smoke-blocks.py cleanup
}
trap cleanup EXIT
trap 'exit 143' TERM
trap 'exit 130' INT
python3 /usr/local/bin/smoke-blocks.py setup

busybox syslogd -O /work/syslog.log
cat > /run/podvm-containerd.toml <<'EOF'
version = 2
disabled_plugins = ["io.containerd.grpc.v1.cri"]
EOF
containerd --config /run/podvm-containerd.toml \
    --address /run/podvm-containerd/containerd.sock \
    --root /var/lib/podvm-containerd --state /run/podvm-containerd \
    --log-level debug >> /work/runtime.log 2>&1 &
daemon_pid=$!

# Wait for the daemon's API before handing control to ctr. The outer smoke
# timeout bounds the entire test, including startup and guest boot.
attempt=0
while [ "$attempt" -lt 30 ]; do
    if ctr --address /run/podvm-containerd/containerd.sock \
        --connect-timeout 1s version > /dev/null 2>&1; then
        "$@" &
        task_pid=$!
        wait "$task_pid"
        exit $?
    fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then
        echo "smoke containerd exited before becoming ready" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
echo "smoke containerd did not become ready" >&2
exit 1
