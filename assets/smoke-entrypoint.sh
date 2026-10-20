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

# A private CNI-style namespace gives the guest egress without moving the
# smoke container's own interface into Kata. All state dies with this container.
ip netns add podvm-smoke
ip link add podvm-net type veth peer name eth0 netns podvm-smoke
ip addr add 192.0.2.1/30 dev podvm-net
ip link set podvm-net up
ip -n podvm-smoke addr add 192.0.2.2/30 dev eth0
ip -n podvm-smoke link set eth0 up
ip -n podvm-smoke link set lo up
ip -n podvm-smoke route add default via 192.0.2.1
printf '1\n' > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -s 192.0.2.0/30 -j MASQUERADE
iptables -A FORWARD -i podvm-net -j ACCEPT
iptables -A FORWARD -o podvm-net -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT

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
