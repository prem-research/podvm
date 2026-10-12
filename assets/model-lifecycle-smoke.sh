#!/bin/sh
set -eu
ctr() {
    command ctr --address /run/podvm-containerd/containerd.sock --namespace podvm-smoke "$@"
}
run() {
    ctr run --runtime io.containerd.kata.v2 --runtime-config-path /work/configuration.toml "$@"
}
remove_task() {
    attempt=0
    # The pinned shim publishes exit before StopContainer finishes.
    until ctr tasks rm "$1" >/work/task-cleanup.log 2>&1; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 100 ]; then cat /work/task-cleanup.log >&2; exit 1; fi
        sleep 0.1
    done
    ctr containers rm "$1"
}
check() {
    id=$1
    shift
    ctr tasks exec --exec-id "check-$checks" "$id" /model-smoke "$@"
    checks=$((checks + 1))
}
stop() {
    ctr tasks kill --signal SIGTERM "$1"
    remove_task "$1"
}
checks=0
sandbox=podvm-model-sandbox
run --detach --config /work/fixture/sandbox.json "$sandbox"
# An init container can finish with no model volumes at all.
run --rm --config /work/fixture/model-init.json podvm-model-init
# Failed verification must roll back only this container, then allow creation.
if run --detach --config /work/fixture/model-bad.json podvm-model-app; then
    echo 'unauthenticated model accepted' >&2
    exit 1
fi
ctr containers rm podvm-model-app >/work/failed-cleanup.log 2>&1 || true
run --detach --config /work/fixture/model-subset.json podvm-model-subset
run --detach --config /work/fixture/model-app.json podvm-model-app
check podvm-model-app /models/example0 /models/example1
check podvm-model-subset /models/example0
stop podvm-model-app
check podvm-model-subset /models/example0
run --detach --config /work/fixture/model-app.json podvm-model-app
check podvm-model-app /models/example0 /models/example1
stop podvm-model-subset
check podvm-model-app /models/example0 /models/example1
stop podvm-model-app
# Leave a consuming workload to exercise sandbox teardown cleanup.
run --detach --config /work/fixture/model-subset.json podvm-model-teardown
check podvm-model-teardown /models/example0
check podvm-model-teardown /models/example0
stop "$sandbox"
echo MODEL_LIFECYCLE_OK
