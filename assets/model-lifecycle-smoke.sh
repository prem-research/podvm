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
    # This pinned shim publishes exit before StopContainer finishes. Wait for
    # its runtime state to become deletable without changing the host runtime.
    until ctr tasks rm "$1" >/work/task-cleanup.log 2>&1; do
        attempt=$((attempt + 1))
        if [ "$attempt" -ge 100 ]; then
            cat /work/task-cleanup.log >&2
            exit 1
        fi
        sleep 0.1
    done
    ctr containers rm "$1"
}
check_model() {
    config=$1
    id=$2
    shift 2
    run --detach --config "$config" "$id"
    ctr tasks exec --exec-id model-check "$id" /model-smoke "$@"
    ctr tasks kill --signal SIGTERM "$id"
    remove_task "$id"
}

sandbox=podvm-model-sandbox
run --detach --config /work/fixture/sandbox.json "$sandbox"
check_model /work/fixture/model-app.json podvm-model-app /models/example0 /models/example1
check_model /work/fixture/model-subset.json podvm-model-subset /models/example0
# Recreate the first container: Kata generates new shared-file names, but
# the agent must reuse the original verified mounts in this same sandbox.
check_model /work/fixture/model-app.json podvm-model-app /models/example0 /models/example1
ctr tasks kill --signal SIGTERM "$sandbox"
remove_task "$sandbox"
attempt=0
until grep -q 'action:.*remove.*devices/virtual/block/dm-1' /work/runtime.log &&
      grep -q 'action:.*remove.*devices/virtual/block/dm-2' /work/runtime.log; do
    attempt=$((attempt + 1))
    if [ "$attempt" -ge 100 ]; then
        echo "guest did not release both model mappings before shutdown" >&2
        exit 1
    fi
    sleep 0.1
done
echo MODEL_LIFECYCLE_OK
