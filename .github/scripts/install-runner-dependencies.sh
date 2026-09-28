#!/usr/bin/env bash
set -euo pipefail

job=${1:?usage: install-runner-dependencies.sh build|measure|publish}
packages=(ca-certificates coreutils curl git tar)
case "$job" in
  build)
    packages+=(binutils grep gzip ipxe-qemu jq kmod make python3 qemu-system-x86 qemu-utils sed xz-utils zstd)
    ;;
  measure)
    packages+=(jq kmod python3 python3-venv qemu-system-x86 qemu-utils zstd)
    ;;
  publish) ;;
  *) echo "Unknown job: $job" >&2; exit 1 ;;
esac

elevate=()
if (( EUID != 0 )); then
  elevate=(sudo -n)
fi
apt_install() {
  "${elevate[@]}" env DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends "$@"
}

"${elevate[@]}" apt-get update
apt_install "${packages[@]}"
"${elevate[@]}" install -d -m 0755 /etc/apt/keyrings /etc/apt/sources.list.d

if [[ "$job" == build || "$job" == publish ]]; then
  # Use the official repository: older distro packages lack gh attestation.
  # https://github.com/cli/cli/blob/trunk/docs/install_linux.md
  curl --fail --location --retry 3 https://cli.github.com/packages/githubcli-archive-keyring.gpg \
    | "${elevate[@]}" tee /etc/apt/keyrings/githubcli-archive-keyring.gpg > /dev/null
  "${elevate[@]}" chmod 0644 /etc/apt/keyrings/githubcli-archive-keyring.gpg
  echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/githubcli-archive-keyring.gpg] https://cli.github.com/packages stable main" \
    | "${elevate[@]}" tee /etc/apt/sources.list.d/github-cli.list > /dev/null
  packages=(gh)
else
  packages=()
fi

if [[ "$job" == build || "$job" == measure ]]; then
  # ARC supplies the Docker daemon; install the client and buildx when absent.
  # https://docs.docker.com/engine/install/ubuntu/#install-using-the-apt-repository
  if ! command -v docker > /dev/null || ! docker buildx version > /dev/null 2>&1; then
    # shellcheck disable=SC1091
    . /etc/os-release
    case "$ID" in
      ubuntu|debian) ;;
      *) echo "Unsupported Docker apt distribution: $ID" >&2; exit 1 ;;
    esac
    curl --fail --location --retry 3 "https://download.docker.com/linux/${ID}/gpg" \
      | "${elevate[@]}" tee /etc/apt/keyrings/docker.asc > /dev/null
    "${elevate[@]}" chmod 0644 /etc/apt/keyrings/docker.asc
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/${ID} ${VERSION_CODENAME} stable" \
      | "${elevate[@]}" tee /etc/apt/sources.list.d/docker.list > /dev/null
    packages+=(docker-buildx-plugin)
    if ! command -v docker > /dev/null; then
      packages+=(docker-ce-cli)
    fi
  fi
fi

if (( ${#packages[@]} )); then
  "${elevate[@]}" apt-get update
  apt_install "${packages[@]}"
fi

if [[ "$job" == build ]]; then
  # Match the yq version and checksum in the locked CAA Makefile.defaults.
  # The distro's Python-based yq is not compatible with these Makefiles.
  yq_binary=$(mktemp)
  trap 'rm -f "$yq_binary"' EXIT
  curl --fail --location --retry 3 --output "$yq_binary" \
    https://github.com/mikefarah/yq/releases/download/v4.35.1/yq_linux_amd64
  echo "bd695a6513f1196aeda17b174a15e9c351843fb1cef5f9be0af170f2dd744f08  ${yq_binary}" \
    | sha256sum --check --strict
  "${elevate[@]}" install -m 0755 "$yq_binary" /usr/local/bin/yq
  yq --version
  make --version
fi

if [[ "$job" == build || "$job" == publish ]]; then
  gh --version
  gh attestation verify --help > /dev/null
fi

if [[ "$job" == build || "$job" == measure ]]; then
  python3 -c 'import sys; assert sys.version_info >= (3, 10), "Python 3.10 or newer is required"'
  docker buildx version
  if ! docker info; then
    echo "The ARC runner must expose a running Docker daemon accessible to the runner user." >&2
    exit 1
  fi
  if [[ -e /dev/kvm ]]; then "${elevate[@]}" chmod a+rw /dev/kvm; fi
  "${elevate[@]}" modprobe vhost_vsock || true
fi
