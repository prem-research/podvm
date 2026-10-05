#!/usr/bin/env bash
# Sourced by the pinned Kata image builder.

# Docker-in-Docker may expose sysfs without receiving host udev device nodes.
# Use the kernel's device numbers; partition minors are not derived from loop IDs.
ensure_loop_node() {
	local sysfs="$1" node="$2" type="$3"
	local major minor expected actual
	if [[ ! -r "${sysfs}/dev" ]]; then
		error "Kernel device unavailable: ${sysfs}; the Docker host must provide the loop driver"
		return 1
	fi
	IFS=: read -r major minor < "${sysfs}/dev" || return 1
	expected=$(printf '%x:%x' "${major}" "${minor}")
	actual=$(stat -Lc '%t:%T' "${node}" 2>/dev/null) || actual=""
	if [[ "${actual}" == "${expected}" ]] && \
	   { [[ "${type}" == b && -b "${node}" ]] || [[ "${type}" == c && -c "${node}" ]]; }; then
		return 0
	fi
	if [[ -e "${node}" || -L "${node}" ]]; then
		if [[ ! -b "${node}" && ! -c "${node}" ]]; then
			error "Refusing to replace non-device path: ${node}"
			return 1
		fi
		rm -f "${node}" || return 1
	fi
	if ! mknod -m 0600 "${node}" "${type}" "${major}" "${minor}"; then
		# Another builder or udev may have created the same node meanwhile.
		actual=$(stat -Lc '%t:%T' "${node}" 2>/dev/null) || return 1
		[[ "${actual}" == "${expected}" ]] && \
		   { [[ "${type}" == b && -b "${node}" ]] || [[ "${type}" == c && -c "${node}" ]]; }
	fi
}
