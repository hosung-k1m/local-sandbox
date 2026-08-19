#!/bin/sh
# Runs the Linux-side mediated-workspace preflight for a disposable Lima guest.
# It intentionally fails before running the mutation matrix when the guest
# cannot provide the security boundary that matrix is meant to validate.
set -eu

if [ "$#" -ne 1 ]; then
  echo "usage: $0 <lima-instance>" >&2
  exit 2
fi
if [ -z "$1" ]; then
  echo "usage: $0 <lima-instance>" >&2
  exit 2
fi

instance=$1

exec limactl shell "$instance" -- sudo /bin/sh -s <<'GUEST_E2E'
set -eu

fail() {
  echo "mediated-workspace-e2e: FAIL: $*" >&2
  exit 1
}

require_file() {
  test -f "$1" || fail "missing $1"
}

require_char_device() {
  test -c "$1" || fail "missing character device $1"
}

require_kernel_69() {
  read -r release < /proc/sys/kernel/osrelease
  major=${release%%.*}
  rest=${release#*.}
  minor=${rest%%.*}
  case "$major:$minor" in
    6:[9-9] | 6:[1-9][0-9] | [7-9]:* | [1-9][0-9]:*) ;;
    *) fail "kernel $release lacks FUSE passthrough; require >= 6.9" ;;
  esac
}

require_mount() {
  path=$1
  want_fstype=$2
  output_path=/run/boxedai/mediated-workspace-e2e.mountinfo.$$
  findmnt -T "$path" -n -o FSTYPE,OPTIONS,SOURCE --raw > "$output_path" || fail "no mount at $path"
  IFS= read -r output < "$output_path"
  rm -f "$output_path"
  case "$output" in
    "$want_fstype"*) ;;
    *) fail "mount $path is $output, want $want_fstype" ;;
  esac
}

require_kernel_69
require_char_device /dev/fuse
require_file /etc/boxedai/agent.json
require_file /run/boxedai/workspace-mediator-ready
require_mount /workspace fuse
require_mount /var/lib/boxedai/private/workspace-lower virtiofs

grep -Fq '"mediated_workspace":true' /etc/boxedai/agent.json || fail "guest agent is not configured for a mediated workspace"
grep -Fq '"workspace_lower_path":"/var/lib/boxedai/private/workspace-lower"' /etc/boxedai/agent.json || fail "guest agent has an unexpected lower workspace path"

if setpriv --reuid 4242 --regid 4242 --clear-groups test -r /var/lib/boxedai/private/workspace-lower; then
  fail "workload UID can read the private lower workspace"
fi
if setpriv --reuid 5000 --regid 5000 --clear-groups test -r /var/lib/boxedai/private/workspace-lower; then
  fail "human UID can read the private lower workspace"
fi

cat <<'MATRIX'
mediated-workspace-e2e: preflight passed
The following mutation matrix must be run only in a disposable mediated session:
  - concurrent agent/human writes with recorder event attribution
  - O_RDWR open, write, flush, fsync, and release lifecycle
  - mmap/msync writeback with UID 0 opener-fallback attribution
  - recorder failure leaves the lower workspace unchanged
  - direct lower-path access remains denied for workload and human UIDs
  - host health gate rejects a missing mediator readiness marker
MATRIX
GUEST_E2E
