#!/bin/bash
# aegis-log-reader - the ONLY thing the AEGIS collector key can run.
#
# Installed at /usr/local/bin/aegis-log-reader. The 'aegis' user's
# authorized_keys entry is:
#
#     restrict,command="/usr/local/bin/aegis-log-reader" ssh-ed25519 AAAA...
#
# `restrict` removes port forwarding, agent forwarding and terminals.
# `command=` makes sshd run this script whatever the client asked for; the
# client's request arrives in SSH_ORIGINAL_COMMAND and is treated as untrusted
# input. Two requests are understood:
#
#     list                      one "<inode> <size> <name>" line per log file
#     read <inode> <offset>     up to 8 MiB of that file, from byte <offset>
#
# Anything else exits with status 2. The collector is src/aegis/sources/cowrie.py.

set -uo pipefail

LOG_DIR=/var/lib/aegis-cowrie/log
MAX_BYTES=8388608 # must equal MAX_READ_BYTES in cowrie.py

read -r verb arg1 arg2 extra <<<"${SSH_ORIGINAL_COMMAND:-}"

cd "$LOG_DIR" || exit 1
shopt -s nullglob

log_files() {
  # The live file and dated rotations only. Symbolic links are refused: if the
  # container were ever compromised, a link named cowrie.json must not become a
  # way to read other files on the host.
  local name
  for name in cowrie.json cowrie.json.[0-9][0-9][0-9][0-9]-[0-9][0-9]-[0-9][0-9]; do
    if [[ -f "$name" && ! -L "$name" ]]; then
      echo "$name"
    fi
  done
}

case "${verb:-}" in
  list)
    [[ -z "${arg1:-}" ]] || exit 2
    while read -r name; do
      stat -c '%i %s %n' -- "$name"
    done < <(log_files)
    ;;

  read)
    [[ "${arg1:-}" =~ ^[0-9]{1,20}$ ]] || exit 2
    [[ "${arg2:-}" =~ ^[0-9]{1,15}$ ]] || exit 2
    [[ -z "${extra:-}" ]] || exit 2
    while read -r name; do
      if [[ "$(stat -c '%i' -- "$name")" == "$arg1" ]]; then
        # head closes the pipe early on large files; tail's resulting SIGPIPE
        # is expected, not an error.
        tail -c "+$((arg2 + 1))" -- "$name" | head -c "$MAX_BYTES"
        exit 0
      fi
    done < <(log_files)
    exit 3 # no such file: rotated away or deleted since `list`
    ;;

  *)
    echo "usage: list | read <inode> <offset>" >&2
    exit 2
    ;;
esac
