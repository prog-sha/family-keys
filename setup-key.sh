#!/bin/sh
# Save the shared key from a one-time invitation without displaying it.
set +x
set -eu
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$#" -eq 1 ] || fail 'Usage: setup-key.sh INVITATION_URL'
url=${1%%\#*}
secret=${1#*\#}
id=${url##*/}
case "$url" in http://*/agent/setup/"$id"|https://*/agent/setup/"$id") ;; *) fail 'Invalid invitation URL';; esac
case "$id" in *[!0-9a-f]*) fail 'Invalid invitation ID';; esac
case "$secret" in *[!A-Za-z0-9_-]*) fail 'Invalid invitation key';; esac
[ "${#id}" -eq 32 ] && [ "${#secret}" -eq 43 ] || fail 'Invalid invitation'

target=${FAMILY_KEYS_KEY_FILE:-$HOME/.config/family-keys/key.env}
valid_key() { [ -f "$1" ] && [ ! -L "$1" ] && grep -Eq '^FAMILY_KEYS_K=[A-Za-z0-9_-]{32,}$' "$1"; }
if [ -e "$target" ] || [ -L "$target" ]; then
    valid_key "$target" || fail 'Existing key file could not be verified'
    chmod 600 "$target"
else
    dir=$(dirname -- "$target")
    mkdir -p -- "$dir"
    tmp=$(mktemp -d "$dir/.setup.XXXXXX")
    trap 'rm -rf "$tmp"' EXIT
    scripts=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
    proof=$(printf 'FK1-INVITE-PROOF:%s:%s' "$id" "$secret" | openssl dgst -sha256 | sed 's/^.*= //')
    K="$secret" FAMILY_KEYS_INVITE_PROOF="$proof" sh "$scripts/append-env.sh" "$url" "$tmp/key.env" invite >/dev/null
    valid_key "$tmp/key.env" || fail 'Invitation returned an invalid key file'
    ln -- "$tmp/key.env" "$target" || fail 'Key file already exists'
fi
printf 'OK\n'
