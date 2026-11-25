#!/bin/sh
set +x
set -eu
umask 077
target=${2:-.env}
mode=${3:-}
key_source=$target
if [ "$mode" = otp ]; then
    [ "$target" = - ] && [ "$#" -ge 4 ] || exit 1
    case "$1" in http://*/agent/otp/*|https://*/agent/otp/*) ;; *) exit 1;; esac
    key_source=.env
elif [ "$mode" = bundle ] || [ "$mode" = bundle-json ]; then
    [ "$target" = - ] && [ "$#" -ge 4 ] || exit 1
    case "$1" in http://*/agent/batch/*|https://*/agent/batch/*) ;; *) exit 1;; esac
    key_source=.env
else
    case "$1" in */agent/otp/*) exit 1;; esac
fi
read_key() { sed -n 's/^FAMILY_KEYS_K=//p' "$1" 2>/dev/null | tr -d '\r' | tail -n 1; }
K=${K:-${FAMILY_KEYS_K:-$(read_key "$key_source")}}
K=${K:-$(read_key "${FAMILY_KEYS_KEY_FILE:-$HOME/.config/family-keys/key.env}")}
: "${K:? Set the Family Keys shared key.}"
t=$(mktemp -d)
trap 'rm -rf "$t"' EXIT
if [ "$mode" = invite ]; then
    curl -q -fsS --noproxy '*' --max-time 30 -H 'Content-Type: application/json' \
        -H "X-Keys-Invite-Proof: ${FAMILY_KEYS_INVITE_PROOF:?}" --data '{}' "$1" -o "$t/a"
elif [ "$mode" = bundle-json ]; then
    curl -q -fsS --noproxy '*' --max-time 30 -H 'X-Keys-Bundle: json' "$1" -o "$t/a"
else
    curl -fsS "$1" -o "$t/a"
fi
tail -n +2 "$t/a" > "$t/b"
[ "$(openssl dgst -sha256 -hmac "FK1-MAC:$K" "$t/b" | sed 's/^.*= //')" = "$(head -n 1 "$t/a")" ]
k=$(printf %s "FK1-ENC:$K" | openssl dgst -sha256 | sed 's/^.*= //'); iv=$(head -n 1 "$t/b")
tail -n +2 "$t/b" | openssl enc -d -aes-256-cbc -nosalt -a -A -K "$k" -iv "$iv" -out "$t/env"
if [ "$mode" = otp ]; then
    grep -Exq '[0-9]{6}' "$t/env"
    shift 3
    "$@" < "$t/env" >/dev/null 2>&1
    printf 'OK\n'
    exit 0
fi
case "$1" in
    */agent/batch/*)
        if [ "$mode" = bundle-json ]; then
            [ "$(head -c 1 "$t/env")" = '{' ] || exit 1
        else
            [ "$(head -n 1 "$t/env")" = FK1-BATCH ] && [ "$(wc -l < "$t/env" | tr -d ' ')" = 3 ] || exit 1
        fi
        if [ "$mode" = bundle ] || [ "$mode" = bundle-json ]; then
            shift 3
            status=0
            "$@" < "$t/env" >/dev/null 2>&1 || status=$?
            case "$status" in
                0) printf 'OK\n';;
                10) printf 'NO_OTP\n'; exit 10;;
                11) printf 'NO_FIELD\n'; exit 11;;
                12) printf 'SUBMITTED\n';;
                *) printf 'BUNDLE_ERROR\n' >&2; exit 1;;
            esac
            exit 0
        fi
        sed -n '2p' "$t/env" | tr -d '\n' | openssl base64 -d -A -out "$t/values"
        [ -s "$t/values" ] || exit 1
        mv "$t/values" "$t/env"
        ;;
esac
{ printf '\n'; cat "$t/env"; } >> "$target"
chmod 600 "$target"
printf 'OK\n'
