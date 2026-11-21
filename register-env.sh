#!/bin/sh
# Register selected dotenv variables in one encrypted request.
set +x
set -eu
umask 077
fail() { printf '%s\n' "$1" >&2; exit 1; }
mode=register
with_totp=false
case "${1:-}" in
    --change) mode=update; shift;;
    --delete) mode=delete; shift;;
    --totp) mode=totp; shift;;
    --with-totp) with_totp=true; shift;;
esac
if [ "$with_totp" = true ]; then
    [ "$#" -eq 6 ] || fail 'Usage: register-env.sh --with-totp BASE .env ENV TITLE PURPOSE OTPAUTH_FILE_OR_DASH'
    otp_source=$6
    set -- "$1" "$2" "$3" "$4" "$5"
elif [ "$mode" = register ]; then
    [ "$#" -ge 5 ] && [ "$#" -le 98 ] && [ "$(( ($# - 2) % 3 ))" -eq 0 ] || fail 'Usage: register-env.sh BASE .env ENV TITLE PURPOSE [ENV TITLE PURPOSE ...]'
elif [ "$mode" = totp ]; then
    [ "$#" -eq 3 ] || fail 'Usage: register-env.sh --totp URL ENV OTPAUTH_FILE_OR_DASH'
else
    [ "$#" -eq 2 ] || { [ "$mode" = update ] && [ "$#" -eq 3 ]; } || fail 'Usage: register-env.sh --change URL ENV [.env] | --delete URL ENV'
fi
base=${1%/}
case "$base" in http://*|https://*) ;; *) fail 'Specify the Keys HTTP endpoint';; esac
file=./.env
if [ "$mode" = register ]; then
    file=$2
    endpoint="$base/agent/register"
else
    variable=$2
    case "$variable" in ''|[0-9]*|*[!A-Za-z0-9_]*|FAMILY_KEYS_K) fail 'Invalid variable name';; esac
    token=${base##*/}
    [ "${base%/*}" = "${base%%/agent/manage/*}/agent/manage" ] &&
        printf '%s\n' "$token" | grep -Eq '^[0-9a-fA-F-]{36}$' || fail 'Specify a Keys management URL'
    endpoint=$base
    if [ "$mode" = totp ]; then
        otp_source=$3
    elif [ "$#" -eq 3 ]; then
        file=$3
    fi
fi
if [ "$with_totp" = true ] || [ "$mode" = totp ]; then
    case "$otp_source" in
        -) [ ! -t 0 ] || fail 'Pipe the otpauth URI or pass a file';;
        *) [ -f "$otp_source" ] && [ -r "$otp_source" ] || fail 'Cannot read otpauth file';;
    esac
fi
if [ "$with_totp" = true ]; then
    if [ "$otp_source" = - ]; then
        initial_uri=$(head -c 4099)
    else
        initial_uri=$(head -c 4099 < "$otp_source")
    fi
    [ -n "$initial_uri" ] && [ "${#initial_uri}" -le 4097 ] &&
        [ "$(printf '%s' "$initial_uri" | wc -l | tr -d ' ')" -eq 0 ] || fail 'Provide one otpauth URI'
fi
if [ "$mode" = register ] || { [ "$mode" = update ] && [ "$#" -eq 3 ]; }; then
    [ -f "$file" ] && [ -r "$file" ] || fail 'Cannot read dotenv file'
fi
case "$file" in /*) ;; *) file=./$file;; esac

read_key() { sed -n 's/^FAMILY_KEYS_K=//p' "$1" 2>/dev/null | tr -d '\r' | tail -n 1; }
secret=${FAMILY_KEYS_K:-$(read_key "$file")}
secret=${secret:-$(read_key "${FAMILY_KEYS_KEY_FILE:-$HOME/.config/family-keys/key.env}")}
[ -n "$secret" ] || fail 'Set the family-keys shared key'

digest() { openssl dgst -sha256 | sed 's/^.*= //'; }
encode_entry() (
    variable=$1
    case "$variable" in ''|[0-9]*|*[!A-Za-z0-9_]*|FAMILY_KEYS_K) fail 'Invalid variable name';; esac

    # Track quoted assignments across lines so a line inside another value cannot match.
    assignment=$(awk -v wanted="$variable" '
    function closed(line, quote, start, i, ch) {
        for (i=start; i<=length(line); i++) {
            ch=substr(line,i,1)
            if (ch=="\\" && quote=="\"") i++
            else if (ch==quote) return 1
        }
        return 0
    }
    {
        sub(/\r$/, "")
        if (quote!="") {
            if (selected) value=value "\n" $0
            if (closed($0, quote, 1)) quote=""
            next
        }
        if (!match($0,/^[ \t]*(export[ \t]+)?[A-Za-z_][A-Za-z0-9_]*[ \t]*=/)) next
        name=substr($0,1,RLENGTH-1)
        rest=substr($0,RLENGTH+1)
        sub(/^[ \t]+/,"",name); sub(/^export[ \t]+/,"",name); sub(/[ \t]+$/,"",name)
        selected=(name==wanted)
        if (selected) { value=name "=" rest; count++ }
        sub(/^[ \t]+/,"",rest)
        first=substr(rest,1,1)
        if ((first=="\"" || first==sprintf("%c",39)) && !closed(rest, first, 2)) quote=first
    }
    END { if (count!=1 || quote!="") exit 1; print value }
    ' "$file") || fail 'Variable missing, duplicated, or malformed'

    {
        if [ "$with_totp" = true ]; then printf 'FK1-INTAKE-TOTP\n%s\n' "$initial_uri"; fi
        printf '%s\n' "$assignment"
    } | seal_entry "$@"
)
seal_entry() (
    variable=$1
    nonce=$(openssl rand -hex 16)
    iv=$(openssl rand -hex 16)
    enc_key=$(printf 'FK1-REGISTER-ENC:%s:%s' "$nonce" "$secret" | digest)
    mac_key=$(printf 'FK1-REGISTER-MAC:%s:%s' "$nonce" "$secret" | digest)
    title=$(printf '%s' "$2" | openssl base64 -A)
    purpose=$(printf '%s' "$3" | openssl base64 -A)
    cipher=$(openssl enc -aes-256-cbc -nosalt -a -A -K "$enc_key" -iv "$iv")
    mac=$(printf 'FK1-REGISTER\n%s\n%s\n%s\n%s\n%s\n%s' "$nonce" "$title" "$purpose" "$variable" "$iv" "$cipher" |
        openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac_key" | sed 's/^.*= //')
    printf '{"nonce":"%s","title":"%s","purpose":"%s","variable":"%s","iv":"%s","cipher":"%s","mac":"%s"}' \
        "$nonce" "$title" "$purpose" "$variable" "$iv" "$cipher" "$mac"
)
if [ "$mode" != register ]; then
    body='{}'
    mac=''
    if [ "$mode" = totp ]; then
        if [ "$otp_source" = - ]; then
            body=$(seal_entry "$variable" totp '')
        else
            body=$(seal_entry "$variable" totp '' < "$otp_source")
        fi
    elif [ "$#" -eq 3 ]; then
        body=$(encode_entry "$variable" "$variable" '')
    fi
    if [ "$body" != '{}' ]; then
        mac=${body##*\"mac\":\"}
        mac=${mac%%\"*}
    fi
    manage_key=$(printf 'FK1-MANAGE-KEY:%s:%s' "$token" "$secret" | digest)
    proof=$(printf 'FK1-MANAGE:%s:%s:%s:%s' "$token" "$mode" "$variable" "$mac" |
        openssl dgst -sha256 -mac HMAC -macopt "hexkey:$manage_key" | sed 's/^.*= //')
    set -- -H "X-Keys-Manage-Proof: $proof"
else
    shift 2
    entries=''
    while [ "$#" -gt 0 ]; do
        entry=$(encode_entry "$1" "$2" "$3")
        entries="${entries}${entries:+,}${entry}"
        shift 3
    done
    if [ "$entries" = "$entry" ]; then
        body=$entry
    else
        body=$(printf '{"entries":[%s]}' "$entries")
    fi
fi
http_status=$(printf '%s' "$body" |
    curl -q -fsS --noproxy '*' --max-time 30 -H 'Content-Type: application/json' "$@" --data-binary @- \
        -o /dev/null -w '%{http_code}' "$endpoint") || http_status=
[ "$http_status" = 200 ] || fail 'Operation not confirmed. Check Keys before retrying.'
printf 'OK\n'
