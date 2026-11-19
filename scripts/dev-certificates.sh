#!/bin/sh
set -eu
if [ "$#" -lt 3 ]; then
    echo 'Usage: scripts/dev-certificates.sh DIRECTORY SERVER_DNS_NAME CLIENT_NAME [CLIENT_NAME ...]' >&2
    exit 2
fi
directory=$1
server_name=$2
shift 2
umask 077
mkdir -p "$directory"
cd "$directory"
[ ! -e ca.key ] || { echo 'CA key already exists' >&2; exit 1; }
case "$server_name" in
    ''|*[!a-zA-Z0-9.-]*) echo 'Invalid DNS name' >&2; exit 2 ;;
esac
for name in "$@"; do
    case "$name" in
        ''|ca|server|*[!a-zA-Z0-9_-]*) echo 'Invalid client name' >&2; exit 2 ;;
    esac
done
openssl req -new -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
    -days 30 -subj /CN=pp2-development -keyout ca.key -out ca.pem
for name in server "$@"; do
    openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
        -subj "/CN=$name" -keyout "$name.key" -out "$name.csr"
    if [ "$name" = server ]; then
        printf 'extendedKeyUsage=serverAuth\nsubjectAltName=DNS:%s\n' "$server_name" > "$name.ext"
    else
        printf 'extendedKeyUsage=clientAuth\n' > "$name.ext"
    fi
    openssl x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial \
        -days 30 -extfile "$name.ext" -out "$name.pem"
done
