#!/bin/sh
set -eu

if [ "$#" -ne 2 ]; then
    echo "Usage: $0 PP2 PUBLISHER_HOME" >&2
    exit 2
fi
pp2=$1
publisher=$2
example=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
package_dir=$(mktemp -d)
trap 'rm -rf -- "$package_dir"' EXIT

"$pp2" app native identity "$publisher" >/dev/null
entry=$("$pp2" peer pack "$example/app.mjs" "$package_dir/app.ppj")
store=$("$pp2" peer pack "$example/store.mjs" "$package_dir/store.ppj")
cat >"$package_dir/manifest.json" <<MANIFEST
{
  "name": "Personal notes",
  "entry": "$entry",
  "budget": {"timeout_ms": 6500, "calls": 12, "depth": 1},
  "bindings": {
    "notes": {
      "description": "Read and edit the approved local notes replica",
      "program": "$store",
      "access": "Write"
    }
  }
}
MANIFEST
package=$("$pp2" app native pack "$package_dir/manifest.json" "$package_dir/app.ppa")
for block in app.ppj store.ppj app.ppa; do
    "$pp2" peer put "$publisher/peer.db" "$package_dir/$block" --publish >/dev/null
done
printf '%s %s\n' "$package" "$store"
