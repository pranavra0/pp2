#!/bin/sh
set -eu

if [ "$#" -lt 2 ] || [ "$#" -gt 3 ]; then
    echo "Usage: $0 PP2 PUBLISHER_HOME [APP_SOURCE]" >&2
    exit 2
fi
pp2=$1
publisher=$2
example=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
entry_source=${3:-"$example/app.mjs"}
package_dir=$(mktemp -d)
trap 'rm -rf -- "$package_dir"' EXIT

"$pp2" app native identity "$publisher" >/dev/null
entry=$("$pp2" peer pack "$entry_source" "$package_dir/app.ppj")
index=$("$pp2" peer pack "$example/index.mjs" "$package_dir/index.ppj")
cat >"$package_dir/manifest.json" <<MANIFEST
{
  "name": "Document search",
  "entry": "$entry",
  "budget": {"timeout_ms": 6000, "calls": 4, "depth": 1},
  "bindings": {
    "documents": {
      "description": "Read a selected directory and update its index on the owning peer",
      "program": "$index",
      "access": "Write"
    }
  }
}
MANIFEST
package=$("$pp2" app native pack "$package_dir/manifest.json" "$package_dir/app.ppa")
for block in app.ppj index.ppj app.ppa; do
    "$pp2" peer put "$publisher/peer.db" "$package_dir/$block" --publish >/dev/null
done
printf '%s %s\n' "$package" "$index"
