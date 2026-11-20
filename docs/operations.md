# Operate a peer

## Workspace

The peer needs Linux 5.9 or later with seccomp and `close_range`. Directory grants also need `openat2` and filesystem creation timestamps. First use of stable identity needs the OpenSSL executable.

The CLI creates `~/.pp2` on first use. Set `PP2_HOME` for separate identities and keep its parent private. Stop processes before backing up the whole workspace. Protect the backup like the identity key and run only one advertiser per identity.

`pp2 list` shows installation IDs. Set `PP2_APP` when there is more than one. Choose update to keep private app state. See `pp2 app native --help` for installation management, `pp2 app --help` for fixed graphs and subscriptions, and `pp2 peer --help` for peer administration.

## Networking

Run `pp2 host` on a reachable TCP port. LAN discovery uses UDP multicast at `239.255.73.42:47342`. For `peer-unavailable`, check the listener, multicast interface, firewall, and clocks. Set `lan_interface` in `discovery.json` to select a local IPv4 interface.

Across networks, run `pp2 peer rendezvous 0.0.0.0:7341 --relay`. Put the reachable service address in both workspaces' `discovery.json` and restart the peers.

```json
{"rendezvous":"192.0.2.10:7341","relay":true}
```

Use `advertise` for reachable direct endpoints. Direct and relayed sessions authenticate the destination. [Discovery limits and identity rotation](architecture.md#peer-identity-and-discovery)

## Authority and recovery

Keep each grant ID and recipient. Run `pp2 revoke "$GRANT_ID"` at the issuer to withdraw future access. Disclosed data can persist in caches. Binding and package changes leave issued grants under the issuer's control.

For **awaiting grant**, check the request name, program, and access. For an ambiguous update, retry with identical arguments and the same operation ID. [Commit and retry rules](architecture.md#evaluation-and-authority)
