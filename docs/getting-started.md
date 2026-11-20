# Search files across two machines

Begin on the computer that owns the documents. Use a fresh Linux account or set `PP2_HOME` to a new private workspace path. Install the runtime and TypeScript compiler from the checkout as in the [README](../README.md#try-document-search). If you completed the README example, you can use that installation and skip to **Connect a laptop**.

## Create and run the application locally

Run these commands from the checkout. The generated project contains editable source, and the sample directory contains one meeting note.

```sh
pp2 new search
pp2 install search
pp2 grant documents examples/native-documents/sample
pp2 run index
pp2 run 'search budget'
```

Approve the package after reviewing the request. The result includes `meeting.md`. You can substitute a directory of your own at the grant step. The starter reads up to 32 UTF-8 Markdown or plain text files, at most 16 KiB each, in up to 20 directories including the root.

The terminal code in `search/app.mjs` sends a search query through the named `documents` capability. The TypeScript function in `search/index.ts` runs where that capability points. To change which files it indexes, edit the filename extension check there. The [application guide](applications.md) explains how to install the change.

## Connect a laptop

Use two Linux machines on the same IPv4 LAN with synchronized clocks. Allow UDP multicast on port 47342 and inbound TCP on port 7340 at the owner. For another network arrangement see [peer operations](operations.md#networking).

1. Install the runtime on the laptop using the Cargo step from the README, or copy the built executable to a compatible Linux system. The laptop needs OpenSSL for first use. It can fetch compiled applications without Node.js, npm or the project checkout. On the laptop run:

   ```sh
   pp2 identity
   ```

2. Give that identity to the owner over a trusted channel. On the owner set the shell variable `LAPTOP_ID` to the received value. From the same checkout and workspace used above, run:

   ```sh
   pp2 publish
   pp2 grant documents examples/native-documents/sample "$LAPTOP_ID" > documents.grant
   pp2 host 0.0.0.0:7340
   ```

   The first command prints a package address in the form `PACKAGE@PEER`. The second writes a grant addressed to the laptop. Save the grant ID printed on stderr for revocation. Give the laptop the package address and the grant file through a trusted channel. Keep the host process running. Publishing exposes the compiled app and its imports to peers. The selected files and index stay private to the owner.

3. On the laptop, set `RELEASE` to the package address and put the received file in the current directory. Review and approve the installation, then run:

   ```sh
   pp2 install --from "$RELEASE"
   pp2 connect documents documents.grant
   pp2 run index
   pp2 run 'search budget'
   ```

   The laptop prints `meeting.md` with the owner's current revision. Stop the owner with Ctrl-C and repeat the search on the laptop. A previously successful query prints its cached paths and revision. A new query reports that it has no cached result. Restart the owner to refresh the index.

Starting with the locally tested project, the first remote execution takes seven pp2 commands including the laptop identity, publication, grant, host, installation, connection and first invocation. It uses two private workspaces, one package address and one transferred grant file. The LAN path requires no hand-written network configuration. Starting from the supplied project source adds one owner-side install command. Creating an editable copy with the starter adds one more.
