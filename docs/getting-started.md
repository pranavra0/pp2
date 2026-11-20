# Search files across two machines

On the document owner, follow the [quickstart](../README.md#try-document-search) in a fresh workspace. For editable source, run `pp2 new search` and substitute `pp2 install search`. The starter indexes up to 32 UTF-8 Markdown or text files, 16 KiB each, across up to 20 directories including the root.

## Connect a laptop

Use two Linux machines on the same IPv4 LAN with synchronized clocks. Allow UDP multicast on port 47342 and inbound TCP on port 7340 at the owner. For other networks, see [peer operations](operations.md#networking).

1. Install pp2 on the laptop or copy a compatible executable. First use requires OpenSSL. Run `pp2 identity` and send the ID to the owner over a trusted channel.
2. On the owner, set `LAPTOP_ID` to that ID and run from the checkout and workspace used above.

   ```sh
   pp2 publish
   pp2 grant documents examples/native-documents/sample "$LAPTOP_ID" > documents.grant
   pp2 host 0.0.0.0:7340
   ```

   Save the grant ID printed on stderr for revocation. Send the `PACKAGE@PEER` address and `documents.grant` to the laptop. Keep the host running.
3. On the laptop, set `RELEASE` to the package address and put the grant in the current directory. Review the package before approving.

   ```sh
   pp2 install --from "$RELEASE"
   pp2 connect documents documents.grant
   pp2 run index
   pp2 run 'search budget'
   ```

   The laptop prints `meeting.md` with the owner's index revision. With the host stopped, a previously successful query shows its cached paths and revision. Restart the host to refresh.
