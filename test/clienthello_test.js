import { Byte, Binders } from "../src/dep.ts"
import { ClientHello } from "../src/clienthello.js"

// from RFC 8448 sample
export const clientHelloRFC8448 = Byte.fromHex(`03 03 cb
   34 ec b1 e7 81 63 ba 1c 38 c6 da cb 19 6a 6d ff a2 1a 8d 99 12
   ec 18 a2 ef 62 83 02 4d ec e7 00 00 06 13 01 13 03 13 02 01 00
   00 91 00 00 00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01
   00 00 0a 00 14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02
   01 03 01 04 00 23 00 00 00 33 00 26 00 24 00 1d 00 20 99 38 1d
   e5 60 e4 bd 43 d2 3d 8e 43 5a 7d ba fe b3 c0 6e 51 c1 3c ae 4d
   54 13 69 1e 52 9a af 2c 00 2b 00 03 02 03 04 00 0d 00 20 00 1e
   04 03 05 03 06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02
   01 04 02 05 02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01`)

const clientHelloRFC8448back = ClientHello.from(clientHelloRFC8448);

const {
   supported_versions,
   psk_key_exchange_modes,
   supported_groups,
   signature_algorithms,
   server_names } = clientHelloRFC8448back;

const clientHelloPSKBinder = Byte.fromHex(
   `01 00 01 fc 03 03 1b c3 ce b6 bb
   e3 9c ff 93 83 55 b5 a5 0a db 6d b2 1b 7a 6a f6 49 d7 b4 bc 41
   9d 78 76 48 7d 95 00 00 06 13 01 13 03 13 02 01 00 01 cd 00 00
   00 0b 00 09 00 00 06 73 65 72 76 65 72 ff 01 00 01 00 00 0a 00
   14 00 12 00 1d 00 17 00 18 00 19 01 00 01 01 01 02 01 03 01 04
   00 33 00 26 00 24 00 1d 00 20 e4 ff b6 8a c0 5f 8d 96 c9 9d a2
   66 98 34 6c 6b e1 64 82 ba dd da fe 05 1a 66 b4 f1 8d 66 8f 0b
   00 2a 00 00 00 2b 00 03 02 03 04 00 0d 00 20 00 1e 04 03 05 03
   06 03 02 03 08 04 08 05 08 06 04 01 05 01 06 01 02 01 04 02 05
   02 06 02 02 02 00 2d 00 02 01 01 00 1c 00 02 40 01 00 15 00 57
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00
   00 00 00 00 29 00 dd 00 b8 00 b2 2c 03 5d 82 93 59 ee 5f f7 af
   4e c9 00 00 00 00 26 2a 64 94 dc 48 6d 2c 8a 34 cb 33 fa 90 bf
   1b 00 70 ad 3c 49 88 83 c9 36 7c 09 a2 be 78 5a bc 55 cd 22 60
   97 a3 a9 82 11 72 83 f8 2a 03 a1 43 ef d3 ff 5d d3 6d 64 e8 61
   be 7f d6 1d 28 27 db 27 9c ce 14 50 77 d4 54 a3 66 4d 4e 6d a4
   d2 9e e0 37 25 a6 a4 da fc d0 fc 67 d2 ae a7 05 29 51 3e 3d a2
   67 7f a5 90 6c 5b 3f 7d 8f 92 f2 28 bd a4 0d da 72 14 70 f9 fb
   f2 97 b5 ae a6 17 64 6f ac 5c 03 27 2e 97 07 27 c6 21 a7 91 41
   ef 5f 7d e6 50 5e 5b fb c3 88 e9 33 43 69 40 93 93 4a e4 d3 57
   fa d6 aa cb`
)
const clientHelloPSKBinderBack = ClientHello.from(clientHelloPSKBinder.subarray(4));

// this is truncated offeredPsks where binders list is being calculated and added into the end of this extension.,
// the length of ClientHello including binders list eventhough it is not added yet.
const { offeredPsks } = clientHelloPSKBinderBack;

/**!SECTION
 * binders calculation refer to {@link https://datatracker.ietf.org/doc/html/rfc8446#section-4.2.11.2 PSK Binder}
 * The PskBinderEntry is computed in the same way as the Finished
   message (Section 4.4.4) but with the BaseKey being the binder_key
   derived via the key schedule from the corresponding PSK which is
   being offered
   ```
   PskBinderEntry binders<33..2^16-1>;
   opaque PskBinderEntry<32..255>;
   ```
 */
const binders = Byte.fromHex(`00 21 20 3a dd 4f b2 d8 fd f8 22 a0 ca
   3c f7 67 8e f5 e8 8d ae 99 01 41 c5 92 4d 57 bb 6f a3 1b 9e 5f
   9d`);
const bindersBack = Binders.from(binders)

/**!SECTION
 * Add binders to the last of truncated ClientHello
 */
const clientHelloPsk_0 = clientHelloPSKBinderBack.addBinders(binders);


