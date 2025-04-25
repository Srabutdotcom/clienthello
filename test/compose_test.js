import { clientHelloCompose } from "../src/compose.js";
import { NamedGroup } from "../src/dep.ts";

const clientHello_1 = clientHelloCompose({server_names:["test"],groups:[NamedGroup.X25519]});

clientHello_1.groups = [NamedGroup.SECP256R1]

const clientHello_2 =clientHelloCompose(clientHello_1);

let i = 0;
for(const e of clientHello_1){
   console.log(`index: ${i}-first:${e} - next:${clientHello_2[i]} ${e==clientHello_2[i]}`);
   i++;
}
