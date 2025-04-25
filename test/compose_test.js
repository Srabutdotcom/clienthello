import { clientHelloCompose } from "../src/compose.js";
import { NamedGroup } from "../src/dep.ts";

const clientHello_1 = clientHelloCompose({});

clientHello_1.groups = [NamedGroup.X25519]

const clientHello_2 =clientHelloCompose(clientHello_1);
