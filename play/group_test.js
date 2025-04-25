import { NamedGroup } from "../src/dep.ts";

const a = NamedGroup.X25519;
const b = NamedGroup.X25519;

console.log("is Both group the same :", a.privateKey.toString()==b.privateKey.toString());

