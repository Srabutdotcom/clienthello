//@ts-self-types = "../type/clienthello.d.ts"
import { Cipher, Cookie, EarlyDataIndication, Extension, ExtensionType, KeyShareClientHello, NamedGroupList, OfferedPsks, Padding, PskKeyExchangeModes, RecordSizeLimit, unity, ServerNameList, SignatureSchemeList, Uint16, Uint24, Version, Versions } from "./dep.ts";
//import { parseItems } from "./utils.js"
import { parseItems } from "./dep.ts"

export class ClientHello extends Uint8Array {
   #version
   #random
   #legacy_session_id
   #ciphers
   #legacy_compression_methods
   #extensions
   #groups
   #proto
   #keyshares
   #sni

   static create(...args) {
      return new ClientHello(...args)
   }
   static from = ClientHello.create
   constructor(...args) {
      sanitize(args)
      super(...args)
   }
   get version() {
      this.#version ||= Version.from(this.subarray(0, 2))
      return this.#version
   }
   get legacy_version() { return this.version }
   get random() {
      this.#random ||= this.subarray(2, 34);
      return this.#random;
   }
   get legacy_session_id() {
      if (this.#legacy_session_id) return this.#legacy_session_id
      const lengthOf = this.at(34);
      if (lengthOf == 0) {
         this.#legacy_session_id = this.subarray(34, 35);
         this.#legacy_session_id.end = 35
      } else {
         const end = 35 + lengthOf
         this.#legacy_session_id = this.subarray(35, end);
         this.#legacy_session_id.end = end;
      }
      return this.#legacy_session_id
   }
   get session_id() { return this.legacy_session_id }
   get ciphers() {
      if (this.#ciphers) return this.#ciphers;
      const lengthOf = Uint16.from(this.subarray(this.legacy_session_id.end)).value;
      if (lengthOf < 2) throw Error(`expected at list one cipher`)
      const start = this.legacy_session_id.end + 2;
      const end = start + lengthOf;
      this.#ciphers = parseItems(this, start, lengthOf, Cipher);//
      this.#ciphers.end = end;
      return this.#ciphers;
   }
   /**
    * For every TLS 1.3 ClientHello, this vector
      MUST contain exactly one byte, set to zero, which corresponds to
      the "null" compression method in prior versions of TLS.  If a
      TLS 1.3 ClientHello is received with any other value in this
      field, the server MUST abort the handshake with an
      "illegal_parameter" alert.
    */
   get legacy_compression_methods() {
      if (this.#legacy_compression_methods) return this.#legacy_compression_methods
      const end = this.ciphers.end + 2;
      this.#legacy_compression_methods ||= this.subarray(this.ciphers.end, end);
      this.#legacy_compression_methods.end = end
      return this.#legacy_compression_methods
   }
   get extensions() {
      if (this.#extensions) return this.#extensions;
      const copy = this.subarray(this.legacy_compression_methods.end)
      const lengthOf = Uint16.from(copy).value;
      this.#extensions ||= parseItems(copy, 2, lengthOf, Extension, { parser: parseExtension, store: new Map, storeset: (store, data) => store.set(data.type, data.data) }) //output;
      return this.#extensions;
   }
   get supported_versions() {
      const data = this.extensions.get(ExtensionType.SUPPORTED_VERSIONS);
      return Versions.from(data).versions;
   }
   get psk_key_exchange_modes() {
      const data = this.extensions.get(ExtensionType.PSK_KEY_EXCHANGE_MODES);
      return PskKeyExchangeModes.from(data).ke_modes
   }
   get supported_groups() {
      const data = this.extensions.get(ExtensionType.SUPPORTED_GROUPS);
      return NamedGroupList.from(data).named_group_list
   }
   get signature_algorithms() {
      const data = this.extensions.get(ExtensionType.SIGNATURE_ALGORITHMS);
      return SignatureSchemeList.from(data).supported_signature_algorithms
   }
   get server_names() {
      const data = this.extensions.get(ExtensionType.SERVER_NAME);
      return [...ServerNameList.from(data).serverNames].map(e => e.name)
   }
   get offeredPsks() {
      const data = this.extensions.get(ExtensionType.PRE_SHARED_KEY);
      return OfferedPsks.from(data)
   }
   addBinders(binders) {
      const _psk = this.extensions.get(ExtensionType.PRE_SHARED_KEY);
      const array = unity(this, binders);
      return new ClientHello(array)
   }
   get handshake() {
      const handshake = unity(1, Uint24.fromValue(this.length), this);
      handshake.groups = this.groups;
      handshake.message = this
      return handshake;
   }
   get record() {
      const handshake = this.handshake
      const record = unity(22, Version.TLS10.byte, Uint16.fromValue(handshake.length), handshake);
      record.groups = this.groups;
      record.fragment = handshake;
      return record
   }
   set groups(groups) {
      this.#groups = groups;
   }
   get groups() {
      if (this.#groups) return this.#groups;
      this.#groups ||= this.extensions.get(ExtensionType.KEY_SHARE).data.keyShareEntries
      return this.#groups;
   }
   set proto(proto) {
      this.#proto = proto;
   }
   get proto() {
      return this.#proto;
   }
   set keyshares(keyshares) {
      this.#keyshares = keyshares;
   }
   get keyshares() {
      return this.#keyshares;
   }
   set sni(sni) {
      this.#sni = sni;
   }
   get sni() {
      return this.#sni;
   }
}

function isUint8Array(data) { return data instanceof Uint8Array }

function sanitize(args) {
   const data = args[0]
   if (isUint8Array(data) == false) return
   let offset = 0;
   // client_version (2 bytes) + random (32 bytes)
   if (Version.from(data).value < 0x0300) return Alert.fromAlertDescription(AlertDescription.PROTOCOL_VERSION)
   offset += 2 + 32;

   // session_id
   const sessionIdLen = data[offset];
   if (sessionIdLen > 32) return Alert.fromAlertDescription(AlertDescription.UNEXPECTED_MESSAGE)
   offset += 1 + sessionIdLen;

   // cipher_suites
   const cipherSuitesLen = (data[offset] << 8) | data[offset + 1];
   const _ciphers = parseItems(data, offset + 2, cipherSuitesLen, Cipher);
   offset += 2 + cipherSuitesLen;

   // compression_methods
   const compressionMethodsLen = data[offset];
   if (compressionMethodsLen !== 1) return Alert.fromAlertDescription(AlertDescription.UNEXPECTED_MESSAGE)
   offset += 1 + compressionMethodsLen;

   // extensions
   const extensionsLen = (data[offset] << 8) | data[offset + 1];
   const _extensions = parseItems(data, offset + 2, extensionsLen, Extension);
   offset += 2;

   // ClientHello may have trunchated data
   //if (offset + extensionsLen > data.length) return Alert.fromAlertDescription(AlertDescription.UNEXPECTED_MESSAGE);

   args[0] = data.subarray(0, offset + extensionsLen);
   return
}

function parseExtension(extension) {
   switch (extension.type) {
      case ExtensionType.SUPPORTED_GROUPS: {
         extension.parser = NamedGroupList; break;
      }
      case ExtensionType.KEY_SHARE: {
         extension.parser = KeyShareClientHello; break;
      }
      case ExtensionType.SUPPORTED_VERSIONS: {
         extension.parser = Versions; break;
      }
      case ExtensionType.SIGNATURE_ALGORITHMS: {
         extension.parser = SignatureSchemeList; break;
      }
      case ExtensionType.SERVER_NAME: {
         extension.parser = extension.data.length ? ServerNameList : undefined; break;
      }
      case ExtensionType.PSK_KEY_EXCHANGE_MODES: {
         extension.parser = PskKeyExchangeModes; break;
      }
      case ExtensionType.COOKIE: {
         extension.parser = Cookie; break;
      }
      case ExtensionType.RECORD_SIZE_LIMIT: {
         extension.parser = RecordSizeLimit; break;
      }
      case ExtensionType.EARLY_DATA: {
         extension.parser = EarlyDataIndication; break;
      }
      case ExtensionType.PADDING: {
         extension.parser = Padding; break;
      }
      case ExtensionType.PRE_SHARED_KEY: {
         extension.parser = OfferedPsks; break;
      }
      default:
         break;
   }
}



