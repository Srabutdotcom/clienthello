import {
  Cipher,
  NamedGroup,
  OfferedPsks,
  SignatureScheme,
  Version,
} from "../src/dep.ts";
import { ClientHelloOption } from "../src/compose.js";

/**
 * Represents a TLS 1.3 ClientHello message as a binary structure.
 * Extends Uint8Array and provides convenient access to TLS fields.
 * @version 1.1.3
 */
export class ClientHello extends Uint8Array {
  /** compose ClientHello */
  static compose(option?: ClientHelloOption): ClientHello;

  /** Create a new instance from given arguments. */
  static create(...args: ConstructorParameters<typeof Uint8Array>): ClientHello;

  /** Alias for `create`. */
  static from: typeof ClientHello.create;

  /** Create a new ClientHello instance. */
  constructor(...args: ConstructorParameters<typeof Uint8Array>);

  /** The protocol version field from ClientHello. */
  get version(): Version;

  /** Alias for `version`. */
  get legacy_version(): Version;

  /** 32 bytes of cryptographic random bytes from the client. */
  get random(): Uint8Array;

  /** The legacy session ID from ClientHello. */
  get legacy_session_id(): Uint8Array & { end: number };

  /** Alias for `legacy_session_id`. */
  get session_id(): Uint8Array & { end: number };

  /** List of supported cipher suites. */
  get ciphers(): Cipher[] & { end: number };

  /**
   * The compression methods vector.
   * TLS 1.3 requires it to contain a single 0x00 value.
   */
  get legacy_compression_methods(): Uint8Array & { end: number };

  /**
   * Parsed extension list stored in a Map.
   */
  get extensions(): Map<number, any>;

  /** List of versions the client supports. */
  get supported_versions(): Version[];

  /** Key exchange modes the client supports. */
  get psk_key_exchange_modes(): number[];

  /** List of supported groups (elliptic curves, etc.). */
  get supported_groups(): NamedGroup[];

  /** Supported signature algorithms. */
  get signature_algorithms(): SignatureScheme[];

  /** List of SNI (Server Name Indication) names. */
  get server_names(): string[];

  /** Parsed Pre-Shared Keys offered by the client. */
  get offeredPsks(): OfferedPsks;

  /**
   * Creates a new ClientHello with binders added.
   * @param binders - Binder values to attach to PSK.
   */
  addBinders(binders: Uint8Array): ClientHello;

  /**
   * Wraps the ClientHello in a Handshake structure.
   */
  get handshake(): Uint8Array & {
    groups: any;
    message: ClientHello;
  };

  /**
   * Wraps the handshake in a TLS record.
   */
  get record(): Uint8Array & {
    groups: any;
    fragment: Uint8Array;
  };

  /**!SECTION
    * ```markdown
    * In order to maximize backward
      compatibility, a record containing an initial ClientHello SHOULD have
      version 0x0301 (reflecting TLS 1.0) and a record containing a second
      ClientHello or a ServerHello MUST have version 0x0303 (reflecting
      TLS 1.2).
      ```
  */
  get initRecord(): Uint8Array & {
    groups: any;
    fragment: Uint8Array;
  };

  /** Set the parsed key exchange groups (e.g., key share entries). */
  set groups(groups: any);

  /** Get the parsed key exchange groups. */
  get groups(): any;

  /** Set the application protocol (e.g., ALPN). */
  set proto(proto: any);

  /** Get the application protocol. */
  get proto(): any;

  /** Set the key share list. */
  set keyshares(keyshares: any);

  /** Get the key share list. */
  get keyshares(): any;

  /** Set the server name indication (SNI). */
  set sni(sni: any);

  /** Get the server name indication (SNI). */
  get sni(): any;
}
