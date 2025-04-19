/**
 * Options for constructing a TLS ClientHello message.
 */
export interface ClientHelloOption {
  /**
   * TLS legacy_version (e.g., `Uint8Array.of(0x03, 0x03)` for TLS 1.2).
   */
  legacy_version?: Uint8Array;

  /**
   * 32-byte cryptographic random value.
   */
  random?: Uint8Array;

  /**
   * Session ID for resumption; can be empty.
   */
  session_id?: Uint8Array;

  /**
   * Supported cipher suites as a list of 2-byte numbers.
   * Example: [0x1301, 0x1302] for TLS_AES_128_GCM_SHA256, etc.
   */
  ciphers?: number[] | Uint16Array[];

  /**
   * Usually `[0x00]` to indicate "null compression".
   */
  legacy_compression_methods?: Uint8Array;

  /**
   * TLS versions supported, such as `[0x0304]` for TLS 1.3.
   */
  supported_versions?: number[] | Uint16Array[];

  /**
   * PSK key exchange modes, e.g. `[0x01]` (PSK_DHE_KE).
   */
  psk_key_exchange_modes?: number[] | Uint8Array;

  /**
   * Supported groups (named curves), e.g. `[0x001D]` for `x25519`.
   */
  supported_groups?: number[] | Uint16Array[];

  /**
   * Signature algorithms supported, such as `[0x0804]` (ed25519).
   */
  signature_algorithms?: number[] | Uint16Array[];

  /**
   * List of hostnames to include in the SNI extension.
   */
  server_names?: string[];
}

/**
 * Default ClientHello options used internally as fallback.
 */
export declare const defaultOption: Required<ClientHelloOption>;

/**
 * Composes a TLS 1.3 ClientHello message.
 * @version 0.0.6
 */
export declare function clientHelloCompose(
  option?: ClientHelloOption
): Uint8Array & { groups: number[] };
 