# TLS 1.3 Parameter Structures (RFC 8446 - Section 4.1)
@version 0.10.0

This project provides JavaScript implementations for handling TLS 1.3 parameters as defined in [RFC 8446 Section 4.1](https://datatracker.ietf.org/doc/html/rfc8446#section-4.1). The code focuses on encoding, decoding, and managing the data structures involved in the `ClientHello` messages during the TLS 1.3 handshake process.

## Features

- **ClientHello**: Implements the `ClientHello` message structure.
  - Encodes and decodes client-generated parameters such as `key_share`, `supported_versions`, and `extensions`.
  - Validates constraints and ensures compliance with RFC 8446 requirements.


### Usage

Import the modules and use them to construct and manage handshake messages:

```javascript
import { ClientHello } from "@tls/clienthello";

// ClientHello usage
const clientHello = new ClientHello();

```

## Completed Work

- [x] 4.1.2. ClientHello


## References

- [RFC 8446: The Transport Layer Security (TLS) Protocol Version 1.3](https://datatracker.ietf.org/doc/html/rfc8446)

### Donation

- [Support the project on PayPal](https://paypal.me/aiconeid)

### License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.