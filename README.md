# tr-jwe

Compact JWE encrypt/decrypt for Node.js.

This package produces and consumes compact JWE tokens whose plaintext
is any JSON-serialisable value — object, array, string, number,
boolean, or `null`. It supports AES key wrap, AES-GCM key wrap, direct
encryption, RSA-based key transport, and ECDH-ES.

# Reference

## Installation

```sh
npm install tr-jwe
```

Node.js `>=24.0.0` is required.

## Exports

```js
const { encrypt, decrypt, unwrap } = require('tr-jwe');
```

## `encrypt(alg, jwk, data, options)`

Encrypts a JSON object and returns either a compact JWE string or, when
`extendedReturn` is set, an object that also exposes the content-encryption
key.

- `alg`: JWE key management algorithm
- `jwk`: recipient or wrapping key in JWK form
- `data`: plain JavaScript object
- `options`: optional object (defaults to `{}`)

Supported `options` fields:

- `compressPayload`
    - `false` (default): no compression.
    - `true`: payload is deflated and the header carries `zip: "DEF"`.
    - `"auto"`: payload is deflated only if the result is smaller than the
      raw JSON; otherwise the raw JSON is encrypted and no `zip` header is
      emitted.
- `extendedReturn`
    - `false` (default): the function returns the compact JWE string.
    - `true`: the function returns
      `{ token, contentEncryptionKey }` where `contentEncryptionKey` is an
      `oct` JWK suitable for `decrypt(token, contentEncryptionKey)`. This is
      useful when the caller needs to share or later re-derive the CEK
      without access to the wrapping key.

Unknown option keys and unexpected value types throw.

Supported `alg` values:

- `A128GCMKW`, `A192GCMKW`, `A256GCMKW`
- `A128KW`, `A192KW`, `A256KW`
- `dir`
- `RSA1_5`, `RSA-OAEP`, `RSA-OAEP-256`
- `ECDH-ES`

Content encryption is selected automatically:

- `A128GCMKW` and `A128KW` use `A128GCM`
- `A192GCMKW` and `A192KW` use `A192GCM`
- `A256GCMKW` and `A256KW` use `A256GCM`
- `dir` picks `A128GCM`, `A192GCM`, or `A256GCM` from key size
- `ECDH-ES` picks `A128GCM`, `A192GCM`, or `A256GCM` from EC curve
- RSA picks `A128GCM` for 1024-bit keys and `A256GCM` for 2048-bit or larger keys

Example:

```js
const { encrypt, decrypt } = require('tr-jwe');
const { cipherKeyGen } = require('tr-jwk');

const key = cipherKeyGen('A256GCMKW');
const token = encrypt('A256GCMKW', key, { message: 'secret' });
const payload = decrypt(token, key);

// Compression with auto-fallback and access to the content-encryption key:
const { token: t2, contentEncryptionKey: cek } =
    encrypt('A256GCMKW', key, { message: 'secret' },
            { compressPayload: 'auto', extendedReturn: true });
const samePayload = decrypt(t2, cek);
```

## `decrypt(token, jwk)`

Decrypts a compact JWE token and returns the parsed JSON payload.

The expected JWK depends on the token:

- AES wrap and `dir`: `oct` JWK
- RSA algorithms: RSA private JWK
- `ECDH-ES`: EC private JWK

## `unwrap(token, jwk)`

Derives or unwraps the content-encryption key from a compact JWE token and returns it as an `oct` JWK.

This is useful when the recipient wants the CEK itself instead of the decrypted payload.

## Notes

- Payload input may be any JSON-serialisable value (object, array,
  string, number, boolean, or `null`).
- Only compact serialization is supported.
- Only AES-GCM content encryption is implemented.
- Compression uses raw DEFLATE (`zip: "DEF"`).

# Author

Timo J. Rinne <tri@iki.fi> — https://github.com/rinne/

# Copyright

Copyright © 2023–2026 Timo J. Rinne <tri@iki.fi>.
See `COPYING` for the full MIT license text.

# License

MIT License
