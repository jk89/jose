# @dxe/runtime-independent-crypto-utilities

> Native crypto runtime independent utilities

## Implemented specs & features

The following specifications are implemented:

- parseKeyToJWK,
- parseJWKToKey,
- digest,
- timingSafeEqual,
- checkCekLength,
- sign,
- verify,
- encrypt,
- decrypt,
- fetch,
- random,
- encryptPbes2kw,
- decryptPbes2kw,



## Support Matrix

| Key Types | Supported | `kty` value | |
| -- | -- | -- | -- |
| RSA | ✓ | RSA | |
| Elliptic Curve | ✓ | EC | supported curves: P-256, secp256k1, P-384, P-521 |
| Octet Key Pair | ✓ | OKP | supported subtypes: Ed25519, Ed448, X25519, X448 |
| Octet sequence | ✓ | oct | |


| JWS Algorithms | Supported | |
| -- | -- | -- |
| RSASSA-PKCS1-v1_5 | ✓ | RS256, RS384, RS512 |
| RSASSA-PSS | ✓ | PS256, PS384, PS512 |
| ECDSA | ✓ | ES256, ES256K, ES384, ES512 |
| Edwards-curve DSA | ✓ | EdDSA |
| HMAC with SHA-2 | ✓ | HS256, HS384, HS512 |
| Unsecured JWS | ✓ | none |

| JWE Management Algorithms | Supported | |
| -- | -- | -- |
| AES | ✓ | A128KW, A192KW, A256KW |
| AES GCM | ✓ | A128GCMKW, A192GCMKW, A256GCMKW |
| Direct Key Agreement | ✓ | dir |
| RSAES OAEP | ✓ | RSA-OAEP, RSA-OAEP-256, RSA-OAEP-384, RSA-OAEP-512 |
| RSAES-PKCS1-v1_5 | ✓ | RSA1_5 |
| PBES2 | ✓ | PBES2-HS256+A128KW, PBES2-HS384+A192KW, PBES2-HS512+A256KW |
| ECDH-ES | ✓ | ECDH-ES, ECDH-ES+A128KW, ECDH-ES+A192KW, ECDH-ES+A256KW |

| Content Encryption Algorithms | Supported | |
| -- | -- | -- |
| AES GCM | ✓ | A128GCM, A192GCM, A256GCM |
| AES CBC w/ HMAC | ✓ |  A128CBC-HS256, A192CBC-HS384, A256CBC-HS512 |

Legend:
- **✓** Implemented
- **✕** Not Considered

## Runtime Support Matrix

| Platform | supported versions | caveats |
| -- | -- | -- |
| Node.js | LTS ^12.19.0 &vert;&vert; ^14.15.0 | |
| Electron | `process.version` must match<br> the Node.js supported versions. So 12+</sup> | see <sup>[1]</sup> |
| Deno | ✕ | needs [Web Cryptography API integration](https://github.com/denoland/deno/issues/1891) first |
| React Native | ✕ | has no available and usable crypto runtime |
| IE | ✕ | implements old version of the Web Cryptography API specification |
| Browsers | see [caniuse.com][caniuse] | |
| --- | | |
| Edge | 79+ | see <sup>[2], [4]</sup> |
| Firefox | 57+ | see <sup>[2]</sup> |
| Chrome | 63+ | see <sup>[2], [4]</sup> |
| Safari | 11+ | see <sup>[2], [3]</sup> |
| Opera | 50+ | see <sup>[2], [4]</sup> |
| iOS Safari | 12+ | see <sup>[2], [3]</sup> |

<sup>1</sup> Due to its use of BoringSSL the following is not supported in Electron
  - A128KW, A192KW, A256KW, and all composite algorithms utilizing those
  - secp256k1 EC curves
  - Ed448, X25519, and X448 OKP Sub Types  

<sup>2</sup> RSA1_5, OKP JWK Key Type, and secp256k1 EC curve is not supported in [Web Cryptography API][webcrypto].   

<sup>3</sup> P-521 EC curve is not supported in Safari  

<sup>4</sup> 192 bit AES keys are not supported in Chromium  

## FAQ


#### Semver?

**Yes.** All module's public API is subject to [Semantic Versioning 2.0.0](https://semver.org/spec/v2.0.0.html).

#### Uint8Array?!

- Whenever `Uint8Array` is a valid input, so is [`Buffer`](https://nodejs.org/api/buffer.html#buffer_buffer) since buffers are instances of Uint8Array.
- Whenever `Uint8Array` is returned and you want a `Buffer` instead, use `Buffer.from(uint8array)`.


#### Most types are "any"

Install @types/node as your project's development dependency

```
npm install --save-dev @types/node
```

#### "Cannot find module '...' or its corresponding type declarations."

Install @types/node as your project's development dependency

```
npm install --save-dev @types/node
```

#### "Module '"crypto"' has no exported member '...'"

Update @types/node as your project's development dependency

```
npm uninstall @types/node
npm install --save-dev @types/node
```

#### "Module not found: Error: Can't resolve '...' in '...'"

Use a supported Node.js runtime and make sure whatever tools you may use for transpiling the code also support the Subpath exports ("exports") feature.

#### Why? Just. Why?

[documentation]: /docs/README.md
[node-jose]: https://github.com/cisco/node-jose
[spec-b64]: https://tools.ietf.org/html/rfc7797
[spec-cookbook]: https://tools.ietf.org/html/rfc7520
[spec-jwa]: https://tools.ietf.org/html/rfc7518
[spec-jwe]: https://tools.ietf.org/html/rfc7516
[spec-jwk]: https://tools.ietf.org/html/rfc7517
[spec-jws]: https://tools.ietf.org/html/rfc7515
[spec-jwt]: https://tools.ietf.org/html/rfc7519
[spec-okp]: https://tools.ietf.org/html/rfc8037
[spec-secp256k1]: https://tools.ietf.org/html/rfc8812
[spec-thumbprint]: https://tools.ietf.org/html/rfc7638
[support-sponsor]: https://github.com/sponsors/panva
[conditional-exports]: https://nodejs.org/api/packages.html#packages_conditional_exports
[webcrypto]: https://www.w3.org/TR/WebCryptoAPI/
[nodewebcrypto]: https://nodejs.org/docs/latest-v15.x/api/webcrypto.html
[caniuse]: https://caniuse.com/mdn-javascript_operators_await,async-functions,mdn-javascript_statements_for_await_of,cryptography,textencoder

# ignore 
    "!dist/types/runtime/*",
    "!dist/types/lib/*",
    "dist/types/lib/jwt_producer.d.ts"