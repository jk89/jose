
/* eslint-disable @typescript-eslint/naming-convention */
import type { KeyObject } from 'crypto'
import digest from '../runtime/digest.js';
import parseKeyToJWK from '../runtime/key_to_jwk.js';
import parseJWKToKey from '../runtime/jwk_to_key.js';
import timingSafeEqual from '../runtime/timing_safe_equal.js';
import checkCekLength from '../runtime/check_cek_length.js';
import sign from '../runtime/sign.js';
import verify from '../runtime/verify.js';
import encrypt from '../runtime/encrypt.js';
import decrypt from '../runtime/decrypt.js';
import fetch from '../runtime/fetch.js';
import random from '../runtime/random.js';
import { encrypt as encryptPbes2kw, decrypt as decryptPbes2kw } from '../runtime/pbes2kw.js';
import checkIvLength from './check_iv_length.js';
import checkKeyType from './check_key_type.js';
import checkP2s from './check_p2s.js';
import decryptKeyManagement from './decrypt_key_management.js';
import encryptKeyManagement from './encrypt_key_management.js';
import isDisjoint from './is_disjoint.js';
import isObject from './is_object.js';
import toEpoch from './epoch.js';
import runtime from './env.js';



export * from './buffer_utils.js';
export * from './cek.js';


export * from '../runtime/aesgcmkw.js';
export * from '../runtime/generate.js';
export * from '../runtime/ecdhes.js';
export * from '../runtime/base64url.js';
export * from '../runtime/base64.js';
export * from '../runtime/webcrypto.js';
export * from '../runtime/zlib.js';
// export * from '../runtime/interfaces.js';
export { 
    runtime,
    toEpoch,
    isObject,
    isDisjoint,
    decryptKeyManagement,
    encryptKeyManagement,
    checkP2s,
    checkKeyType,
    checkIvLength,
    parseKeyToJWK,
    parseJWKToKey,
    digest,
    timingSafeEqual,
    checkCekLength,
    sign,
    verify,
    encrypt,
    decrypt,
    fetch,
    random,
    encryptPbes2kw,
    decryptPbes2kw,
};


/**
 * JSON Web Key ([JWK](https://tools.ietf.org/html/rfc7517)).
 * "RSA", "EC", "OKP", and "oct" key types are supported.
 */
export interface DXEJWK {
    /**
     * JWK "alg" (Algorithm) Parameter.
     */
    alg?: string
    crv?: string
    d?: string
    dp?: string
    dq?: string
    e?: string
    /**
     * JWK "ext" (Extractable) Parameter.
     */
    ext?: boolean
    k?: string
    /**
     * JWK "key_ops" (Key Operations) Parameter.
     */
    key_ops?: string[]
    /**
     * JWK "kid" (Key ID) Parameter.
     */
    kid?: string
    /**
     * JWK "kty" (Key Type) Parameter.
     */
    kty?: string
    n?: string
    oth?: Array<{
      d?: string
      r?: string
      t?: string
    }>
    p?: string
    q?: string
    qi?: string
    /**
     * JWK "use" (Public Key Use) Parameter.
     */
    use?: string
    x?: string
    y?: string
    /**
     * JWK "x5c" (X.509 Certificate Chain) Parameter.
     */
    x5c?: string[]
    /**
     * JWK "x5t" (X.509 Certificate SHA-1 Thumbprint) Parameter.
     */
    x5t?: string
    /**
     * "x5t#S256" (X.509 Certificate SHA-256 Thumbprint) Parameter.
     */
    'x5t#S256'?: string
    /**
     * JWK "x5u" (X.509 URL) Parameter.
     */
    x5u?: string
  }
  
  /**
   * Generic Interface for consuming operations dynamic key resolution.
   * No token components have been verified at the time of this function call.
   *
   * If you cannot match a key suitable for the token, throw an error instead.
   *
   * @param protectedHeader JWE or JWS Protected Header.
   * @param token The consumed JWE or JWS token.
   */
  export interface DXEGetKeyFunction<T, T2> {
    (protectedHeader: T, token: T2): Promise<DXEKeyLike>
  }
  
  /**
   * KeyLike are platform-specific references to keying material.
   *
   * - [KeyObject](https://nodejs.org/api/crypto.html#crypto_class_keyobject) instances come from
   * node's [crypto module](https://nodejs.org/api/crypto.html) (see crypto.generateKeyPair,
   * crypto.createPublicKey, crypto.createPrivateKey, crypto.createSecretKey).
   * - [CryptoKey](https://www.w3.org/TR/WebCryptoAPI) instances come from
   * [Web Cryptography API](https://www.w3.org/TR/WebCryptoAPI) (see SubtleCrypto.importKey,
   * SubtleCrypto.generateKey, SubtleCrypto.deriveKey, SubtleCrypto.unwrapKey).
   * - [Uint8Array](https://developer.mozilla.org/en-US/docs/Web/JavaScript/Reference/Global_Objects/Uint8Array)
   * is used exclusively for symmetric secret representations, a CryptoKey or KeyObject is
   * preferred, but in Web Crypto API this isn't an option for some algorithms.
   */
  export type DXEKeyLike = KeyObject | CryptoKey | Uint8Array
  
  /**
   * Flattened JWS definition for verify function inputs, allows payload as
   * Uint8Array for detached signature validation.
   */
  export interface DXEFlattenedJWSInput {
    /**
     * The "header" member MUST be present and contain the value JWS
     * Unprotected Header when the JWS Unprotected Header value is non-
     * empty; otherwise, it MUST be absent.  This value is represented as
     * an unencoded JSON object, rather than as a string.  These Header
     * Parameter values are not integrity protected.
     */
    header?: DXEJWSHeaderParameters
  
    /**
     * The "payload" member MUST be present and contain the value
     * BASE64URL(JWS Payload). When RFC7797 "b64": false is used
     * the value passed may also be a Uint8Array.
     */
    payload: string | Uint8Array
  
    /**
     * The "protected" member MUST be present and contain the value
     * BASE64URL(UTF8(JWS Protected Header)) when the JWS Protected
     * Header value is non-empty; otherwise, it MUST be absent.  These
     * Header Parameter values are integrity protected.
     */
    protected?: string
  
    /**
     * The "signature" member MUST be present and contain the value
     * BASE64URL(JWS Signature).
     */
    signature: string
  }
  
  /**
   * General JWS definition for verify function inputs, allows payload as
   * Uint8Array for detached signature validation.
   */
  export interface DXEGeneralJWSInput {
    /**
     * The "payload" member MUST be present and contain the value
     * BASE64URL(JWS Payload). When RFC7797 "b64": false is used
     * the value passed may also be a Uint8Array.
     */
    payload: string | Uint8Array
  
    /**
     * The "signatures" member value MUST be an array of JSON objects.
     * Each object represents a signature or MAC over the JWS Payload and
     * the JWS Protected Header.
     */
    signatures: Omit<DXEFlattenedJWSInput, 'payload'>[]
  }
  
  /**
   * Flattened JWS definition. Payload is an optional return property, it
   * is not returned when JWS Unencoded Payload Option
   * [RFC7797](https://tools.ietf.org/html/rfc7797) is used.
   */
  export interface DXEFlattenedJWS extends Partial<DXEFlattenedJWSInput> {
    payload?: string
    signature: string
  }
  
  /**
   * General JWS definition. Payload is an optional return property, it
   * is not returned when JWS Unencoded Payload Option
   * [RFC7797](https://tools.ietf.org/html/rfc7797) is used.
   */
  export interface DXEGeneralJWS {
    payload?: string
    signatures: Omit<DXEFlattenedJWSInput, 'payload'>[]
  }
  
  export interface DXEJoseHeaderParameters {
    /**
     * "kid" (Key ID) Header Parameter.
     */
    kid?: string
  
    /**
     * "x5t" (X.509 Certificate SHA-1 Thumbprint) Header Parameter.
     */
    x5t?: string
  
    /**
     * "x5c" (X.509 Certificate Chain) Header Parameter.
     */
    x5c?: string[]
  
    /**
     * "x5u" (X.509 URL) Header Parameter.
     */
    x5u?: string
  
    /**
     * "jwk" (JSON Web Key) Header Parameter.
     */
    jwk?: Pick<DXEJWK, 'kty' | 'crv' | 'x' | 'y' | 'e' | 'n'>
  
    /**
     * "typ" (Type) Header Parameter.
     */
    typ?: string
  
    /**
     * "cty" (Content Type) Header Parameter.
     */
    cty?: string
  }
  
  /**
   * Recognized JWS Header Parameters, any other Header Members
   * may also be present.
   */
  export interface DXEJWSHeaderParameters extends DXEJoseHeaderParameters {
    /**
     * JWS "alg" (Algorithm) Header Parameter.
     */
    alg?: string
  
    /**
     * This JWS Extension Header Parameter modifies the JWS Payload
     * representation and the JWS Signing Input computation as per
     * [RFC7797](https://tools.ietf.org/html/rfc7797).
     */
    b64?: boolean
  
    /**
     * JWS "crit" (Critical) Header Parameter.
     */
    crit?: string[]
  
    /**
     * Any other JWS Header member.
     */
    [propName: string]: any
  }
  
  /**
   * Recognized JWE Key Management-related Header Parameters.
   */
  export interface DXEJWEKeyManagementHeaderParameters {
    apu?: Uint8Array
    apv?: Uint8Array
    epk?: DXEKeyLike
    iv?: Uint8Array
    p2c?: number
    p2s?: Uint8Array
  }
  
  /**
   * Flattened JWE definition.
   */
  export interface DXEFlattenedJWE {
    /**
     * The "aad" member MUST be present and contain the value
     * BASE64URL(JWE AAD)) when the JWE AAD value is non-empty;
     * otherwise, it MUST be absent.  A JWE AAD value can be included to
     * supply a base64url-encoded value to be integrity protected but not
     * encrypted.
     */
    aad?: string
  
    /**
     * The "ciphertext" member MUST be present and contain the value
     * BASE64URL(JWE Ciphertext).
     */
    ciphertext: string
  
    /**
     * The "encrypted_key" member MUST be present and contain the value
     * BASE64URL(JWE Encrypted Key) when the JWE Encrypted Key value is
     * non-empty; otherwise, it MUST be absent.
     */
    encrypted_key?: string
  
    /**
     * The "header" member MUST be present and contain the value JWE Per-
     * Recipient Unprotected Header when the JWE Per-Recipient
     * Unprotected Header value is non-empty; otherwise, it MUST be
     * absent.  This value is represented as an unencoded JSON object,
     * rather than as a string.  These Header Parameter values are not
     * integrity protected.
     */
    header?: DXEJWEHeaderParameters
  
    /**
     * The "iv" member MUST be present and contain the value
     * BASE64URL(JWE Initialization Vector) when the JWE Initialization
     * Vector value is non-empty; otherwise, it MUST be absent.
     */
    iv: string
  
    /**
     * The "protected" member MUST be present and contain the value
     * BASE64URL(UTF8(JWE Protected Header)) when the JWE Protected
     * Header value is non-empty; otherwise, it MUST be absent.  These
     * Header Parameter values are integrity protected.
     */
    protected?: string
  
    /**
     * The "tag" member MUST be present and contain the value
     * BASE64URL(JWE Authentication Tag) when the JWE Authentication Tag
     * value is non-empty; otherwise, it MUST be absent.
     */
    tag: string
  
    /**
     * The "unprotected" member MUST be present and contain the value JWE
     * Shared Unprotected Header when the JWE Shared Unprotected Header
     * value is non-empty; otherwise, it MUST be absent.  This value is
     * represented as an unencoded JSON object, rather than as a string.
     * These Header Parameter values are not integrity protected.
     */
    unprotected?: DXEJWEHeaderParameters
  }
  
  export interface DXEGeneralJWE extends Omit<DXEFlattenedJWE, 'encrypted_key' | 'header'> {
    recipients: Pick<DXEFlattenedJWE, 'encrypted_key' | 'header'>[]
  }
  
  /**
   * Recognized JWE Header Parameters, any other Header members
   * may also be present.
   */
  export interface DXEJWEHeaderParameters extends DXEJoseHeaderParameters {
    /**
     * JWE "alg" (Algorithm) Header Parameter.
     */
    alg?: string
  
    /**
     * JWE "enc" (Encryption Algorithm) Header Parameter.
     */
    enc?: string
  
    /**
     * JWE "crit" (Critical) Header Parameter.
     */
    crit?: string[]
  
    /**
     * JWE "zip" (Compression Algorithm) Header Parameter.
     */
    zip?: string
  
    /**
     * Any other JWE Header member.
     */
    [propName: string]: any
  }
  
  /**
   * Shared Interface with a "crit" property for all sign and verify operations.
   */
  export interface DXECritOption {
    /**
     * An object with keys representing recognized "crit" (Critical) Header Parameter
     * names. The value for those is either `true` or `false`. `true` when the
     * Header Parameter MUST be integrity protected, `false` when it's irrelevant.
     *
     * This makes the "Extension Header Parameter "${parameter}" is not recognized"
     * error go away.
     *
     * Use this when a given JWS/JWT/JWE profile requires the use of proprietary
     * non-registered "crit" (Critical) Header Parameters. This will only make sure
     * the Header Parameter is syntactically correct when provided and that it is
     * optionally integrity protected. It will not process the Header Parameter in
     * any way or reject if the operation if it is missing. You MUST still
     * verify the Header Parameter was present and process it according to the
     * profile's validation steps after the operation succeeds.
     *
     * The JWS extension Header Parameter `b64` is always recognized and processed
     * properly. No other registered Header Parameters that need this kind of
     * default built-in treatment are currently available.
     */
    crit?: {
      [propName: string]: boolean
    }
  }
  
  /**
   * JWE Decryption options.
   */
  export interface DXEDecryptOptions extends DXECritOption {
    /**
     * A list of accepted JWE "alg" (Algorithm) Header Parameter values.
     */
    keyManagementAlgorithms?: string[]
  
    /**
     * A list of accepted JWE "enc" (Encryption Algorithm) Header Parameter values.
     */
    contentEncryptionAlgorithms?: string[]
  
    /**
     * In a browser runtime you have to provide an implementation for Inflate Raw
     * when you expect JWEs with compressed plaintext.
     */
    inflateRaw?: DXEInflateFunction
  }
  
  /**
   * JWE Encryption options.
   */
  export interface DXEEncryptOptions extends DXECritOption {
    /**
     * In a browser runtime you have to provide an implementation for Deflate Raw
     * when you will be producing JWEs with compressed plaintext.
     */
    deflateRaw?: DXEDeflateFunction
  }
  
  /**
   * JWT Claims Set verification options.
   */
  export interface DXEJWTClaimVerificationOptions {
    /**
     * Expected JWT "aud" (Audience) Claim value(s).
     */
    audience?: string | string[]
  
    /**
     * Expected clock tolerance
     * - in seconds when number (e.g. 5)
     * - parsed as seconds when a string (e.g. "5 seconds").
     */
    clockTolerance?: string | number
  
    /**
     * Expected JWT "iss" (Issuer) Claim value(s).
     */
    issuer?: string | string[]
  
    /**
     * Maximum time elapsed (in seconds) from the JWT "iat" (Issued At) Claim value.
     */
    maxTokenAge?: string
  
    /**
     * Expected JWT "sub" (Subject) Claim value.
     */
    subject?: string
  
    /**
     * Expected JWT "typ" (Type) Header Parameter value.
     */
    typ?: string
  
    /**
     * Date to use when comparing NumericDate claims, defaults to `new Date()`.
     */
    currentDate?: Date
  }
  
  /**
   * JWS Verification options.
   */
  export interface DXEVerifyOptions extends DXECritOption {
    /**
     * A list of accepted JWS "alg" (Algorithm) Header Parameter values.
     */
    algorithms?: string[]
  }
  
  /**
   * JWS Signing options.
   */
  export interface DXESignOptions extends DXECritOption {}
  
  /**
   * Recognized JWT Claims Set members, any other members
   * may also be present.
   */
  export interface DXEJWTPayload {
    /**
     * JWT Issuer - [RFC7519#section-4.1.1](https://tools.ietf.org/html/rfc7519#section-4.1.1).
     */
    iss?: string
  
    /**
     * JWT Subject - [RFC7519#section-4.1.2](https://tools.ietf.org/html/rfc7519#section-4.1.2).
     */
    sub?: string
  
    /**
     * JWT Audience [RFC7519#section-4.1.3](https://tools.ietf.org/html/rfc7519#section-4.1.3).
     */
    aud?: string | string[]
  
    /**
     * JWT ID - [RFC7519#section-4.1.7](https://tools.ietf.org/html/rfc7519#section-4.1.7).
     */
    jti?: string
  
    /**
     * JWT Not Before - [RFC7519#section-4.1.5](https://tools.ietf.org/html/rfc7519#section-4.1.5).
     */
    nbf?: number
  
    /**
     * JWT Expiration Time - [RFC7519#section-4.1.4](https://tools.ietf.org/html/rfc7519#section-4.1.4).
     */
    exp?: number
  
    /**
     * JWT Issued At - [RFC7519#section-4.1.6](https://tools.ietf.org/html/rfc7519#section-4.1.6).
     */
    iat?: number
  
    /**
     * Any other JWT Claim Set member.
     */
    [propName: string]: any
  }
  
  /**
   * Deflate Raw implementation, e.g. promisified [zlib.deflateRaw](https://nodejs.org/api/zlib.html#zlib_zlib_deflateraw_buffer_options_callback).
   */
  export interface DXEDeflateFunction {
    (input: Uint8Array): Promise<Uint8Array>
  }
  
  /**
   * Inflate Raw implementation, e.g. promisified [zlib.inflateRaw](https://nodejs.org/api/zlib.html#zlib_zlib_inflateraw_buffer_options_callback).
   */
  export interface DXEInflateFunction {
    (input: Uint8Array): Promise<Uint8Array>
  }
  
  export interface DXEFlattenedDecryptResult {
    /**
     * JWE AAD.
     */
    additionalAuthenticatedData?: Uint8Array
  
    /**
     * Plaintext.
     */
    plaintext: Uint8Array
  
    /**
     * JWE Protected Header.
     */
    protectedHeader?: DXEJWEHeaderParameters
  
    /**
     * JWE Shared Unprotected Header.
     */
    sharedUnprotectedHeader?: DXEJWEHeaderParameters
  
    /**
     * JWE Per-Recipient Unprotected Header.
     */
    unprotectedHeader?: DXEJWEHeaderParameters
  }
  
  export interface DXEGeneralDecryptResult extends DXEFlattenedDecryptResult {}
  
  export interface DXECompactDecryptResult {
    /**
     * Plaintext.
     */
    plaintext: Uint8Array
  
    /**
     * JWE Protected Header.
     */
    protectedHeader: DXEJWEHeaderParameters
  }
  
  export interface DXEFlattenedVerifyResult {
    /**
     * JWS Payload.
     */
    payload: Uint8Array
  
    /**
     * JWS Protected Header.
     */
    protectedHeader?: DXEJWSHeaderParameters
  
    /**
     * JWS Unprotected Header.
     */
    unprotectedHeader?: DXEJWSHeaderParameters
  }
  
  export interface DXEGeneralVerifyResult extends DXEFlattenedVerifyResult {}
  
  export interface DXECompactVerifyResult {
    /**
     * JWS Payload.
     */
    payload: Uint8Array
  
    /**
     * JWS Protected Header.
     */
    protectedHeader: DXEJWSHeaderParameters
  }
  
  export interface DXEJWTVerifyResult {
    /**
     * JWT Claims Set.
     */
    payload: DXEJWTPayload
  
    /**
     * JWS Protected Header.
     */
    protectedHeader: DXEJWSHeaderParameters
  }
  
  export interface DXEJWTDecryptResult {
    /**
     * JWT Claims Set.
     */
    payload: DXEJWTPayload
  
    /**
     * JWE Protected Header.
     */
    protectedHeader: DXEJWEHeaderParameters
  }
  