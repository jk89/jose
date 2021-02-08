/* eslint-disable prefer-destructuring */

import * as base64 from '../runtime/base64.js'

/**
 * Utility function to encode a string or Uint8Array as a base64 string.
 *
 * @param input Value that will be base64-encoded.
 */
interface Base64Encode {
  (input: Uint8Array | string): string
}
/**
 * Utility function to decode a base64 encoded string.
 *
 * @param input Value that will be base64-decoded.
 */
interface Base64Decode {
  (input: Uint8Array | string): Uint8Array
}

export const encode64: Base64Encode = base64.encode64
export const decode64: Base64Decode = base64.decode64
