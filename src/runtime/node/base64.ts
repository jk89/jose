import { decoder } from '../../lib/buffer_utils.js'

export const encode64 = (input: Uint8Array | string) =>
  Buffer.from(input).toString('base64');

export const decode64 = (input: Uint8Array | string) => {
  let encoded = input
  if (encoded instanceof Uint8Array) {
    encoded = decoder.decode(encoded)
  }
  return new Uint8Array(Buffer.from(encoded, 'base64'))
}
