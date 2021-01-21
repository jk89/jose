import * as crypto from 'crypto'
/*
if (crypto.webcrypto === undefined) {
  throw new Error('Node.js crypto.webcrypto is not available in your runtime')
}

*/

if (crypto.webcrypto) {
  process.emitWarning(
    'The implementation of Web Cryptography API in Node.js is experimental.',
    'ExperimentalWarning',
  )
}

export default crypto.webcrypto
export function ensureSecureContext() {}
