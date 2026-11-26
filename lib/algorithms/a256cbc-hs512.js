/*!
 * AES_256_CBC_HMAC_SHA_512 content encryption, see:
 * https://www.rfc-editor.org/rfc/rfc7518#section-5.2.5
 */
import crypto from '../crypto.js';

export const JWE_ENC = 'A256CBC-HS512';

// the CEK is `MAC_KEY || ENC_KEY`, 32 bytes each
const KEY_BYTES = 64;
const IV_BYTES = 16;
// the tag is the HMAC-SHA-512 output truncated to its first 32 bytes
const TAG_BYTES = 32;

/**
 * Generates a content encryption key (CEK). The 512-bit key holds a 256-bit
 * HMAC-SHA-512 key followed by a 256-bit AES-CBC key.
 *
 * @returns {Promise<Uint8Array>} - Resolves to the generated key.
 */
export async function generateKey() {
  return crypto.getRandomValues(new Uint8Array(KEY_BYTES));
}

/**
 * Encrypts some data using the given 512-bit content encryption key (CEK).
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array} options.data - The data to encrypt.
 * @param {Uint8Array} [options.additionalData] - Optional additional
 *   authentication data.
 * @param {Uint8Array} options.cek - The content encryption key to use.
 *
 * @returns {Promise<object>} - A Promise that resolves to
 *   `{ciphertext, iv, tag}`.
 */
export async function encrypt({data, additionalData, cek}) {
  if(!(data instanceof Uint8Array)) {
    throw new TypeError('"data" must be a Uint8Array.');
  }
  const {encKey, macKey} = await _importCek({cek, usage: 'encrypt'});
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTES));
  // WebCrypto AES-CBC applies PKCS #7 padding
  const ciphertext = new Uint8Array(await crypto.subtle.encrypt(
    {name: 'AES-CBC', iv}, encKey, data));
  const tag = await _computeTag({macKey, additionalData, iv, ciphertext});
  return {ciphertext, iv, tag};
}

/**
 * Decrypts some encrypted data. The data must have been encrypted using
 * the given 512-bit content encryption key.
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array} options.ciphertext - The data to decrypt.
 * @param {Uint8Array} options.iv - The initialization vector.
 * @param {Uint8Array} options.tag - The authentication tag.
 * @param {Uint8Array} [options.additionalData] - Optional additional
 *   authentication data.
 * @param {Uint8Array} options.cek - The content encryption key to use.
 *
 * @returns {Promise<Uint8Array>} - The decrypted data or `null` if the
 *   authentication tag does not match.
 */
export async function decrypt({ciphertext, iv, tag, additionalData, cek}) {
  if(!(iv instanceof Uint8Array && iv.length === IV_BYTES)) {
    throw new Error('Invalid or missing "iv".');
  }
  if(!(ciphertext instanceof Uint8Array)) {
    throw new Error('Invalid or missing "ciphertext".');
  }
  if(!(tag instanceof Uint8Array)) {
    throw new Error('Invalid or missing "tag".');
  }
  const {encKey, macKey} = await _importCek({cek, usage: 'decrypt'});

  // authenticate before decrypting
  const expected = await _computeTag({macKey, additionalData, iv, ciphertext});
  if(!_constantTimeEqual(expected, tag)) {
    return null;
  }
  try {
    return new Uint8Array(await crypto.subtle.decrypt(
      {name: 'AES-CBC', iv}, encKey, ciphertext));
  } catch(e) {
    // invalid padding
    return null;
  }
}

async function _importCek({cek, usage}) {
  if(!(cek instanceof Uint8Array && cek.length === KEY_BYTES)) {
    throw new TypeError(`"cek" must be a ${KEY_BYTES} byte Uint8Array.`);
  }
  const half = KEY_BYTES / 2;
  const [macKey, encKey] = await Promise.all([
    crypto.subtle.importKey(
      'raw', cek.subarray(0, half), {name: 'HMAC', hash: 'SHA-512'}, false,
      ['sign']),
    crypto.subtle.importKey(
      'raw', cek.subarray(half), {name: 'AES-CBC'}, false, [usage])
  ]);
  return {encKey, macKey};
}

// tag = HMAC(MAC_KEY, AAD || IV || ciphertext || AL), truncated, where `AL`
// is the bit length of the AAD as a 64-bit big endian integer
async function _computeTag({
  macKey, additionalData = new Uint8Array(0), iv, ciphertext
}) {
  const input = new Uint8Array(
    additionalData.length + iv.length + ciphertext.length + 8);
  let offset = 0;
  input.set(additionalData, offset);
  input.set(iv, offset += additionalData.length);
  input.set(ciphertext, offset += iv.length);
  const dv = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const bits = additionalData.length * 8;
  dv.setUint32(offset += ciphertext.length, Math.floor(bits / 0x100000000));
  dv.setUint32(offset + 4, bits >>> 0);
  const mac = new Uint8Array(await crypto.subtle.sign('HMAC', macKey, input));
  return mac.slice(0, TAG_BYTES);
}

function _constantTimeEqual(a, b) {
  if(a.length !== b.length) {
    return false;
  }
  let diff = 0;
  for(let i = 0; i < a.length; ++i) {
    diff |= a[i] ^ b[i];
  }
  return diff === 0;
}
