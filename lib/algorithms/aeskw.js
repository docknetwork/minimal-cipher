/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from '../crypto.js';
import * as base64url from 'base64url-universal';

class Kek {
  constructor(key) {
    this.key = key;
    this.algorithm = {name: 'A256KW'};
  }

  /**
   * Wraps a cryptographic key.
   *
   * @param {object} options - The options to use.
   * @param {Uint8Array} options.unwrappedKey - The key material as a
   *   `Uint8Array`.
   *
   * @returns {Promise<string>} - The base64url-encoded wrapped key bytes.
   */
  async wrapKey({unwrappedKey}) {
    const kek = this.key;
    // Note: `AES-GCM` algorithm name doesn't matter; will be exported raw.
    const extractable = true;
    const {algorithm, usages} = _wrappedKeyParams(unwrappedKey.length);

    unwrappedKey = await crypto.subtle.importKey(
      'raw', unwrappedKey, algorithm,
      // key usage refers to the key that is to be wrapped not the KEK itself;
      // we just treat it like an AES-GCM key (or an HMAC key if it is not
      // 256 bits) regardless of what it is
      extractable, usages);
    const wrappedKey = await crypto.subtle.wrapKey(
      'raw', unwrappedKey, kek, kek.algorithm);
    return base64url.encode(new Uint8Array(wrappedKey));
  }

  /**
   * Unwraps a cryptographic key.
   *
   * @param {object} options - The options to use.
   * @param {string} options.wrappedKey - The wrapped key material as a
   *   base64url-encoded string.
   *
   * @returns {Promise<Uint8Array>} - Resolves to the key bytes or null if
   *   the unwrapping fails because the key does not match.
   */
  async unwrapKey({wrappedKey}) {
    const kek = this.key;
    // Note: `AES-GCM` algorithm name doesn't matter; will be exported raw.
    wrappedKey = base64url.decode(wrappedKey);
    try {
      const extractable = true;
      // AES-KW adds 8 bytes to the key it wraps
      const {algorithm, usages} = _wrappedKeyParams(wrappedKey.length - 8);
      const key = await crypto.subtle.unwrapKey(
        'raw', wrappedKey, kek, kek.algorithm,
        // key usage refers to the key that is being unwrapped; we just treat
        // it like an AES-GCM key (or an HMAC key if it is not 256 bits)
        // regardless of what it is
        algorithm, extractable, usages);
      const keyBytes = await crypto.subtle.exportKey('raw', key);
      return new Uint8Array(keyBytes);
    } catch(e) {
      // unwrapping key failed
      return null;
    }
  }
}

// WebCrypto must be told what kind of key is wrapped; AES keys can not be
// longer than 256 bits, so longer keys (e.g. the 512-bit `A256CBC-HS512` CEK)
// are handled as HMAC keys, which can have any length
function _wrappedKeyParams(length) {
  if(length === 32) {
    return {algorithm: {name: 'AES-GCM', length: 256}, usages: ['encrypt']};
  }
  return {algorithm: {name: 'HMAC', hash: 'SHA-512'}, usages: ['sign']};
}

export async function createKek({keyData}) {
  const extractable = true;
  const key = await crypto.subtle.importKey(
    'raw', keyData, {name: 'AES-KW', length: 256}, extractable,
    ['wrapKey', 'unwrapKey']);
  return new Kek(key);
}
