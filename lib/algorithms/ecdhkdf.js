/*!
 * Copyright (c) 2019-2020 Digital Bazaar, Inc. All rights reserved.
 */
import crypto from '../crypto.js';

// RFC 7518 Section 4.6.2 specifies using SHA-256 for ECDH-ES KDF
// https://tools.ietf.org/html/rfc7518#section-4.6.2
const HASH_ALGORITHM = {name: 'SHA-256'};

// derived keys are always 256-bits
const KEY_LENGTH = 256;

/**
 * Derives a 256-bit AES-KW key encryption key from a shared secret that
 * was derived from an ephemeral and static pair
 * of Elliptic Curve Diffie-Hellman keys.
 *
 * The KDF used is described in RFC 7518. This KDF is referenced by RFC 8037,
 * which defines how to perform Curve25519 (X25519) ECDH key agreement.
 *
 * @param {object} options - The options to use.
 * @param {Uint8Array} options.secret - The shared secret (i.e., `Z`) to use.
 * @param {Uint8Array} options.producerInfo - An array of application-specific
 *   bytes describing the consumer (aka the "encrypter" or "sender").
 * @param {Uint8Array} options.consumerInfo - An array of application-specific
 *   bytes describing the producer (aka the "decrypter" or
 *   "receiver"/"recipient").
 * @param {string} options.alg - The algorithm name, such as ECDH-ES+256KW.
 * @param {Uint8Array} [options.tag] - The JWE authentication tag. When given,
 *   it is bound into the derived key as the `cctag` of ECDH-1PU key wrapping
 *   (draft-madden-jose-ecdh-1pu-04, section 2.3), and `producerInfo` and
 *   `consumerInfo` may be empty.
 * @param {number} [options.keyLength=256] - The length, in bits, of the key
 *   to derive; at most 256.
 *
 * @returns {Promise<Uint8Array>} - Resolves to the generated key.
 */
export async function deriveKey({
  secret, producerInfo, consumerInfo, alg, tag, keyLength = KEY_LENGTH
}) {
  if(!(secret instanceof Uint8Array && secret.length > 0)) {
    throw new TypeError('"secret" must be a non-empty Uint8Array.');
  }
  if(!(Number.isInteger(keyLength) && keyLength > 0 &&
    keyLength <= KEY_LENGTH && keyLength % 8 === 0)) {
    throw new TypeError(
      `"keyLength" must be a multiple of 8 no greater than ${KEY_LENGTH}.`);
  }

  // no extra info supplied, just hash the secret
  if(!producerInfo && !consumerInfo && tag === undefined) {
    // hash input and return result as derived key
    return new Uint8Array(
      await crypto.subtle.digest(HASH_ALGORITHM, secret));
  }

  // party info may be empty only when a tag is bound into the key
  const minLength = tag === undefined ? 1 : 0;
  if(!(producerInfo instanceof Uint8Array &&
    producerInfo.length >= minLength)) {
    throw new TypeError('"producerInfo" must be a non-empty Uint8Array.');
  }
  if(!(consumerInfo instanceof Uint8Array &&
    consumerInfo.length >= minLength)) {
    throw new TypeError('"consumerInfo" must be a non-empty Uint8Array.');
  }
  if(tag !== undefined && !(tag instanceof Uint8Array && tag.length > 0)) {
    throw new TypeError('"tag" must be a non-empty Uint8Array.');
  }

  // create algorithmID encoded buffer
  const algorithmContent = new TextEncoder().encode(alg);
  const algorithmID = new Uint8Array(4 + algorithmContent.length);
  // write length of content as 32-bit big endian integer, then write content
  const algoDV = new DataView(
    algorithmID.buffer,
    algorithmID.byteOffset,
    algorithmID.byteLength);
  algoDV.setUint32(0, algorithmContent.length);
  algorithmID.set(algorithmContent, 4);

  // the output of Concat KDF is hash(roundNumber || Z || OtherInfo)
  // where roundNumber is always 1 because the hash length is presumed to
  // ...match the key length, encoded as a big endian 32-bit integer
  // where OtherInfo is:
  // AlgorithmID || PartyUInfo || PartyVInfo || SuppPubInfo
  // where SuppPubInfo is the key length in bits, big endian encoded as a
  // 32-bit number, i.e., 256 === [0, 0, 1, 0], followed by the `cctag` when a
  // tag is given: the tag length in bytes as a 32-bit number, then the tag
  const input = new Uint8Array(
    4 + // round number
    secret.length + // `Z`
    algorithmID.length + // AlgorithmID
    4 + producerInfo.length + // PartyUInfo
    4 + consumerInfo.length + // PartyVInfo
    4 + // SuppPubInfo (key data length in bits)
    (tag ? 4 + tag.length : 0)); // SuppPubInfo (cctag)

  let offset = 0;
  const dv = new DataView(input.buffer, input.byteOffset, input.byteLength);
  dv.setUint32(offset, 1);
  input.set(secret, offset += 4);
  input.set(algorithmID, offset += secret.length);
  dv.setUint32(offset += algorithmID.length, producerInfo.length);
  input.set(producerInfo, offset += 4);
  dv.setUint32(offset += producerInfo.length, consumerInfo.length);
  input.set(consumerInfo, offset += 4);
  dv.setUint32(offset += consumerInfo.length, keyLength);
  if(tag) {
    dv.setUint32(offset += 4, tag.length);
    input.set(tag, offset += 4);
  }

  // hash input and return the leading `keyLength` bits as derived key
  const hash = new Uint8Array(
    await crypto.subtle.digest(HASH_ALGORITHM, input));
  return keyLength === KEY_LENGTH ? hash : hash.slice(0, keyLength / 8);
}
