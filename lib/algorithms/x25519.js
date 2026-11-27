/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import {createKek} from './aeskw.js';
import * as base58btc from 'base58-universal';
import {deriveKey} from './ecdhkdf.js';
import {deriveSecret, generateEphemeralKeyPair} from './x25519-helper.js';

const KEY_TYPE = 'X25519KeyAgreementKey2020';
// multibase base58-btc header
const MULTIBASE_BASE58BTC_HEADER = 'z';
// multicodec x25519-pub header as varint
export const MULTICODEC_X25519_PUB_HEADER = new Uint8Array([0xec, 0x01]);
// multicodec x25519-priv header as varint
export const MULTICODEC_X25519_PRIV_HEADER = new Uint8Array([0x82, 0x26]);
export const JWE_ALG = 'ECDH-ES+A256KW';
export const JWE_ALG_SENDER_AUTH = 'ECDH-1PU+A256KW';
export {generateEphemeralKeyPair, deriveSecret};

// Decryption case: get Kek from a private key agreement key and a
// peer's public ephemeral DH key encoded as an `epk`
//
// For `ECDH-1PU+A256KW`, passing the JWE authentication `tag` selects the
// draft-madden-jose-ecdh-1pu-04 derivation: `Z = Ze || Zs`, the `apu` and
// `apv` header values as party info and the tag bound into the KEK. Without
// a `tag` the derivation published in 5.2.1 is used, which hashes `Ze` and
// `Zs` separately and does not bind the content to the wrapped key.
export async function kekFromEphemeralPeer({
  keyAgreementKey, epk, skid, alg, keyResolver, apu, apv, tag
}) {
  const isSenderAuthAlg = alg === JWE_ALG_SENDER_AUTH;
  const isTagBound = isSenderAuthAlg && tag !== undefined;
  if(!(epk && typeof epk === 'object')) {
    throw new TypeError('"epk" must be an object.');
  }
  if(epk.kty !== 'OKP') {
    throw new Error('"epk.kty" must be the string "OKP".');
  }
  if(epk.crv !== 'X25519') {
    throw new Error('"epk.crv" must be the string "X25519".');
  }
  if(isSenderAuthAlg && !keyResolver) {
    throw new Error(`${alg} requires keyResolver argument for sender key.`);
  }
  if(isSenderAuthAlg && typeof skid !== 'string') {
    throw new Error(`${alg} requires a "skid" header with the sender key ID.`);
  }
  // decode public key material
  const publicKey = base64url.decode(epk.x);

  // convert to LD key for Web KMS
  const ephemeralPublicKey = {
    type: KEY_TYPE,
    publicKeyMultibase:
      multibaseEncode(MULTICODEC_X25519_PUB_HEADER, publicKey)
  };

  // safe to use IDs like in rfc7518 or does
  // https://tools.ietf.org/html/rfc7748#section-7 pose any issues?
  const encoder = new TextEncoder();
  let producerInfo;
  let consumerInfo;
  if(isTagBound) {
    // party info is whatever the sender put in the header, possibly nothing
    producerInfo = _decodePartyInfo(apu, 'apu');
    consumerInfo = _decodePartyInfo(apv, 'apv');
  } else {
    // "Party U Info"
    producerInfo = isSenderAuthAlg ? encoder.encode(skid) : publicKey;
    // "Party V Info"
    consumerInfo = encoder.encode(keyAgreementKey.id);
  }

  let secret;
  if(isSenderAuthAlg) {
    // resolve the sender did and convert to LD key for Web KMS
    const senderKeyInfo = await keyResolver({id: skid});
    const senderPublicKey = {
      type: KEY_TYPE,
      publicKeyMultibase: senderKeyInfo.publicKeyMultibase
    };

    const Ze = await keyAgreementKey.deriveSecret(
      {publicKey: ephemeralPublicKey});

    const Zs = await keyAgreementKey.deriveSecret(
      {publicKey: senderPublicKey});

    if(isTagBound) {
      secret = _concat(Ze, Zs);
    } else {
      const ZeHashed = await deriveKey({secret: Ze});
      const ZsHashed = await deriveKey({secret: Zs});
      secret = _concat(ZeHashed, ZsHashed);
    }
  } else {
    secret = await keyAgreementKey.deriveSecret(
      {publicKey: ephemeralPublicKey});
  }

  const keyData = await deriveKey({
    alg, secret, producerInfo, consumerInfo, tag: isTagBound ? tag : undefined
  });
  return {
    kek: await createKek({keyData})
  };
}

/**
 * (Encryption case, draft-madden-jose-ecdh-1pu-04) Computes the ECDH-1PU
 * shared secret `Z = Ze || Zs` between the sender and one recipient. The KEK
 * can only be derived from it once the content has been encrypted, see
 * `kekFromSenderAuthSecret`.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.ephemeralKeyPair - Ephemeral key pair.
 * @param {object} options.staticPublicKey - The recipient's static public key.
 * @param {object} options.keyAgreementKey - The sender's key agreement key
 *   API with `id` and `deriveSecret`.
 *
 * @returns {Promise<Uint8Array>} - Resolves to the shared secret.
 */
export async function senderAuthSecretFromStaticPeer({
  ephemeralKeyPair, staticPublicKey, keyAgreementKey
}) {
  if(!staticPublicKey) {
    throw new Error('"staticPublicKey" is required.');
  }
  if(staticPublicKey.type !== KEY_TYPE) {
    throw new Error(
      `"staticPublicKey.type" must be "${KEY_TYPE}".`);
  }
  if(!keyAgreementKey) {
    throw new Error(
      `${JWE_ALG_SENDER_AUTH} requires keyAgreementKey for sender ` +
      'authentication');
  }
  const {privateKey} = ephemeralKeyPair;
  const remotePublicKey = multibaseDecode(
    MULTICODEC_X25519_PUB_HEADER, staticPublicKey.publicKeyMultibase);
  const Ze = await deriveSecret({privateKey, remotePublicKey});
  const Zs = await keyAgreementKey.deriveSecret({publicKey: staticPublicKey});
  return _concat(Ze, Zs);
}

/**
 * (Encryption case, draft-madden-jose-ecdh-1pu-04) Derives the KEK for one
 * recipient from the ECDH-1PU shared secret and the authentication tag of
 * the encrypted content. Binding the tag stops a recipient from reusing
 * another recipient's wrapped key for different content.
 *
 * @param {object} options - Options hashmap.
 * @param {Uint8Array} options.secret - The shared secret `Z = Ze || Zs`.
 * @param {Uint8Array} options.producerInfo - The decoded `apu` header value.
 * @param {Uint8Array} options.consumerInfo - The decoded `apv` header value.
 * @param {Uint8Array} options.tag - The JWE authentication tag.
 *
 * @returns {Promise<object>} - Resolves to the KEK.
 */
export async function kekFromSenderAuthSecret({
  secret, producerInfo, consumerInfo, tag
}) {
  if(!(tag instanceof Uint8Array && tag.length > 0)) {
    throw new TypeError('"tag" must be a non-empty Uint8Array.');
  }
  const keyData = await deriveKey(
    {alg: JWE_ALG_SENDER_AUTH, secret, producerInfo, consumerInfo, tag});
  return createKek({keyData});
}

/**
 * (Encryption case) Generates KEK from ephemeral DH private key and a peer's
 * public static key.
 *
 * @param {object} options - Options hashmap.
 * @param {object} options.ephemeralKeyPair - Ephemeral key pair.
 * @param {object} options.staticPublicKey - Static public key.
 * @param {object} [options.keyAgreementKey] - The sender's key agreement key
 *   API; required when `alg` is `ECDH-1PU+A256KW`.
 * @param {string} options.alg - The key wrapping algorithm.
 * @typedef {{
 *   kek: (object), epk: *, apv: (*|string), apu: (*|string), ephemeralPublicKey
 * }} kekObject
 *
 * @returns {Promise<kekObject>} - Resolves with kek object derived from static
 *   peer.
 */
export async function kekFromStaticPeer({
  ephemeralKeyPair, staticPublicKey, keyAgreementKey, alg
}) {
  if(!staticPublicKey) {
    throw new Error('"staticPublicKey" is required.');
  }
  const {privateKey} = ephemeralKeyPair;
  // TODO: consider accepting JWK format for `staticPublicKey` not just LD key
  if(staticPublicKey.type !== KEY_TYPE) {
    throw new Error(
      `"staticPublicKey.type" must be "${KEY_TYPE}".`);
  }

  const isSenderAuthAlg = alg === JWE_ALG_SENDER_AUTH;
  if(isSenderAuthAlg) {
    if(!keyAgreementKey) {
      throw new Error(
        `${alg} requires keyAgreementKey for sender authentication`
      );
    }
  }

  const remotePublicKey = multibaseDecode(
    MULTICODEC_X25519_PUB_HEADER, staticPublicKey.publicKeyMultibase);

  const encoder = new TextEncoder();
  // "Party U Info"
  const producerInfo = isSenderAuthAlg ?
    encoder.encode(keyAgreementKey.id) : ephemeralKeyPair.publicKey;
  // "Party V Info"
  const consumerInfo = encoder.encode(staticPublicKey.id);

  let secret;
  if(isSenderAuthAlg) {
    const Ze = await deriveSecret({privateKey, remotePublicKey});
    const Zs = await keyAgreementKey.deriveSecret(
      {publicKey: staticPublicKey});
    const ZeHashed = await deriveKey({secret: Ze});
    const ZsHashed = await deriveKey({secret: Zs});
    secret = _concat(ZeHashed, ZsHashed);
  } else {
    secret = await deriveSecret({privateKey, remotePublicKey});
  }

  const keyData = await deriveKey({alg, secret, producerInfo, consumerInfo});
  return {
    kek: await createKek({keyData}),
    epk: ephemeralKeyPair.epk,
    apu: base64url.encode(producerInfo),
    apv: base64url.encode(consumerInfo),
    ephemeralPublicKey: ephemeralKeyPair.publicKey
  };
}

/**
 * Adds a multicodec prefix to a given bytes array representing a public
 * or private key, and multibase-encodes the result.
 *
 * @param {Uint8Array} header - Multicodec x25519 pub or pri key header, varint.
 * @param {Uint8Array} bytes - Byte array representing a public or private key.
 *
 * @returns {string} Base58-btc encoded key (with multicodec prefix).
 */
export function multibaseEncode(header, bytes) {
  const mcBytes = new Uint8Array(header.length + bytes.length);
  mcBytes.set(header);
  mcBytes.set(bytes, header.length);
  return MULTIBASE_BASE58BTC_HEADER + base58btc.encode(mcBytes);
}

/**
 * Decodes a given string as a multibase-encoded multicodec value.
 *
 * @param {Uint8Array} header - Expected header bytes for the multicodec value.
 * @param {string} text - Multibase encoded string to decode.
 *
 * @returns {Uint8Array} Decoded bytes.
 */
export function multibaseDecode(header, text) {
  const mcValue = base58btc.decode(text.substr(1));

  if(!header.every((val, i) => mcValue[i] === val)) {
    throw new Error('Multibase value does not have expected header.');
  }

  return mcValue.slice(header.length);
}

function _decodePartyInfo(value, name) {
  if(value === undefined) {
    return new Uint8Array(0);
  }
  if(typeof value !== 'string') {
    throw new TypeError(`"${name}" must be a string.`);
  }
  return base64url.decode(value);
}

// `Buffer` is not available in browsers, so concatenate with `Uint8Array`
function _concat(a, b) {
  const out = new Uint8Array(a.length + b.length);
  out.set(a);
  out.set(b, a.length);
  return out;
}
