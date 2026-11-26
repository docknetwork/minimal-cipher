/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';

import * as fipsAlgorithm from './algorithms/fips.js';
import * as recAlgorithm from './algorithms/recommended.js';
import {stringToUint8Array} from './util.js';

// support `C20P` for backwards compatibility
import * as c20p from './algorithms/c20p.js';
// content encryption for `ECDH-1PU+A256KW` in the `draft-04` format
import * as a256cbcHs512 from './algorithms/a256cbc-hs512.js';

const CIPHER_ALGORITHMS = {
  [fipsAlgorithm.cipher.JWE_ENC]: fipsAlgorithm.cipher,
  [recAlgorithm.cipher.JWE_ENC]: recAlgorithm.cipher,
  [a256cbcHs512.JWE_ENC]: a256cbcHs512,
  // backwards compatibility for decryption only (*not* encryption)
  [c20p.JWE_ENC]: c20p
};

// only supported key algorithm
const KEY_ALGORITHM = 'ECDH-ES+A256KW';
const KEY_ALGORITHM_1PU = 'ECDH-1PU+A256KW';

export class DecryptTransformer {
  constructor({
    keyAgreement,
    keyAgreementKey,
    keyResolver,
    allowLegacySenderAuth = true
  } = {}) {
    if(!keyAgreement) {
      throw new TypeError('"keyAgreement" is a required parameter.');
    }
    if(!keyAgreementKey) {
      throw new TypeError('"keyAgreementKey" is a required parameter.');
    }
    this.keyAgreement = keyAgreement;
    this.keyAgreementKey = keyAgreementKey;
    this.keyResolver = keyResolver;
    this.allowLegacySenderAuth = allowLegacySenderAuth;
  }

  async transform(chunk, controller) {
    // assumes `chunk` is an object with a JWE under the `jwe` property
    if(!(chunk && typeof chunk === 'object')) {
      throw new TypeError('"chunk" must be an object.');
    }
    const {jwe} = chunk;

    const data = await this.decrypt(jwe);
    if(data === null) {
      const error = new Error('Invalid decryption key.');
      error.name = 'DataError';
      throw error;
    }

    controller.enqueue(data);
  }

  async decrypt(jwe) {
    // validate JWE
    if(!(jwe && typeof jwe === 'object')) {
      throw new TypeError('"jwe" must be an object.');
    }
    if(typeof jwe.protected !== 'string') {
      throw new TypeError('"jwe.protected" is missing or not a string.');
    }
    if(typeof jwe.iv !== 'string') {
      throw new Error('Invalid or missing "iv".');
    }
    if(typeof jwe.ciphertext !== 'string') {
      throw new Error('Invalid or missing "ciphertext".');
    }
    if(typeof jwe.tag !== 'string') {
      throw new Error('Invalid or missing "tag".');
    }

    // validate encryption header
    let header;
    let additionalData;
    try {
      // ASCII(BASE64URL(UTF8(JWE Protected Header)))
      additionalData = stringToUint8Array(jwe.protected);
      header = JSON.parse(new TextDecoder().decode(
        base64url.decode(jwe.protected)));
    } catch(e) {
      throw new Error('Invalid JWE "protected" header.');
    }
    // support older JWEs with alg set where enc would be
    if(!header.enc && typeof header.alg === 'string') {
      header = {enc: header.alg};
    }
    if(!(header.enc && typeof header.enc === 'string')) {
      throw new Error('Invalid JWE "enc" header.');
    }
    const cipher = CIPHER_ALGORITHMS[header.enc];
    if(!cipher) {
      throw new Error('Unsupported encryption algorithm "${header.enc}".');
    }
    if(!Array.isArray(jwe.recipients)) {
      throw new TypeError('"jwe.recipients" must be an array.');
    }

    // header parameters can be in the protected header, in the shared
    // unprotected header or in each recipient's header
    const {unprotected} = jwe;
    const sharedHeader = {
      ...(unprotected && typeof unprotected === 'object' ? unprotected : {}),
      ...header
    };

    // find `keyAgreementKey` matching recipient
    const {keyAgreementKey} = this;
    const recipient = _findRecipient(
      jwe.recipients, keyAgreementKey, sharedHeader);
    if(!recipient) {
      throw new Error('No matching recipient found for key agreement key.');
    }
    // get wrapped CEK
    const {encrypted_key: wrappedKey} = recipient;
    if(typeof wrappedKey !== 'string') {
      throw new Error('Invalid or missing "encrypted_key".');
    }

    // TODO: consider a cache of encrypted_key => CEKs to reduce unwrapping
    // calls which may even need to hit the network (e.g., Web KMS)

    // derive KEK and unwrap CEK
    const {epk, skid, alg, apu, apv} = {...recipient.header, ...sharedHeader};
    const {keyAgreement} = this;
    const tag = base64url.decode(jwe.tag);
    const kekOptions = {
      keyAgreementKey, epk, skid, alg, keyResolver: this.keyResolver
    };
    if(alg === KEY_ALGORITHM_1PU) {
      if(header.enc === a256cbcHs512.JWE_ENC) {
        // `draft-04` format: the KEK is bound to the authentication tag
        Object.assign(kekOptions, {apu, apv, tag});
      } else if(!this.allowLegacySenderAuth) {
        // the legacy format lets any recipient replace the content, and
        // ECDH-1PU key wrapping requires `A*CBC-HS*` content encryption
        throw new Error(
          `"${alg}" with "${header.enc}" content encryption is the legacy ` +
          'sender authentication format, which is not allowed.');
      }
    }

    const {kek} = await keyAgreement.kekFromEphemeralPeer(kekOptions);
    const cek = await kek.unwrapKey({wrappedKey});
    if(!cek) {
      // failed to unwrap key
      return null;
    }

    // decrypt content
    const {ciphertext, iv} = jwe;
    return cipher.decrypt({
      ciphertext: base64url.decode(ciphertext),
      iv: base64url.decode(iv),
      tag,
      additionalData,
      cek
    });
  }
}

function _findRecipient(recipients, key, sharedHeader) {
  return recipients.find(e => {
    if(!(e.header && e.header.kid === key.id) || key.algorithm) {
      return false;
    }
    // `alg` may be shared by all recipients
    const alg = sharedHeader.alg || e.header.alg;
    return alg === KEY_ALGORITHM_1PU || alg === KEY_ALGORITHM;
  });
}
