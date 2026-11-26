/*!
 * Copyright (c) 2019-2022 Digital Bazaar, Inc. All rights reserved.
 */
import * as base64url from 'base64url-universal';
import * as fipsAlgorithm from './algorithms/fips.js';
import * as recAlgorithm from './algorithms/recommended.js';
import * as senderAuthCipher from './algorithms/a256cbc-hs512.js';
import crypto from './crypto.js';
import {DecryptTransformer} from './DecryptTransformer.js';
import {EncryptTransformer} from './EncryptTransformer.js';
import {stringToUint8Array} from './util.js';

const VERSIONS = ['recommended', 'fips'];
// wire formats for `ECDH-1PU+A256KW` (sender authenticated) recipients
const SENDER_AUTH_FORMATS = ['legacy', 'draft-04'];

export class Cipher {
  /**
   * Creates a new Cipher instance that can be used to encrypt or decrypt
   * data. A version must be supplied for encrypting data; the version
   * indicates whether a FIPS-compliant algorithm or the latest recommended
   * algorithm will be used.
   *
   * @param {object} [options] - The options to use.
   * @param {string} [options.version='recommended'] - `fips` to use a
   *   FIPS-compliant algorithm, `recommended` to use the latest recommended
   *   algorithm when encrypting.
   * @param {string} [options.senderAuthFormat='legacy'] - The format used
   *   when encrypting for `ECDH-1PU+A256KW` recipients. `legacy` is the
   *   format of version 5.2.1; with more than one recipient it does not stop
   *   a recipient from forging a message from the sender to the others, and
   *   it does not interoperate with other ECDH-1PU implementations.
   *   `draft-04` follows draft-madden-jose-ecdh-1pu-04: it always uses
   *   `A256CBC-HS512` content encryption and binds the content to each
   *   wrapped key, but versions before 6.0.0 can not decrypt it.
   * @param {boolean} [options.allowLegacySenderAuth=true] - Whether to
   *   decrypt `ECDH-1PU+A256KW` JWEs in the `legacy` format. Set to `false`
   *   once all senders use `draft-04`.
   *
   * @returns {Cipher} A Cipher used to encrypt and decrypt data.
   */
  constructor({
    version = 'recommended', senderAuthFormat = 'legacy',
    allowLegacySenderAuth = true
  } = {}) {
    if(typeof version !== 'string') {
      throw new TypeError('"version" must be a string.');
    }
    if(!VERSIONS.includes(version)) {
      throw new Error(`Unsupported version "${version}".`);
    }
    if(!SENDER_AUTH_FORMATS.includes(senderAuthFormat)) {
      throw new Error(`Unsupported senderAuthFormat "${senderAuthFormat}".`);
    }
    if(typeof allowLegacySenderAuth !== 'boolean') {
      throw new TypeError('"allowLegacySenderAuth" must be a boolean.');
    }
    this.version = version;
    this.senderAuthFormat = senderAuthFormat;
    this.allowLegacySenderAuth = allowLegacySenderAuth;
    if(version === 'fips') {
      this.cipher = fipsAlgorithm.cipher;
      this.keyAgreement = fipsAlgorithm.keyAgreement;
    } else {
      this.cipher = recAlgorithm.cipher;
      this.keyAgreement = recAlgorithm.keyAgreement;
    }
  }

  /**
   * Creates a TransformStream that will encrypt some data for one or more
   * recipients and output a stream of chunks, each containing an object
   * with the property `jwe` with a JWE value.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - The options for the stream.
   * @param {Array} options.recipients - An array of recipients for the
   *   encrypted content.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @param {number} [options.chunkSize=1048576] - The size, in bytes,
   *   of the chunks to break the incoming data into.
   * @param {object} [options.keyAgreementKey] - The sender's key agreement
   *   key API with `id` and `deriveSecret`; required for any recipient that
   *   uses `ECDH-1PU+A256KW`.
   *
   * @returns {Promise<TransformStream>} Resolves to a TransformStream.
   */
  async createEncryptStream({
    recipients, keyResolver, chunkSize, keyAgreementKey
  }) {
    const transformer = await this.createEncryptTransformer(
      {recipients, keyResolver, chunkSize, keyAgreementKey});
    // eslint-disable-next-line no-undef
    return new TransformStream(transformer);
  }

  /**
   * Creates a TransformStream that will decrypt one or more chunks, each one
   * that is an object with a `jwe` property that has a JWE as a value. The
   * stream will output chunks of Uint8Arrays consisting of the decrypted
   * data from each chunk.
   *
   * The only JWEs currently supported use an `alg` of `ECDH-ES+A256KW` and
   * `enc` of `A256GCM` or `XC20P`. These parameters refer to data that has been
   * encrypted using a 256-bit AES-GCM or XChaCha20Poly1305 content encryption
   * key (CEK) that has been wrapped using a 256-bit AES-KW key encryption key
   * (KEK) generated via a shared secret between an ephemeral ECDH key and a
   * static ECDH key (ECDH-ES).
   *
   * @param {object} options - Options for createDecryptStream.
   * @param {object} options.keyAgreementKey - A key agreement key API with
   *   `id` and deriveSecret`.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @returns {Promise<TransformStream>} Resolves to the TransformStream.
   */
  async createDecryptStream({keyAgreementKey, keyResolver}) {
    const transformer = await this.createDecryptTransformer(
      {keyAgreementKey, keyResolver});
    // eslint-disable-next-line no-undef
    return new TransformStream(transformer);
  }

  /**
   * Encrypts some data for one or more recipients and outputs a JWE. The
   * data to encrypt can be given as a Uint8Array or a string.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - Options for encrypt.
   * @param {Uint8Array|string} [options.data] - The data to encrypt.
   * @param {Array} options.recipients - An array of recipients for the\
   *   encrypted content.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @param {object} [options.keyAgreementKey] - The sender's key agreement
   *   key API with `id` and `deriveSecret`; required for any recipient that
   *   uses `ECDH-1PU+A256KW`.
   * @returns {Promise<object>} Resolves to a JWE.
   */
  async encrypt({data, recipients, keyResolver, keyAgreementKey}) {
    if(!(data instanceof Uint8Array) && typeof data !== 'string') {
      throw new TypeError('"data" must be a Uint8Array or a string.');
    }
    if(data) {
      data = stringToUint8Array(data);
    }
    const transformer = await this.createEncryptTransformer(
      {recipients, keyResolver, keyAgreementKey});
    return transformer.encrypt(data);
  }

  /**
   * Encrypts an object. The object will be serialized to JSON and passed
   * to `encrypt`. See `encrypt` for other parameters.
   *
   * @param {object} options - Options to use.
   * @param {object} options.obj - The object to encrypt.
   * @param {object} options.rest - The other options to be passed to encrypt.
   *
   * @returns {Promise<object>} Resolves to a JWE.
   */
  async encryptObject({obj, ...rest}) {
    if(typeof obj !== 'object') {
      throw new TypeError('"obj" must be an object.');
    }
    return this.encrypt({data: JSON.stringify(obj), ...rest});
  }

  /**
   * Decrypts a single JWE.
   *
   * The only JWEs currently supported use an `alg` of `ECDH-ES+A256KW` and
   * `enc` of `A256GCM` or `XC20P`. These parameters refer to data that has been
   * encrypted using a 256-bit AES-GCM or XChaCha20Poly1305 content encryption
   * key (CEK) that has been wrapped using a 256-bit AES-KW key encryption key
   * (KEK) generated via a shared secret between an ephemeral ECDH key and a
   * static ECDH key (ECDH-ES).
   *
   * Note: This version also supports decrypting data that was encrypted using
   * `C20P` (ChaCha20Poly1305) for backwards compatibility.
   *
   * @param {object} options - Options for decrypt.
   * @param {object} options.jwe - The JWE to decrypt.
   * @param {object} options.keyAgreementKey - A key agreement key API with
   *   `id` and `deriveSecret`.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @returns {Promise<Uint8Array>} - Resolves to the decrypted data
   *   or `null` if the decryption failed.
   */
  async decrypt({jwe, keyAgreementKey, keyResolver}) {
    const transformer = await this.createDecryptTransformer(
      {keyAgreementKey, keyResolver});
    return transformer.decrypt(jwe);
  }

  /**
   * Decrypts a JWE that must contain an encrypted object. This method will
   * call `decrypt` and then `JSON.parse` the resulting decrypted UTF-8 data.
   *
   * @param {object} options - Options.
   * @param {object} options.jwe - The JWE to decrypt.
   * @param {object} options.keyAgreementKey - A key agreement key API with
   *   `id` and `deriveSecret`.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @returns {Promise<object>} - Resolves to the decrypted object or `null`
   *   if the decryption failed.
   */
  async decryptObject({jwe, keyAgreementKey, keyResolver}) {
    const data = await this.decrypt({jwe, keyAgreementKey, keyResolver});
    if(!data) {
      // decryption failed
      return null;
    }
    return JSON.parse(new TextDecoder().decode(data));
  }

  /**
   * Creates an EncryptTransformer that can be used to encrypt one or more
   * chunks of data.
   *
   * A list of recipients must be given in the `recipients` array, identified
   * by key agreement keys. An ephemeral ECDH key will be generated and used to
   * derive shared KEKs that will wrap a randomly generated CEK. Each recipient
   * in the `recipients` array will be updated to include the generated
   * ephemeral ECDH key.
   *
   * @param {object} options - Options for the transformer.
   * @param {Array} options.recipients - An array of recipients for the
   *   encrypted content.
   * @param {Function} options.keyResolver - A function that returns
   *   a Promise that resolves a key ID to a DH public key.
   * @param {number} [options.chunkSize=1048576] - The size, in bytes, of the
   *   chunks to break the incoming data into (only applies if returning a
   *   stream).
   * @param {object} [options.keyAgreementKey] - The sender's key agreement
   *   key API with `id` and `deriveSecret`; required for any recipient that
   *   uses `ECDH-1PU+A256KW`.
   *
   * @returns {Promise<EncryptTransformer>} - Resolves to an EncryptTransformer.
   */
  async createEncryptTransformer({
    recipients, keyResolver, chunkSize, keyAgreementKey
  }) {
    if(!(Array.isArray(recipients) && recipients.length > 0)) {
      throw new TypeError('"recipients" must be a non-empty array.');
    }
    // ensure all recipients use the supported key agreement algorithm
    const {keyAgreement} = this;
    const {JWE_ALG: alg, JWE_ALG_SENDER_AUTH: algSenderAuth} = keyAgreement;
    if(!recipients.every(e => e.header &&
      (e.header.alg === alg || e.header.alg === algSenderAuth))) {
      throw new Error(
        `All recipients must use the algorithm "${alg}" or "${algSenderAuth}".`
      );
    }
    if(this.senderAuthFormat === 'draft-04' &&
      recipients.some(e => e.header.alg === algSenderAuth)) {
      return this._createSenderAuthEncryptTransformer(
        {recipients, keyResolver, chunkSize, keyAgreementKey});
    }
    const {cipher} = this;

    // generate a CEK for encrypting the content
    const cek = await cipher.generateKey();

    // derive ephemeral ECDH key pair to use with all recipients
    const ephemeralKeyPair = await keyAgreement.generateEphemeralKeyPair();

    recipients = await Promise.all(recipients.map(
      recipient => this._createRecipient(
        {recipient, cek, ephemeralKeyPair, keyResolver, keyAgreementKey})));

    // create shared protected header as associated authenticated data (aad)
    // ASCII(BASE64URL(UTF8(JWE Protected Header)))
    const enc = cipher.JWE_ENC;
    const jweProtectedHeader = JSON.stringify({enc});
    const encodedProtectedHeader =
      base64url.encode(stringToUint8Array(jweProtectedHeader));
    // UTF8-encoding a base64url-encoded string is the same as ASCII
    const additionalData = stringToUint8Array(encodedProtectedHeader);

    return new EncryptTransformer({
      recipients,
      encodedProtectedHeader,
      cipher,
      additionalData,
      cek,
      chunkSize
    });
  }

  /**
   * Creates a DecryptTransformer.
   *
   * @param {object} options - Options to use.
   * @param {object} options.keyAgreementKey - A key agreement key API with
   *   `id` and `deriveSecret`.
   * @param {Function} options.keyResolver - A function that returns a Promise
   *   that resolves a key ID to a DH public key.
   * @returns {Promise<DecryptTransformer>} - Resolves to a DecryptTransformer.
   */
  async createDecryptTransformer({keyAgreementKey, keyResolver}) {
    return new DecryptTransformer({
      keyAgreement: this.keyAgreement,
      keyAgreementKey,
      keyResolver,
      allowLegacySenderAuth: this.allowLegacySenderAuth
    });
  }

  /**
   * Creates an EncryptTransformer for `ECDH-1PU+A256KW` recipients in the
   * `draft-04` format (draft-madden-jose-ecdh-1pu-04, key agreement with key
   * wrapping).
   *
   * The key agreement parameters go in the protected header, so they are
   * authenticated together with the content, and the CEK is wrapped only
   * after the content is encrypted because each KEK is derived from the
   * resulting authentication tag.
   *
   * @param {object} options - Options for the transformer.
   * @param {Array} options.recipients - An array of recipients for the
   *   encrypted content.
   * @param {Function} options.keyResolver - A function that returns
   *   a Promise that resolves a key ID to a DH public key.
   * @param {number} [options.chunkSize] - The size, in bytes, of the chunks
   *   to break the incoming data into.
   * @param {object} options.keyAgreementKey - The sender's key agreement key
   *   API with `id` and `deriveSecret`.
   *
   * @returns {Promise<EncryptTransformer>} - Resolves to an EncryptTransformer.
   */
  async _createSenderAuthEncryptTransformer({
    recipients, keyResolver, chunkSize, keyAgreementKey
  }) {
    const {keyAgreement} = this;
    const alg = keyAgreement.JWE_ALG_SENDER_AUTH;
    // the protected header holds a single `alg` and sender for everyone
    if(!recipients.every(e => e.header.alg === alg)) {
      throw new Error(
        `All recipients must use the algorithm "${alg}" when one of them ` +
        'does and "senderAuthFormat" is "draft-04".');
    }
    if(!keyAgreementKey) {
      throw new Error(
        `${alg} requires keyAgreementKey for sender authentication`);
    }
    if(!keyResolver) {
      throw new TypeError('"options.keyResolver" is required.');
    }

    // ECDH-1PU key wrapping is only safe with a content encryption algorithm
    // where a tag commits to the key, which `XC20P` and `A256GCM` do not
    const cipher = senderAuthCipher;
    const cek = await cipher.generateKey();
    const ephemeralKeyPair = await keyAgreement.generateEphemeralKeyPair();

    // the secrets do not depend on the content; compute them only once
    const secrets = await Promise.all(recipients.map(async recipient => {
      const staticPublicKey = await keyResolver({id: recipient.header.kid});
      const secret = await keyAgreement.senderAuthSecretFromStaticPeer(
        {ephemeralKeyPair, staticPublicKey, keyAgreementKey});
      // `alg` moves to the protected header; a header parameter must not
      // appear in more than one place
      // eslint-disable-next-line no-unused-vars
      const {alg, ...header} = recipient.header;
      return {recipient: {...recipient, header}, secret};
    }));

    // party info as used by DIDComm v2: the sender key ID and the hash of
    // the sorted recipient key IDs
    const skid = keyAgreementKey.id;
    const producerInfo = stringToUint8Array(skid);
    const kids = recipients.map(e => e.header.kid).sort().join('.');
    const consumerInfo = new Uint8Array(await crypto.subtle.digest(
      {name: 'SHA-256'}, stringToUint8Array(kids)));

    const jweProtectedHeader = JSON.stringify({
      alg,
      enc: cipher.JWE_ENC,
      skid,
      apu: base64url.encode(producerInfo),
      apv: base64url.encode(consumerInfo),
      epk: ephemeralKeyPair.epk
    });
    const encodedProtectedHeader =
      base64url.encode(stringToUint8Array(jweProtectedHeader));
    // UTF8-encoding a base64url-encoded string is the same as ASCII
    const additionalData = stringToUint8Array(encodedProtectedHeader);

    const createRecipients = async ({tag}) => Promise.all(secrets.map(
      async ({recipient, secret}) => {
        const kek = await keyAgreement.kekFromSenderAuthSecret(
          {secret, producerInfo, consumerInfo, tag});
        return {
          ...recipient,
          encrypted_key: await kek.wrapKey({unwrappedKey: cek})
        };
      }));

    return new EncryptTransformer({
      createRecipients,
      encodedProtectedHeader,
      cipher,
      additionalData,
      cek,
      chunkSize
    });
  }

  /**
   * Creates a JWE recipient using the given inputs.
   *
   * @see https://tools.ietf.org/html/rfc7516#section-4
   *
   * @param {object} options - Options to use.
   * @param {object} options.recipient - A recipient with a header with a
   *   kid and alg.
   * @param {object} options.ephemeralKeyPair - An ephemeral key pair.
   * @param {object} options.cek - A content encryption key.
   * @param {object} [options.keyAgreementKey] - The sender's key agreement
   *   key API; required if the recipient uses `ECDH-1PU+A256KW`.
   * @param {Function} options.keyResolver - A function that can resolve keys.
   *
   * @returns {Promise<object>} A JWE recipient object.
   */
  async _createRecipient({
    recipient, ephemeralKeyPair, cek, keyResolver, keyAgreementKey
  }) {
    if(!recipient) {
      throw new TypeError('"options.recipient" is required.');
    }
    if(!ephemeralKeyPair) {
      throw new TypeError('"options.ephemeralKeyPair" is required.');
    }
    if(!cek) {
      throw new TypeError('"options.cek" is required.');
    }
    if(!keyResolver) {
      throw new TypeError('"options.keyResolver" is required.');
    }
    // resolve public DH key for recipient
    const {alg} = recipient.header;
    const {keyAgreement} = this;
    const staticPublicKey = await keyResolver({id: recipient.header.kid});
    // derive KEKs for each recipient
    const derivedResult = await keyAgreement.kekFromStaticPeer({
      ephemeralKeyPair, staticPublicKey, keyAgreementKey, alg
    });
    const {kek, epk, apu, apv} = derivedResult;
    const header = {
      // contains the key id - kid
      // contains the algorithm - alg
      ...recipient.header,
      // the ephemeralKeyPair
      epk,
      // base64 encoded ephemeralKeyPair's publicKey or sender key ID
      apu,
      // base64 encoded staticPublicKey's id
      apv,
    };

    // only sender-authenticated recipients carry the sender key ID; an
    // `ECDH-ES` recipient would expose it without authenticating it
    if(alg === keyAgreement.JWE_ALG_SENDER_AUTH) {
      header.skid = keyAgreementKey.id;
    }

    return {
      ...recipient,
      header,
      // the cek is wrapped so the recipient can use it to decrypt later
      encrypted_key: await kek.wrapKey({unwrappedKey: cek})
    };
  }
}

/**
 * See: https://streams.spec.whatwg.org/#ts-model .
 *
 * @typedef TransformStream
 */
