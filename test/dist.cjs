/*!
 * Smoke test for the published CommonJS build: loads `dist/` the way a
 * consumer does and runs a round trip with each key agreement algorithm.
 */
const assert = require('node:assert');
const {Cipher} = require('../dist/index.js');
const {
  deriveSecret, generateEphemeralKeyPair, multibaseDecode, multibaseEncode,
  MULTICODEC_X25519_PUB_HEADER
} = require('../dist/algorithms/x25519.js');

async function createKey(id) {
  const {privateKey, publicKey} = await generateEphemeralKeyPair();
  return {
    id,
    type: 'X25519KeyAgreementKey2020',
    publicKeyMultibase: multibaseEncode(
      MULTICODEC_X25519_PUB_HEADER, publicKey),
    async deriveSecret({publicKey}) {
      const remotePublicKey = multibaseDecode(
        MULTICODEC_X25519_PUB_HEADER, publicKey.publicKeyMultibase);
      return deriveSecret({privateKey, remotePublicKey});
    }
  };
}

(async () => {
  const sender = await createKey('urn:sender');
  const recipient = await createKey('urn:recipient');
  const keys = new Map([[sender.id, sender], [recipient.id, recipient]]);
  const keyResolver = async ({id}) => keys.get(id);
  const obj = {simple: true};

  for(const version of ['recommended', 'fips']) {
    for(const senderAuthFormat of ['legacy', 'draft-04']) {
      const cipher = new Cipher({version, senderAuthFormat});
      for(const alg of ['ECDH-ES+A256KW', 'ECDH-1PU+A256KW']) {
        const jwe = await cipher.encryptObject({
          obj,
          recipients: [{header: {kid: recipient.id, alg}}],
          keyResolver,
          keyAgreementKey: sender
        });
        const result = await cipher.decryptObject(
          {jwe, keyAgreementKey: recipient, keyResolver});
        assert.deepStrictEqual(
          result, obj, `${version} ${senderAuthFormat} ${alg} round trip`);
      }
    }
  }
  console.log('dist smoke test passed');
})().catch(e => {
  console.error(e);
  process.exit(1);
});
