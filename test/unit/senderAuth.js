/*!
 * Tests for `ECDH-1PU+A256KW` (sender authenticated) recipients.
 */
import * as base64url from 'base64url-universal';
import chai from 'chai';
import * as a256cbcHs512 from '../../lib/algorithms/a256cbc-hs512.js';
import * as a256gcm from '../../lib/algorithms/a256gcm.js';
import * as xc20p from '../../lib/algorithms/xc20p.js';
import {deriveKey} from '../../lib/algorithms/ecdhkdf.js';
import {
  deriveSecret, kekFromEphemeralPeer
} from '../../lib/algorithms/x25519.js';
import {Cipher} from '../../lib/index.js';
import {KaK} from '../KaK.js';
import {isJWE} from '../chai-cipher.js';
import {store} from '../store.js';

const should = chai.should();
chai.use(isJWE);

const ALG = 'ECDH-1PU+A256KW';
const ENC = 'A256CBC-HS512';
const LEGACY_CIPHERS = {recommended: xc20p, fips: a256gcm};

const keyResolver = async ({id}) => store.get(id);
const fromHex = hex => new Uint8Array(
  hex.match(/[0-9a-f]{2}/g).map(byte => parseInt(byte, 16)));
const decodeProtected = jwe => JSON.parse(
  new TextDecoder().decode(base64url.decode(jwe.protected)));

// replaces the content of `jwe` the way a recipient who holds `kak` could:
// unwrap the shared CEK, encrypt something else with it and leave the other
// recipients' wrapped keys in place
async function forgeContent({jwe, kak, cipher, obj}) {
  const protectedHeader = decodeProtected(jwe);
  const recipient = jwe.recipients.find(e => e.header.kid === kak.id);
  const {epk, skid, alg, apu, apv} = {...recipient.header, ...protectedHeader};
  const draft04 = protectedHeader.enc === ENC;
  const {kek} = await kekFromEphemeralPeer({
    keyAgreementKey: kak, epk, skid, alg, keyResolver,
    ...(draft04 ? {apu, apv, tag: base64url.decode(jwe.tag)} : {})
  });
  const cek = await kek.unwrapKey({wrappedKey: recipient.encrypted_key});
  should.exist(cek);
  const {ciphertext, iv, tag} = await cipher.encrypt({
    data: new TextEncoder().encode(JSON.stringify(obj)),
    additionalData: new TextEncoder().encode(jwe.protected),
    cek
  });
  return {
    ...jwe,
    iv: base64url.encode(iv),
    ciphertext: base64url.encode(ciphertext),
    tag: base64url.encode(tag)
  };
}

describe('ECDH-1PU sender authentication', function() {
  // https://www.ietf.org/archive/id/draft-madden-jose-ecdh-1pu-04.txt
  describe('draft-madden-jose-ecdh-1pu-04 appendix B vector', function() {
    const alice = {
      d: 'i9KuFhSzEBsiv3PKVL5115OCdsqQai5nj_Flzfkw5jU'
    };
    const ephemeral = {
      d: 'x8EVZH4Fwk673_mUujnliJoSrLz0zYzzCWp5GUX2fc8'
    };
    const recipients = [{
      name: 'Bob',
      x: 'BT7aR0ItXfeDAldeeOlXL_wXqp-j5FltT0vRSG16kRw',
      ze: '32810896e0fe4d570ed1acfcedf67117dc194ed5daac21d8ff7af3244694897f',
      zs: '2157612c9048edfae77cb2e4237140605967c05c7f77a48eeaf2cf29a5737c4a',
      kek: 'df4c37a0668306a11e3d6b0074b5d8df'
    }, {
      name: 'Charlie',
      x: 'q-LsvU772uV_2sPJhfAIq-3vnKNVefNoIlvyvg1hrnE',
      ze: '89dcfe4c37c1dc0271f346b5b3b19c3b705ca2a72f9a237785c34406fcb75f10',
      zs: '78fe63fc661cf8d18f92a8422a6418e4ed5e20a9168185fdeedca1c3d8e6a61c',
      kek: '57d8126f1b7ec4ccb0584dac03cb27cc'
    }];
    const jwe = {
      protected:
        'eyJhbGciOiJFQ0RILTFQVStBMTI4S1ciLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIiwiYXB1' +
        'IjoiUVd4cFkyVSIsImFwdiI6IlFtOWlJR0Z1WkNCRGFHRnliR2xsIiwiZXBrIjp7Imt0' +
        'eSI6Ik9LUCIsImNydiI6IlgyNTUxOSIsIngiOiJrOW9mX2NwQWFqeTBwb1c1Z2FpeFhH' +
        'czluSGt3ZzFBRnFVQUZhMzlkeUJjIn19',
      iv: 'AAECAwQFBgcICQoLDA0ODw',
      ciphertext: 'Az2IWsISEMDJvyc5XRL-3-d-RgNBOGolCsxFFoUXFYw',
      tag: 'HLb4fTlm8spGmij3RyOs2gJ4DpHM4hhVRwdF_hGb3WQ'
    };
    const cek = fromHex(
      'fffefdfcfbfaf9f8f7f6f5f4f3f2f1f0efeeedecebeae9e8e7e6e5e4e3e2e1e0' +
      'dfdedddcdbdad9d8d7d6d5d4d3d2d1d0cfcecdcccbcac9c8c7c6c5c4c3c2c1c0');
    const plaintext = 'Three is a magic number.';

    for(const recipient of recipients) {
      it(`should derive the key encryption key for ${recipient.name}`,
        async function() {
          const remotePublicKey = base64url.decode(recipient.x);
          const ze = await deriveSecret({
            privateKey: base64url.decode(ephemeral.d), remotePublicKey
          });
          const zs = await deriveSecret(
            {privateKey: base64url.decode(alice.d), remotePublicKey});
          new Uint8Array(ze).should.deep.eql(fromHex(recipient.ze));
          new Uint8Array(zs).should.deep.eql(fromHex(recipient.zs));

          const {apu, apv} = decodeProtected(jwe);
          const kek = await deriveKey({
            alg: 'ECDH-1PU+A128KW',
            secret: fromHex(recipient.ze + recipient.zs),
            producerInfo: base64url.decode(apu),
            consumerInfo: base64url.decode(apv),
            tag: base64url.decode(jwe.tag),
            keyLength: 128
          });
          kek.should.deep.eql(fromHex(recipient.kek));
        });
    }

    it('should decrypt the A256CBC-HS512 content', async function() {
      const options = {
        ciphertext: base64url.decode(jwe.ciphertext),
        iv: base64url.decode(jwe.iv),
        tag: base64url.decode(jwe.tag),
        additionalData: new TextEncoder().encode(jwe.protected),
        cek
      };
      const data = await a256cbcHs512.decrypt(options);
      new TextDecoder().decode(data).should.equal(plaintext);

      // a modified tag, ciphertext or protected header must be rejected
      const tag = new Uint8Array(options.tag);
      tag[0] ^= 1;
      should.equal(await a256cbcHs512.decrypt({...options, tag}), null);
      const ciphertext = new Uint8Array(options.ciphertext);
      ciphertext[0] ^= 1;
      should.equal(
        await a256cbcHs512.decrypt({...options, ciphertext}), null);
      const additionalData = new Uint8Array(options.additionalData);
      additionalData[0] ^= 1;
      should.equal(
        await a256cbcHs512.decrypt({...options, additionalData}), null);
    });
  });

  it('should reject an unknown "senderAuthFormat"', function() {
    (() => new Cipher({senderAuthFormat: 'unknown'})).should.throw(
      'Unsupported senderAuthFormat');
  });

  for(const version of ['recommended', 'fips']) {
    describe(`${version} algorithm`, function() {
      let legacyCipher;
      let draftCipher;
      let strictCipher;
      let sender;
      let alice;
      let bob;
      const obj = {simple: true};

      beforeEach(function() {
        legacyCipher = new Cipher({version});
        draftCipher = new Cipher({version, senderAuthFormat: 'draft-04'});
        strictCipher = new Cipher({
          version, senderAuthFormat: 'draft-04', allowLegacySenderAuth: false
        });
        sender = new KaK({id: 'urn:sender'});
        alice = new KaK({id: 'urn:alice'});
        bob = new KaK({id: 'urn:bob'});
      });

      it('should encrypt in the "draft-04" format', async function() {
        const recipients = [
          alice.recipientSenderAuth, bob.recipientSenderAuth
        ];
        const jwe = await draftCipher.encryptObject(
          {obj, recipients, keyResolver, keyAgreementKey: sender});
        jwe.should.be.a.JWE;

        // key agreement parameters are in the protected header
        const header = decodeProtected(jwe);
        header.alg.should.equal(ALG);
        header.enc.should.equal(ENC);
        header.skid.should.equal(sender.id);
        header.apu.should.equal(
          base64url.encode(new TextEncoder().encode(sender.id)));
        header.apv.should.be.a('string');
        header.epk.should.be.an('object');
        jwe.recipients.length.should.equal(2);
        for(const recipient of jwe.recipients) {
          recipient.header.should.have.keys(['kid']);
          recipient.encrypted_key.should.be.a('string');
        }

        for(const keyAgreementKey of [alice, bob]) {
          for(const cipher of [draftCipher, strictCipher, legacyCipher]) {
            const result = await cipher.decryptObject(
              {jwe, keyAgreementKey, keyResolver});
            result.should.eql(obj);
          }
        }
      });

      it('should encrypt and decrypt a stream in the "draft-04" format',
        async function() {
          const data = new Uint8Array(50).map((_, i) => i);
          const encryptStream = await draftCipher.createEncryptStream({
            recipients: [alice.recipientSenderAuth], keyResolver,
            chunkSize: 5, keyAgreementKey: sender
          });
          const decryptStream = await strictCipher.createDecryptStream(
            {keyAgreementKey: alice, keyResolver});
          const chunks = [];
          const encrypted = new ReadableStream({
            start(controller) {
              controller.enqueue(data);
              controller.close();
            }
          }).pipeThrough(encryptStream).pipeThrough(new TransformStream({
            transform(chunk, controller) {
              chunks.push(chunk);
              controller.enqueue(chunk);
            }
          }));
          const reader = encrypted.pipeThrough(decryptStream).getReader();
          const result = [];
          for(;;) {
            const {value, done} = await reader.read();
            if(done) {
              break;
            }
            result.push(...value);
          }
          chunks.length.should.equal(10);
          // every chunk has its own tag, so its own wrapped key
          const wrappedKeys = new Set(
            chunks.map(({jwe}) => jwe.recipients[0].encrypted_key));
          wrappedKeys.size.should.equal(10);
          new Uint8Array(result).should.deep.eql(data);
        });

      it('should not decrypt "draft-04" content replaced by a recipient',
        async function() {
          const recipients = [
            alice.recipientSenderAuth, bob.recipientSenderAuth
          ];
          const jwe = await draftCipher.encryptObject(
            {obj, recipients, keyResolver, keyAgreementKey: sender});
          const forged = await forgeContent(
            {jwe, kak: bob, cipher: a256cbcHs512, obj: {pay: 1000000}});

          // the wrapped key is bound to the tag of the original content
          const result = await draftCipher.decryptObject(
            {jwe: forged, keyAgreementKey: alice, keyResolver});
          should.equal(result, null);
        });

      it('should not decrypt "draft-04" JWEs from another sender',
        async function() {
          const jwe = await draftCipher.encryptObject({
            obj, recipients: [alice.recipientSenderAuth], keyResolver,
            keyAgreementKey: sender
          });
          const other = new KaK({id: 'urn:other'});
          const otherResolver = async ({id}) => id === sender.id ?
            {...other.publicKeyNode, id} : store.get(id);
          const result = await draftCipher.decryptObject(
            {jwe, keyAgreementKey: alice, keyResolver: otherResolver});
          should.equal(result, null);
        });

      it('should decrypt the legacy format unless it is disallowed',
        async function() {
          const recipients = [
            alice.recipientSenderAuth, bob.recipientSenderAuth
          ];
          const jwe = await legacyCipher.encryptObject(
            {obj, recipients, keyResolver, keyAgreementKey: sender});
          decodeProtected(jwe).should.eql(
            {enc: LEGACY_CIPHERS[version].JWE_ENC});

          const result = await draftCipher.decryptObject(
            {jwe, keyAgreementKey: alice, keyResolver});
          result.should.eql(obj);

          let error;
          try {
            await strictCipher.decryptObject(
              {jwe, keyAgreementKey: alice, keyResolver});
          } catch(e) {
            error = e;
          }
          should.exist(error);
          error.message.should.contain('legacy sender authentication format');
        });

      it('should reject legacy content replaced by a recipient when the ' +
        'legacy format is disallowed', async function() {
        const recipients = [
          alice.recipientSenderAuth, bob.recipientSenderAuth
        ];
        const jwe = await legacyCipher.encryptObject(
          {obj, recipients, keyResolver, keyAgreementKey: sender});
        const forged = await forgeContent({
          jwe, kak: bob, cipher: LEGACY_CIPHERS[version], obj: {pay: 1000000}
        });

        // known weakness of the legacy format, the reason for "draft-04"
        const result = await legacyCipher.decryptObject(
          {jwe: forged, keyAgreementKey: alice, keyResolver});
        result.should.eql({pay: 1000000});

        let error;
        try {
          await strictCipher.decryptObject(
            {jwe: forged, keyAgreementKey: alice, keyResolver});
        } catch(e) {
          error = e;
        }
        should.exist(error);
      });

      it('should not mix algorithms in the "draft-04" format',
        async function() {
          const recipients = [alice.recipient, bob.recipientSenderAuth];
          let error;
          try {
            await draftCipher.encryptObject(
              {obj, recipients, keyResolver, keyAgreementKey: sender});
          } catch(e) {
            error = e;
          }
          should.exist(error);
          error.message.should.contain('All recipients must use');
        });

      it('should require a sender key in the "draft-04" format',
        async function() {
          let error;
          try {
            await draftCipher.encryptObject(
              {obj, recipients: [alice.recipientSenderAuth], keyResolver});
          } catch(e) {
            error = e;
          }
          should.exist(error);
          error.message.should.contain('requires keyAgreementKey');
        });

      it('should not change ECDH-ES encryption', async function() {
        const jwe = await draftCipher.encryptObject(
          {obj, recipients: [alice.recipient], keyResolver});
        decodeProtected(jwe).should.eql(
          {enc: LEGACY_CIPHERS[version].JWE_ENC});
        const result = await strictCipher.decryptObject(
          {jwe, keyAgreementKey: alice});
        result.should.eql(obj);
      });
    });
  }
});
