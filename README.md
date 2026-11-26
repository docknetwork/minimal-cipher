# Minimal Cipher _(@digitalbazaar/minimal-cipher)_

Minimal encryption/decryption [JWE](https://tools.ietf.org/html/rfc7516)
library, secure algs only, browser-compatible.

## Table of Contents

- [Security](#security)
- [Background](#background)
- [Install](#install)
- [Usage](#usage)
- [Contribute](#contribute)
- [Commercial Support](#commercial-support)
- [License](#license)

## Security

TBD

## Background

Every version of this library will only offer at most two algorithms
for encryption/decryption: a recommended algorithm and a FIPS-compliant
algorithm. The encryption API will expect the user to specify "recommended"
or "fips" as the version of the algorithm to use, defaulting to "recommended".

In the event that the FIPS-compliant algorithm is the same as the recommended
one in a given version of this library, then that particular version will
use the same algorithm regardless of the user specified "version".

This version of the library will use "XChaCha20-Poly1305" as the "recommended"
version and 256-bit "AES-GCM" as the FIPS-compliant version.

Note: XSalsa20-Poly1305 is an AE (Authenticated Encryption) algorithm, not
an AEAD (Authenticated Encryption and Associated Data) algorithm, making it
incompatible with the current requirements for a
[JWE (JOSE Web Encryption)](https://tools.ietf.org/html/rfc7516)
`protected` clear text header.

This library's API requires an interface for Key Encryption Key (KEKs). This
enables key material that is protected from exfiltration to be used via HSM/SSM
APIs, including Web KMS (TODO: citation needed).

## Install

- Node.js 20.19+ or 22.12+ required. The package is published as CommonJS and
  loads its ESM-only dependencies with `require()`.
- [Streams API][] required. Older browsers must use a polyfill.
- [Web Crypto API][] required. Older browsers must use a polyfill.

To install locally (for development):

```
git clone https://github.com/digitalbazaar/minimal-cipher.git
cd minimal-cipher
npm install
```

## Usage

Pick a Cipher interface (`recommended` or `fips`) and create an instance:

```js
import {Cipher} from '@docknetwork/minimal-cipher';

const cipher = new Cipher(); // by default {version: 'recommended'}
```

### Encrypting

To encrypt something (to create a cipher, serialized as a JWE JSON document),
you will need:

* Some data to encrypt (a string, an object, a stream)
* Keys (called Key Agreement Keys, or KAKs for short)

(You'll also need a `keyResolver`, more about that later.)

First, assemble your Key Agreement public keys (you'll be encrypting with them,
and the intended recipient will use the corresponding private keys to decrypt).

Put together a list of `recipients` (essentially, you're listing the `id`s of
public/private key pairs that will be used to encrypt/decrypt the message):

```js
// Retrieve them from config, a ledger, registry or back channel
const keyAgreementKey = await fetchFromSomewhere();

// or derive them from an existing Ed25519 signing key
import {X25519KeyAgreementKey2020} from '@digitalbazaar/x25519-key-agreement-key-2020';
import {Ed25519VerificationKey2020} from '@digitalbazaar/ed25519-verification-key-2020';
const keyPair = await Ed25519VerificationKey2020.generate();

const keyAgreementKey = X25519KeyPair.fromEd25519VerificationKey2020({keyPair});
// If the source key pair didn't have a controller set, don't forget to set one:
keyAgreementKey.controller = did; // The controller's DID
keyAgreementKey.id = `${did}#${keyAgreementKey.fingerprint()}`;

// or derive them from an authentication key extracted from DID Document
const didDoc = await veresDriver.get({did});
const authnKey = didDoc.getVerificationMethod({proofPurpose: 'authentication'});
const edKeyPair = await Ed25519VerificationKey2020.from(authnKey);
const keyPair = X25519KeyPair.fromEd25519VerificationKey2020({keyPair});

const recipient = {
  header: {
    kid: keyAgreementKey.id,
    alg: 'ECDH-ES+A256KW'
  }
}

const recipients = [recipient];
```

You'll also need a `keyResolver`. Notice that `recipients` lists only key IDs,
not the keys themselves. A `keyResolver` is a function that accepts a key ID
and resolves to the public key corresponding to it.

Some example resolvers:

```js
// Basic hardcoded key resolver; you already have the key material
const publicKeyNode = {
  '@context': 'https://w3id.org/security/suites/x25519-2020/v1',
  id: keyAgreementKey.id,
  type: 'X25519KeyAgreementKey2020',
  publicKeyMultibase: keyAgreementKey.publicKeyMultibase
};
const keyResolver = async () => publicKeyNode;
```

```js
// A more advanced resolver based on DID doc authentication keys
const keyResolver = async ({id}) => {
  // Use veres driver to fetch the authn key directly
  const keyPair = await Ed25519VerificationKey2020.from(await veresDriver.get({did: id}));
  // Convert authn key to key agreement key
  return X25519KeyPair.fromEd25519VerificationKey2020({keyPair});
}
```

```js
// Using did-veres-one driver as a resolver for did:v1:nym: DID keys
// TODO: Implement this
```

```js
// Using the did:key method driver as a key resolver
```

Create the JWE:

```js
// To encrypt a string or a Uint8Array
const data = 'plain text';
const jweDoc = await cipher.encrypt({data, recipients, keyResolver});

// To encrypt an object
const obj = {key: 'value'};
const jweDoc = await cipher.encryptObject({obj, recipients, keyResolver});
```

### Decrypting

Decrypt a JWE JSON Document, using a private `keyAgreementKey`:

```js
const data = await cipher.decrypt({jwe, keyAgreementKey});

const object = await cipher.decryptObject({jwe, keyAgreementKey});
```

### Sender authentication (ECDH-1PU)

Recipients that use `ECDH-ES+A256KW` can not tell who encrypted a JWE. To
authenticate the sender, use `ECDH-1PU+A256KW` recipients and pass the sender's
private `keyAgreementKey` when encrypting. The recipient needs a `keyResolver`
to resolve the sender's public key from the `skid` (sender key ID) header:

```js
const recipients = [{
  header: {kid: recipientKey.id, alg: 'ECDH-1PU+A256KW'}
}];
const jwe = await cipher.encryptObject(
  {obj, recipients, keyResolver, keyAgreementKey: senderKey});

const object = await cipher.decryptObject(
  {jwe, keyAgreementKey: recipientKey, keyResolver});
```

There are two wire formats for `ECDH-1PU+A256KW`, selected when creating the
`Cipher`:

```js
const cipher = new Cipher({
  // format to encrypt with: 'legacy' (default) or 'draft-04'
  senderAuthFormat: 'draft-04',
  // whether to decrypt the legacy format (default: true)
  allowLegacySenderAuth: false
});
```

* `legacy` is the format of version 5.2.1 and the default, so that existing
  deployments keep understanding each other. It has two problems: when a JWE
  has more than one recipient, any of them can replace its content and the
  others will accept it as coming from the sender, and other ECDH-1PU
  implementations can not read it.
* `draft-04` follows
  [draft-madden-jose-ecdh-1pu-04](https://datatracker.ietf.org/doc/html/draft-madden-jose-ecdh-1pu-04)
  (key agreement with key wrapping), with the header layout used by DIDComm
  v2. It always uses `A256CBC-HS512` content encryption, whatever the `Cipher`
  version, and binds the content to each recipient's wrapped key. Versions
  before 6.0.0 can not decrypt it.

Decryption detects the format, so to migrate: first upgrade every party to
6.0.0 or later, then switch senders to `senderAuthFormat: 'draft-04'`, and
finally set `allowLegacySenderAuth: false` so that legacy JWEs are refused.
In the `draft-04` format all recipients of a JWE must use `ECDH-1PU+A256KW`.

TODO: Describe the required KEK API:
// `id`, `algorithm`, `wrapKey({unwrappedKey})`, and `unwrapKey({wrappedKey})`

## Contribute

See [the contribute file](https://github.com/digitalbazaar/bedrock/blob/master/CONTRIBUTING.md)!

PRs accepted.

If editing the README, please conform to the
[standard-readme](https://github.com/RichardLitt/standard-readme) specification.

## Commercial Support

Commercial support for this library is available upon request from
Digital Bazaar: support@digitalbazaar.com

## License

[New BSD License (3-clause)](LICENSE) © Digital Bazaar

[Streams API]: https://developer.mozilla.org/en-US/docs/Web/API/Streams_API
[Web Crypto API]: https://developer.mozilla.org/en-US/docs/Web/API/Web_Crypto_API
