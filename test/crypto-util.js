/* eslint-disable max-len */
import assert from 'assert';
import fs from 'fs/promises';
import elliptic from 'elliptic';
import cryptoUtil from '../lib/crypto-util.js';
import { hexToBuffer } from '../lib/helpers.js';
import { __mockRandomBytes__ } from '../lib/crypto-util.js';
import permutation from '../node_modules/keccak/lib/keccak-state-unroll.js';

const ec = new elliptic.eddsa('ed25519');

// https://github.com/monero-project/monero/blob/v0.17.1.9/tests/crypto/tests.txt
const tests = (await fs.readFile('./test/fixtures/tests.txt', { encoding: 'utf8' })).split('\n');

/**
 * https://github.com/monero-project/monero/blob/v0.17.1.9/tests/crypto/random.c#L36
 */
const state = new Int32Array(new Int8Array(200)
  .fill(42)
  .buffer);

function randomBytes(length) {
  permutation.p1600(state);
  const buf = Buffer.from(state.buffer);  return buf.slice(0, length);
}

__mockRandomBytes__(randomBytes);

describe('crypto-util', () => {
  for (const item of tests) {
    const [cmd, ...rest] = item.split(' ');
    switch (cmd) {
      case 'check_scalar': {
        const [scalar, expected] = rest;
        describe('checkScalar', () => {
          it(`scalar '${scalar}' to be valid '${expected}'`, () => {
            const actual = cryptoUtil.checkScalar(hexToBuffer(scalar));
            assert.strictEqual(actual, expected === 'true');
          });
        });
        break;
      }
      case 'random_scalar': {
        const [expected] = rest;
        describe('randomScalar', () => {
          it(`scalar must be '${expected}'`, () => {
            const actual = cryptoUtil.randomScalar();
            assert.strictEqual(actual.toString('hex'), expected);
          });
        });
        break;
      }
      case 'hash_to_scalar': {
        const [data, expected] = rest;
        describe('hashToScalar', () => {
          it(`hash '${data}' to be converted to scalar '${expected}'`, () => {
            const actual = cryptoUtil.hashToScalar(hexToBuffer(data));
            assert.strictEqual(actual.toString('hex'), expected);
          });
        });
        break;
      }
      case 'generate_keys': {
        const [expectedPub, expectedSec] = rest;
        describe('generateKeys', () => {
          it(`should generate pub '${expectedPub}' sec '${expectedSec}'`, () => {
            const { pub, sec } = cryptoUtil.generateKeys();
            assert.strictEqual(pub.toString('hex'), expectedPub);
            assert.strictEqual(sec.toString('hex'), expectedSec);
          });
        });
        break;
      }
      case 'check_key': {
        const [data, expected] = rest;
        describe('checkKey', () => {
          it(`pub '${data}' to be valid '${expected}'`, () => {
            const actual = cryptoUtil.checkKey(hexToBuffer(data));
            assert.strictEqual(actual, expected === 'true');
          });
        });
        break;
      }
      case 'secret_key_to_public_key': {
        const [sec, success, expected] = rest;
        describe('secretKeyToPublicKey', () => {
          if (success === 'true') {
            it(`sec '${sec}' to be converted to pub '${expected}'`, () => {
              const actual = cryptoUtil.secretKeyToPublicKey(hexToBuffer(sec));
              assert.strictEqual(actual.toString('hex'), expected);
            });
          } else {
            it(`sec '${sec}' should throw 'Invalid secret key'`, () => {
              assert.throws(() => {
                cryptoUtil.secretKeyToPublicKey(hexToBuffer(sec));
              }, { message: 'Invalid secret key' });
            });
          }
        });
        break;
      }
      case 'generate_key_derivation': {
        const [pub, sec, success, expected] = rest;
        describe('generateKeyDerivation', () => {
          if (success === 'true') {
            it(`pub '${pub}' sec '${sec}' to be derived '${expected}'`, () => {
              const actual = cryptoUtil.generateKeyDerivation(hexToBuffer(pub), hexToBuffer(sec));
              assert.strictEqual(actual.toString('hex'), expected);
            });
          } else {
            it(`pub '${pub}' sec '${sec}' should throw 'Invalid secret key'`, () => {
              assert.throws(() => {
                cryptoUtil.generateKeyDerivation(hexToBuffer(pub), hexToBuffer(sec));
              }, { message: 'Invalid public key' });
            });
          }
        });
        break;
      }
      case 'derive_public_key': {
        const [derivation, index, base, success, expected] = rest;
        describe('derivePublicKey', () => {
          if (success === 'true') {
            it(`derivation '${derivation}' index '${index}' base: '${base}' to be derived '${expected}'`, () => {
              const actual = cryptoUtil.derivePublicKey(hexToBuffer(derivation), parseInt(index), hexToBuffer(base));
              assert.strictEqual(actual.toString('hex'), expected);
            });
          } else {
            it(`derivation '${derivation}' index '${index}' base: '${base}' should throw 'Invalid public key'`, () => {
              assert.throws(() => {
                cryptoUtil.derivePublicKey(hexToBuffer(derivation), parseInt(index), hexToBuffer(base));
              }, { message: 'Invalid public key' });
            });
          }
        });
        break;
      }
      case 'derive_secret_key': {
        const [derivation, index, base, expected] = rest;
        describe('deriveSecretKey', () => {
          it(`derivation '${derivation}' index '${index}' base: '${base}' to be derived '${expected}'`, () => {
            const actual = cryptoUtil.deriveSecretKey(hexToBuffer(derivation), parseInt(index), hexToBuffer(base));
            assert.strictEqual(actual.toString('hex'), expected);
          });
        });
        break;
      }
      case 'generate_signature': {
        const [prefix, pub, sec, expected] = rest;
        describe('generateSignature', () => {
          it(`prefix '${prefix}' pub '${pub}' sec: '${sec}' to be signature '${expected}'`, () => {
            const actual = cryptoUtil.generateSignature(hexToBuffer(prefix), hexToBuffer(pub), hexToBuffer(sec));
            assert.strictEqual(actual.toString('hex'), expected);
          });
        });
        break;
      }
      case 'check_signature': {
        const [prefix, pub, sig, expected] = rest;
        describe('checkSignature', () => {
          it(`prefix '${prefix}' pub '${pub}' sig: '${sig}' to be valid signature '${expected}'`, () => {
            const actual = cryptoUtil.checkSignature(hexToBuffer(prefix), hexToBuffer(pub), hexToBuffer(sig));
            assert.strictEqual(actual, expected === 'true');
          });
        });
        break;
      }
      case 'hash_to_point': {
        const [data, expected] = rest;
        describe('hashToPoint', () => {
          it(`hash '${data}' to be converted to point '${expected}'`, () => {
            const point = cryptoUtil.hashToPoint(hexToBuffer(data));
            const actual = Buffer.from(ec.encodePoint(point));
            assert.strictEqual(actual.toString('hex'), expected);
          });
        });
        break;
      }
      case 'hash_to_ec': {
        const [data, expected] = rest;
        describe('hashToEc', () => {
          it(`hash '${data}' to be converted to ec point '${expected}'`, () => {
            const point = cryptoUtil.hashToEc(hexToBuffer(data));
            const actual = Buffer.from(ec.encodePoint(point));
            assert.strictEqual(actual.toString('hex'), expected);
          });
        });
        break;
      }
      case 'generate_key_image': {
        const [pub, sec, expected] = rest;
        describe('generateKeyImage', () => {
          it(`pub '${pub}' sec: '${sec}' to be key image '${expected}'`, () => {
            const actual = cryptoUtil.generateKeyImage(hexToBuffer(pub), hexToBuffer(sec));
            assert.strictEqual(actual.toString('hex'), expected);
          });
        });
        break;
      }
      case 'generate_ring_signature': {
        const [prefix, image, count, ...r] = rest;
        const pubs = r.slice(0, count);
        const [sec, index, expected] = r.slice(count);
        describe('generateRingSignature', () => {
          it(`prefix '${prefix}' image: '${image}' pubs count: ${count} sec: ${sec} to be valid signature'`, () => {
            const actual = cryptoUtil.generateRingSignature(
              hexToBuffer(prefix),
              hexToBuffer(image),
              pubs.map(hexToBuffer),
              hexToBuffer(sec),
              parseInt(index)
            );
            assert.strictEqual(actual.toString('hex'), expected);
          }).timeout(5000);
        });
        break;
      }
      case 'check_ring_signature': {
        const [prefix, image, count, ...r] = rest;
        const pubs = r.slice(0, count);
        const [sig, expected] = r.slice(count);
        describe('checkRingSignature', () => {
          it(`prefix '${prefix}' image '${image}' pubs count: ${count} to be valid signature '${expected}'`, () => {
            const actual = cryptoUtil.checkRingSignature(
              hexToBuffer(prefix),
              hexToBuffer(image),
              pubs.map(hexToBuffer),
              hexToBuffer(sig)
            );
            assert.strictEqual(actual, expected === 'true');
          }).timeout(5000);
        });
        break;
      }
      default: {
        break;
      }
    }
  }
});
