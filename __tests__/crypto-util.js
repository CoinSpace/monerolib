/* eslint-disable max-len */
import '@jest/globals';
import fs from 'fs/promises';
import elliptic from 'elliptic';
import cryptoUtil from '../lib/crypto-util.js';
import { __mockRandomBytes__ } from '../lib/crypto-util.js';
import permutation from '../node_modules/keccak/lib/keccak-state-unroll.js';

const ec = new elliptic.eddsa('ed25519');

// https://github.com/monero-project/monero/blob/v0.17.1.9/tests/crypto/tests.txt
const tests = (await fs.readFile('./__tests__/fixtures/tests.txt', { encoding: 'utf8' })).split('\n');

function hexToBuffer(hex, length = 32) {
  return Buffer.from(hex, 'hex', length);
}

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
        describe('scalarCheck', () => {
          test(`scalar '${scalar}' to be valid '${expected}'`, () => {
            expect(cryptoUtil.scalarCheck(hexToBuffer(scalar))).toBe(expected === 'true');
          });
        });
        break;
      }
      case 'random_scalar': {
        const [expected] = rest;
        describe('randomScalar', () => {
          test(`scalar must be '${expected}'`, () => {
            const actual = cryptoUtil.randomScalar();
            expect(actual.equals(hexToBuffer(expected))).toBe(true);
          });
        });
        break;
      }
      case 'hash_to_scalar': {
        const [data, expected] = rest;
        describe('hashToScalar', () => {
          test(`hash '${data}' to be converted to scalar '${expected}'`, () => {
            const actual = cryptoUtil.hashToScalar(hexToBuffer(data));
            expect(actual.equals(hexToBuffer(expected))).toBe(true);
          });
        });
        break;
      }
      case 'generate_keys': {
        const [expectedPub, expectedSec] = rest;
        describe('generateKeys', () => {
          test(`should generate pub '${expectedPub}' sec '${expectedSec}'`, () => {
            const { pub, sec } = cryptoUtil.generateKeys();
            expect(pub.equals(hexToBuffer(expectedPub))).toBe(true);
            expect(sec.equals(hexToBuffer(expectedSec))).toBe(true);
          });
        });
        break;
      }
      case 'check_key': {
        const [data, expected] = rest;
        describe('keyCheck', () => {
          test(`pub '${data}' to be valid '${expected}'`, () => {
            const actual = cryptoUtil.keyCheck(hexToBuffer(data));
            expect(actual).toBe(expected === 'true');
          });
        });
        break;
      }
      case 'secret_key_to_public_key': {
        const [sec, success, expected] = rest;
        describe('secretKeyToPublicKey', () => {
          if (success === 'true') {
            test(`sec '${sec}' to be converted to pub '${expected}'`, () => {
              const actual = cryptoUtil.secretKeyToPublicKey(hexToBuffer(sec));
              expect(actual.equals(hexToBuffer(expected))).toBe(true);
            });
          } else {
            test(`sec '${sec}' should throw 'Invalid secret key'`, () => {
              expect(() => {
                cryptoUtil.secretKeyToPublicKey(hexToBuffer(sec));
              }).toThrow('Invalid secret key');
            });
          }
        });
        break;
      }
      case 'generate_key_derivation': {
        const [pub, sec, success, expected] = rest;
        describe('generateKeyDerivation', () => {
          if (success === 'true') {
            test(`pub '${pub}' sec '${sec}' to be derived '${expected}'`, () => {
              const actual = cryptoUtil.generateKeyDerivation(hexToBuffer(pub), hexToBuffer(sec));
              expect(actual.equals(hexToBuffer(expected))).toBe(true);
            });
          } else {
            test(`pub '${pub}' sec '${sec}' should throw 'Invalid secret key'`, () => {
              expect(() => {
                cryptoUtil.generateKeyDerivation(hexToBuffer(pub), hexToBuffer(sec));
              }).toThrow('Invalid public key');
            });
          }
        });
        break;
      }
      case 'derive_public_key': {
        const [derivation, index, base, success, expected] = rest;
        describe('derivePublicKey', () => {
          if (success === 'true') {
            test(`derivation '${derivation}' index '${index}' base: '${base}' to be derived '${expected}'`, () => {
              const actual = cryptoUtil.derivePublicKey(hexToBuffer(derivation), parseInt(index), hexToBuffer(base));
              expect(actual.equals(hexToBuffer(expected))).toBe(true);
            });
          } else {
            test(`derivation '${derivation}' index '${index}' base: '${base}' should throw 'Invalid public key'`, () => {
              expect(() => {
                cryptoUtil.derivePublicKey(hexToBuffer(derivation), parseInt(index), hexToBuffer(base));
              }).toThrow('Invalid public key');
            });
          }
        });
        break;
      }
      case 'derive_secret_key': {
        const [derivation, index, base, expected] = rest;
        describe('deriveSecretKey', () => {
          test(`derivation '${derivation}' index '${index}' base: '${base}' to be derived '${expected}'`, () => {
            const actual = cryptoUtil.deriveSecretKey(hexToBuffer(derivation), parseInt(index), hexToBuffer(base));
            expect(actual.equals(hexToBuffer(expected))).toBe(true);
          });
        });
        break;
      }
      case 'generate_signature': {
        const [prefix, pub, sec, expected] = rest;
        describe('generateSignature', () => {
          test(`prefix '${prefix}' pub '${pub}' sec: '${sec}' to be signature '${expected}'`, () => {
            const actual = cryptoUtil.generateSignature(hexToBuffer(prefix), hexToBuffer(pub), hexToBuffer(sec));
            expect(actual.equals(hexToBuffer(expected))).toBe(true);
          });
        });
        break;
      }
      case 'check_signature': {
        const [prefix, pub, sig, expected] = rest;
        describe('checkSignature', () => {
          test(`prefix '${prefix}' pub '${pub}' sec: '${sig}' to be valid signature '${expected}'`, () => {
            const actual = cryptoUtil.checkSignature(hexToBuffer(prefix), hexToBuffer(pub), hexToBuffer(sig));
            expect(actual).toBe(expected === 'true');
          });
        });
        break;
      }
      case 'hash_to_point': {
        const [data, expected] = rest;
        describe('hashToPoint', () => {
          test(`hash '${data}' to be converted to point '${expected}'`, () => {
            const point = cryptoUtil.hashToPoint(hexToBuffer(data));
            const actual = Buffer.from(ec.encodePoint(point));
            expect(actual.equals(hexToBuffer(expected))).toBe(true);
          });
        });
        break;
      }
      case 'hash_to_ec': {
        const [data, expected] = rest;
        describe('hashToEc', () => {
          test(`hash '${data}' to be converted to ec point '${expected}'`, () => {
            const point = cryptoUtil.hashToEc(hexToBuffer(data));
            const actual = Buffer.from(ec.encodePoint(point));
            expect(actual.equals(hexToBuffer(expected))).toBe(true);
          });
        });
        break;
      }
      case 'generate_key_image': {
        const [pub, sec, expected] = rest;
        describe('generateKeyImage', () => {
          test(`pub '${pub}' sec: '${sec}' to be key image '${expected}'`, () => {
            const actual = cryptoUtil.generateKeyImage(hexToBuffer(pub), hexToBuffer(sec));
            expect(actual.equals(hexToBuffer(expected))).toBe(true);
          });
        });
        break;
      }
      case 'generate_ring_signature': {
        const [prefix, image, count, ...r] = rest;
        const pubs = r.slice(0, count);
        const [sec, index, expected] = r.slice(count);
        describe('generateRingSignature', () => {
          test(`prefix '${prefix}' image: '${image}' pubs count: ${count} sec: ${sec} to be valid signature'`, () => {
            const actual = cryptoUtil.generateRingSignature(
              hexToBuffer(prefix),
              hexToBuffer(image),
              pubs.map(hexToBuffer),
              hexToBuffer(sec),
              parseInt(index)
            );
            expect(actual.equals(hexToBuffer(expected))).toBe(true);
          });
        });
        break;
      }
      default: {
        break;
      }
    }
  }
});
