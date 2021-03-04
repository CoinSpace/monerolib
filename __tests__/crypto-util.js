/* eslint-disable max-len */
import '@jest/globals';
import fs from 'fs/promises';
import cryptoUtil from '../lib/crypto-util.js';

// https://github.com/monero-project/monero/blob/v0.17.1.9/tests/crypto/tests.txt
const tests = (await fs.readFile('./__tests__/fixtures/tests.txt', { encoding: 'utf8' })).split('\n');

function hexToBuffer(hex, length = 32) {
  return Buffer.from(hex, 'hex', length);
}

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
        // no tests for random_scalar
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
      default: {
        break;
      }
    }
  }
});
