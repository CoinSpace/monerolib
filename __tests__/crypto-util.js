import '@jest/globals';
import fs from 'fs/promises';
import cryptoUtil from '../lib/crypto-util.js';

// https://github.com/monero-project/monero/blob/v0.17.1.9/tests/crypto/tests.txt
const tests = (await fs.readFile('./__tests__/tests.txt', { encoding: 'utf8' })).split('\n');

describe('crypto-util', () => {
  for (const item of tests) {
    const [cmd, ...rest] = item.split(' ');
    switch (cmd) {
      case 'check_scalar': {
        const [scalar, expected] = rest;
        test(`scalarCheck '${scalar}' is valid '${expected}'`, () => {
          expect(cryptoUtil.scalarCheck(Buffer.from(scalar, 'hex'))).toBe(expected === 'true');
        });
        break;
      }
      case 'random_scalar': {
        // no tests for random_scalar
        break;
      }
      case 'hash_to_scalar': {
        const [data, expected] = rest;
        test(`hashToScalar '${data}' is scalar '${expected}'`, () => {
          const actual = cryptoUtil.hashToScalar(Buffer.from(data, 'hex', 32));
          expect(actual.equals(Buffer.from(expected, 'hex'))).toBe(true);
        });
        break;
      }
      case 'check_key': {
        const [data, expected] = rest;
        test(`keyCheck '${data}' is valid '${expected}'`, () => {
          const actual = cryptoUtil.keyCheck(Buffer.from(data, 'hex', 32));
          expect(actual).toBe(expected === 'true');
        });
        break;
      }
      default: {
        break;
      }
    }
  }
});
