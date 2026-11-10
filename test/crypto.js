import assert from 'node:assert';
import fs from 'fs/promises';
import {
  before, describe, it,
} from 'node:test';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';

import * as crypto from '../lib/crypto.js';
import * as helpers from '../lib/helpers.js';
import { address } from '../lib/address.js';

import { KNACCC_WALLET } from './helpers/wallets.js';
import { mockRandomBytes } from './helpers/mock-random.js';
import { constructFixtures, ownerDerivation } from './helpers/construct.js';

// https://github.com/monero-project/monero/blob/v0.18.5.0/tests/crypto/tests.txt
const tests = (await fs.readFile('./test/fixtures/tests.txt', { encoding: 'utf8' })).trim().split('\n');
// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/hash/tests-fast.txt
const hashTests = (await fs.readFile('./test/fixtures/hash_tests_fast.txt', { encoding: 'utf8' })).trim().split('\n');

// The vectors below replay one shared stream, so it is started once for the whole file.
before(mockRandomBytes);

describe('crypto', () => {
  for (const item of tests) {
    const [cmd, ...rest] = item.split(' ');
    switch (cmd) {
      case 'check_scalar': {
        const [scalar, expected] = rest;
        describe('decodeScalar', () => {
          if (expected === 'true') {
            it(`scalar '${scalar}' to be valid`, () => {
              const actual = crypto.decodeScalar(hexToBytes(scalar));
              assert.strictEqual(bytesToHex(helpers.encodeInt(actual)), scalar);
            });
          } else {
            it(`scalar '${scalar}' should throw 'Invalid scalar'`, () => {
              assert.throws(() => {
                crypto.decodeScalar(hexToBytes(scalar));
              }, { message: 'Invalid scalar' });
            });
          }
        });
        break;
      }
      case 'random_scalar': {
        const [expected] = rest;
        describe('randomScalar', () => {
          it(`scalar must be '${expected}'`, () => {
            const actual = crypto.randomScalar();
            assert.strictEqual(bytesToHex(helpers.encodeInt(actual)), expected);
          });
        });
        break;
      }
      case 'hash_to_scalar': {
        const [data, expected] = rest;
        describe('hashToScalar', () => {
          it(`hash '${data}' to be converted to scalar '${expected}'`, () => {
            const actual = crypto.hashToScalar(data === 'x' ? new Uint8Array(0) : hexToBytes(data));
            assert.strictEqual(bytesToHex(helpers.encodeInt(actual)), expected);
          });
        });
        break;
      }
      case 'generate_keys': {
        const [expectedPub, expectedSec] = rest;
        describe('generateKeys', () => {
          it(`should generate pub '${expectedPub}' sec '${expectedSec}'`, () => {
            const { pub, sec } = crypto.generateKeys();
            assert.strictEqual(bytesToHex(pub), expectedPub);
            assert.strictEqual(bytesToHex(helpers.encodeInt(sec)), expectedSec);
          });
        });
        break;
      }
      case 'check_key': {
        const [point, expected] = rest;
        describe('decodePoint', () => {
          if (expected === 'true') {
            it(`point '${point}' to be valid`, () => {
              const actual = crypto.decodePoint(hexToBytes(point));
              assert.ok(actual instanceof crypto.Point);
            });
          } else {
            it(`point '${point}' should throw 'Invalid point'`, () => {
              assert.throws(() => {
                crypto.decodePoint(hexToBytes(point));
              }, { message: 'Invalid point' });
            });
          }
        });
        break;
      }
      case 'secret_key_to_public_key': {
        const [sec, success, expected] = rest;
        describe('secretKeyToPublicKey', () => {
          if (success === 'true') {
            it(`sec '${sec}' to be converted to pub '${expected}'`, () => {
              const actual = crypto.secretKeyToPublicKey(helpers.decodeInt(hexToBytes(sec)));
              assert.strictEqual(bytesToHex(actual), expected);
            });
          } else {
            it(`sec '${sec}' should throw 'Invalid secret key'`, () => {
              assert.throws(() => {
                crypto.secretKeyToPublicKey(helpers.decodeInt(hexToBytes(sec)));
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
              const actual = crypto.generateKeyDerivation(hexToBytes(pub), helpers.decodeInt(hexToBytes(sec)));
              assert.strictEqual(bytesToHex(actual), expected);
            });
          } else {
            it(`pub '${pub}' sec '${sec}' should throw 'Invalid public key'`, () => {
              assert.throws(() => {
                crypto.generateKeyDerivation(hexToBytes(pub), helpers.decodeInt(hexToBytes(sec)));
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
              const actual = crypto.derivePublicKey(hexToBytes(derivation), parseInt(index), hexToBytes(base));
              assert.strictEqual(bytesToHex(actual), expected);
            });
          } else {
            it(`derivation '${derivation}' index '${index}' base: '${base}' should throw 'Invalid public key'`, () => {
              assert.throws(() => {
                crypto.derivePublicKey(hexToBytes(derivation), parseInt(index), hexToBytes(base));
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
            const actual = crypto.deriveSecretKey(
              hexToBytes(derivation),
              parseInt(index),
              helpers.decodeInt(hexToBytes(base))
            );
            assert.strictEqual(bytesToHex(helpers.encodeInt(actual)), expected);
          });
        });
        break;
      }
      case 'derive_view_tag': {
        const [derivation, index, expected] = rest;
        describe('deriveViewTag', () => {
          it(`derivation '${derivation}' index '${index}' to be view tag '${expected}'`, () => {
            const actual = crypto.deriveViewTag(hexToBytes(derivation), parseInt(index));
            assert.strictEqual(bytesToHex(actual), expected);
          });
        });
        break;
      }
      case 'generate_signature': {
        const [prefix, pub, sec, expected] = rest;
        describe('generateSignature', () => {
          it(`prefix '${prefix}' pub '${pub}' sec: '${sec}' to be signature '${expected}'`, () => {
            const actual = crypto.generateSignature(
              hexToBytes(prefix),
              hexToBytes(pub),
              helpers.decodeInt(hexToBytes(sec))
            );
            assert.strictEqual(bytesToHex(actual), expected);
          });
        });
        break;
      }
      case 'check_signature': {
        const [prefix, pub, sig, expected] = rest;
        describe('checkSignature', () => {
          it(`prefix '${prefix}' pub '${pub}' sig: '${sig}' to be valid signature '${expected}'`, () => {
            const actual = crypto.checkSignature(hexToBytes(prefix), hexToBytes(pub), hexToBytes(sig));
            assert.strictEqual(actual, expected === 'true');
          });
        });
        break;
      }
      case 'hash_to_point': {
        const [data, expected] = rest;
        describe('hashToPoint', () => {
          it(`hash '${data}' to be converted to point '${expected}'`, () => {
            const point = crypto.hashToPoint(hexToBytes(data));
            assert.strictEqual(bytesToHex(crypto.encodePoint(point)), expected);
          });
        });
        break;
      }
      case 'hash_to_ec': {
        const [data, expected] = rest;
        describe('hashToEc', () => {
          it(`hash '${data}' to be converted to ec point '${expected}'`, () => {
            const point = crypto.hashToEc(hexToBytes(data));
            assert.strictEqual(bytesToHex(crypto.encodePoint(point)), expected);
          });
        });
        break;
      }
      case 'generate_key_image': {
        const [pub, sec, expected] = rest;
        describe('generateKeyImage', () => {
          it(`pub '${pub}' sec: '${sec}' to be key image '${expected}'`, () => {
            const actual = crypto.generateKeyImage(hexToBytes(pub), helpers.decodeInt(hexToBytes(sec)));
            assert.strictEqual(bytesToHex(actual), expected);
          });
        });
        break;
      }
      case 'generate_ring_signature': {
        const [prefix, image, count, ...r] = rest;
        const pubs = r.slice(0, count);
        const [sec, index, expected] = r.slice(count);
        describe('generateRingSignature', () => {
          it(`prefix '${prefix}' image: '${image}' pubs count: ${count} sec: ${sec} to be valid signature'`, { timeout: 5000 }, () => {
            const actual = crypto.generateRingSignature(
              hexToBytes(prefix),
              hexToBytes(image),
              pubs.map(hexToBytes),
              helpers.decodeInt(hexToBytes(sec)),
              parseInt(index)
            );
            assert.strictEqual(bytesToHex(actual), expected);
          });
        });
        break;
      }
      case 'check_ring_signature': {
        const [prefix, image, count, ...r] = rest;
        const pubs = r.slice(0, count);
        const [sig, expected] = r.slice(count);
        describe('checkRingSignature', () => {
          it(`prefix '${prefix}' image '${image}' pubs count: ${count} to be valid signature '${expected}'`, { timeout: 5000 }, () => {
            const actual = crypto.checkRingSignature(
              hexToBytes(prefix),
              hexToBytes(image),
              pubs.map(hexToBytes),
              hexToBytes(sig)
            );
            assert.strictEqual(actual, expected === 'true');
          });
        });
        break;
      }
      // The command checks the ref10 ge_p3 form, which has no JS equivalent.
      // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/crypto/crypto.cpp#L35-L63
      case 'check_ge_p3_identity': {
        break;
      }
      default: {
        throw new Error(`Unknown tests.txt command '${cmd}'`);
      }
    }
  }

  describe('fastHash', () => {
    hashTests.forEach((line, i) => {
      const [expected, data] = line.split(' ');
      const input = data === 'x' ? new Uint8Array(0) : hexToBytes(data);
      it(`vector ${i + 1}: ${input.length} bytes`, () => {
        assert.strictEqual(bytesToHex(crypto.fastHash(input)), expected);
      });
    });
  });

  describe('generateSignature', () => {
    it('throws when the public key does not belong to the secret key', () => {
      assert.throws(() => {
        crypto.generateSignature(new Uint8Array(32), crypto.secretKeyToPublicKey(2n), 1n);
      }, { message: 'Incorrect public key' });
    });
  });

  describe('generateRingSignature', () => {
    it('throws for a secret index outside the ring', () => {
      const pubs = [crypto.secretKeyToPublicKey(1n), crypto.secretKeyToPublicKey(2n)];
      assert.throws(() => {
        crypto.generateRingSignature(new Uint8Array(32), crypto.generateKeyImage(pubs[0], 1n), pubs, 1n, 2);
      }, { message: 'Bad index of secret key' });
    });
  });

  describe('checkRingSignature', () => {
    it('is false when a ring member is not a valid point', () => {
      const vector = tests.find((line) => line.startsWith('check_ring_signature') && line.endsWith(' true'));
      const [, prefix, image, count, ...rest] = vector.split(' ');
      const pubs = rest.slice(0, count).map(hexToBytes);
      const sig = hexToBytes(rest[count]);
      assert.strictEqual(crypto.checkRingSignature(hexToBytes(prefix), hexToBytes(image), pubs, sig), true);
      pubs[0] = new Uint8Array(32).fill(0xff);
      assert.strictEqual(crypto.checkRingSignature(hexToBytes(prefix), hexToBytes(image), pubs, sig), false);
    });
  });

  describe('subaddress keys', () => {
    const a = helpers.decodeInt(KNACCC_WALLET.secretViewKey);
    const b = helpers.decodeInt(KNACCC_WALLET.secretSpendKey);
    const B = KNACCC_WALLET.publicSpendKey;
    const A = KNACCC_WALLET.publicViewKey;

    for (const { index, address: subaddress } of KNACCC_WALLET.subaddresses) {
      const { publicSpendKey: D, publicViewKey: C } = address('mainnet').decode(subaddress);
      const name = `(${index.major}, ${index.minor})`;

      it(`subaddressSecret ${name}: m*G = D - B`, () => {
        const m = crypto.subaddressSecret(a, index);
        assert.ok(crypto.Point.BASE.multiply(m).equals(crypto.decodePoint(D).subtract(crypto.decodePoint(B))));
      });

      it(`subaddressPublicSpendKey ${name}: D`, () => {
        assert.deepStrictEqual(crypto.subaddressPublicSpendKey(a, B, index), D);
      });

      it(`subaddressSecretSpendKey ${name}: (b + m)*G = D`, () => {
        assert.deepStrictEqual(crypto.secretKeyToPublicKey(crypto.subaddressSecretSpendKey(a, b, index)), D);
      });

      it(`subaddressPublicKeys ${name}: D and C = a*D`, () => {
        assert.deepStrictEqual(crypto.subaddressPublicKeys(a, B, index), { publicSpendKey: D, publicViewKey: C });
      });
    }

    it('subaddress (1, 1): m, D and C', () => {
      const index = { major: 1, minor: 1 };
      const D = hexToBytes('4a3e863f2a7a43f7fbaa0320e06982009f2986dd04173eaee32aa8473317f19d');
      const C = hexToBytes('d247f90799916273407c1c71230d5ae0a9c71b8a7492da035e5e8ad972eea18b');
      assert.strictEqual(bytesToHex(helpers.encodeInt(crypto.subaddressSecret(a, index))), '81dea0953b33dcaed5097a7c2b94cf5e94a5d8fa9796631331ed656da187ea01');
      assert.deepStrictEqual(crypto.subaddressPublicSpendKey(a, B, index), D);
      assert.deepStrictEqual(crypto.secretKeyToPublicKey(crypto.subaddressSecretSpendKey(a, b, index)), D);
      assert.deepStrictEqual(crypto.subaddressPublicKeys(a, B, index), { publicSpendKey: D, publicViewKey: C });
    });

    describe('main address (0, 0)', () => {
      const main = { major: 0, minor: 0 };

      it('has no subaddress secret', () => {
        assert.throws(() => {
          crypto.subaddressSecret(a, main);
        });
      });

      it('keeps the account keys', () => {
        assert.deepStrictEqual(crypto.subaddressPublicSpendKey(a, B, main), B);
        assert.strictEqual(crypto.subaddressSecretSpendKey(a, b, main), b);
        assert.deepStrictEqual(crypto.subaddressPublicKeys(a, B, main), { publicSpendKey: B, publicViewKey: A });
      });
    });
  });

  // The fixtures come from monero construct_tx, so every output key and vin key image is monero's.
  describe('construct_tx outputs and inputs', () => {
    for (const fixture of constructFixtures) {
      describe(fixture.label, () => {
        const tx = fixture.decode();

        it('deriveSubaddressPublicKey recovers the spend key of every recipient', () => {
          for (const output of fixture.outputs) {
            const derivation = ownerDerivation(fixture, output);
            const outputKey = tx.prefix.vout[output.index].target.data.key;
            const spendKey = crypto.deriveSubaddressPublicKey(outputKey, derivation, output.index);
            assert.deepStrictEqual(spendKey, output.publicSpendKey);
          }
        });

        it('outputKeyOffset gives the one-time secret of every input: (offset + b)*G = P', () => {
          const a = helpers.decodeInt(fixture.sender.secretViewKey);
          const b = helpers.decodeInt(fixture.sender.secretSpendKey);
          for (const input of fixture.inputs) {
            const derivation = crypto.generateKeyDerivation(input.prevTxPublicKey, a);
            const offset = crypto.outputKeyOffset(a, derivation, input.prevOutputIndex, { major: 0, minor: 0 });
            assert.strictEqual(offset, input.keyOffset);
            assert.deepStrictEqual(crypto.secretKeyToPublicKey(crypto.Fn.add(offset, b)), input.publicKey);
          }
        });

        it('outputKeyImage gives the key images of the vin', () => {
          const a = helpers.decodeInt(fixture.sender.secretViewKey);
          const b = helpers.decodeInt(fixture.sender.secretSpendKey);
          const keyImages = fixture.inputs.map((input) => {
            const derivation = crypto.generateKeyDerivation(input.prevTxPublicKey, a);
            return bytesToHex(crypto.outputKeyImage(a, b, derivation, input.prevOutputIndex, { major: 0, minor: 0 }));
          });
          assert.deepStrictEqual(keyImages.sort(), tx.prefix.vin.map((vin) => bytesToHex(vin.data.keyImage)).sort());
        });
      });
    }
  });
});
