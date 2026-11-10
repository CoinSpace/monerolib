import assert from 'node:assert';
import {
  afterEach, beforeEach, describe, it,
} from 'node:test';
import {
  bytesToHex, hexToBytes, randomBytes,
} from '@noble/hashes/utils.js';

import * as bulletproofs from '../lib/bulletproofs.js';
import * as clsag from '../lib/clsag.js';
import * as crypto from '../lib/crypto.js';
import * as helpers from '../lib/helpers.js';
import * as raw from '../lib/raw.js';
import * as ringct from '../lib/ringct.js';
import * as tx from '../lib/tx.js';
import { address } from '../lib/address.js';

import { constructFixtures } from './helpers/construct.js';
import { mockRandomBytes } from './helpers/mock-random.js';
import txExtraFixtures from './fixtures/tx_extra.json' with { type: 'json' };
import txFixtures from './fixtures/txs.json' with { type: 'json' };
import { FUNCTIONAL_TESTS_WALLET, KNACCC_WALLET } from './helpers/wallets.js';
import { fixedKeys, withRandomSource } from './helpers/common.js';

const scalar = helpers.decodeInt;
const pointTimes = (point, s) => crypto.encodePoint(crypto.decodePoint(point).multiply(s));

// A destination with the secret view scalar that finds its outputs.
const recipientOf = (str, secretViewKey) => ({ ...address('mainnet').decode(str), secretView: scalar(secretViewKey) });
const STANDARD = recipientOf(KNACCC_WALLET.address, KNACCC_WALLET.secretViewKey);
const SUBADDRESS = recipientOf(KNACCC_WALLET.subaddresses[0].address, KNACCC_WALLET.secretViewKey);
const OTHER_SUBADDRESS = recipientOf(KNACCC_WALLET.subaddresses[1].address, KNACCC_WALLET.secretViewKey);
const OTHER_STANDARD = recipientOf(FUNCTIONAL_TESTS_WALLET.address, FUNCTIONAL_TESTS_WALLET.secretViewKey);

// The spendable input of 5010000 and the sender of a monero construct_tx fixture.
const SOURCE = constructFixtures[1];
const {
  inputs: INPUTS, secretSpendKey: SECRET_SPEND_KEY, secretViewKey: SECRET_VIEW_KEY,
} = SOURCE.params();
const SENDER = { ...SOURCE.outputs.find((output) => output.isChange), secretView: SECRET_VIEW_KEY };
const changeOf = (amount) => ({
  type: 'address',
  publicSpendKey: SENDER.publicSpendKey,
  publicViewKey: SENDER.publicViewKey,
  secretView: SENDER.secretView,
  isChange: true,
  amount,
});
const paramsOf = (outputs, options = {}) => ({
  inputs: INPUTS, outputs, secretSpendKey: SECRET_SPEND_KEY, secretViewKey: SECRET_VIEW_KEY, ...options,
});

// What the recipient of output i sees: whether the output key is its own, the view tag and the amount.
function receivedBy(decoded, i, recipient) {
  const { txPublicKeys, additionalTxPublicKeys } = tx.parseTxExtra(decoded.prefix.extra);
  const { key, viewTag } = decoded.prefix.vout[i].target.data;
  const derivation = [...txPublicKeys, additionalTxPublicKeys[i]].filter(Boolean)
    .map((R) => crypto.generateKeyDerivation(R, recipient.secretView))
    .find((candidate) => (
      bytesToHex(crypto.derivePublicKey(candidate, i, recipient.publicSpendKey)) === bytesToHex(key)
    ));
  if (!derivation) {
    return undefined;
  }
  const {
    ecdhInfo, outPk, type,
  } = decoded.rctSigBase;
  return {
    viewTag: crypto.deriveViewTag(derivation, i)[0] === viewTag,
    amount: ringct.decodeRct(ecdhInfo[i], outPk[i], type, i, derivation).amount,
  };
}

// test_tx_utils public key: tag 0x01 and 32 bytes.
// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/test_tx_utils.cpp#L100-L109
const PUB_KEY = '1ed062a285405553705bbc59d31883279a16e4503fc68dad6ff4b70495ba8ce6';
const PUB_KEY_FIELD = `01${PUB_KEY}`;
const parsed = (txPublicKeys = [], additionalTxPublicKeys = [], encryptedPaymentId = undefined) => ({
  txPublicKeys: txPublicKeys.map(hexToBytes),
  additionalTxPublicKeys: additionalTxPublicKeys.map(hexToBytes),
  encryptedPaymentId: encryptedPaymentId && hexToBytes(encryptedPaymentId),
});
const parse = (hex) => tx.parseTxExtra(hexToBytes(hex));

describe('tx', () => {
  describe('parseTxExtra', () => {
    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/test_tx_utils.cpp#L45-L136
    describe('monero test_tx_utils', () => {
      it('empty extra', () => {
        assert.deepStrictEqual(parse(''), parsed());
      });

      it('padding of 1, 2 and 255 bytes', () => {
        for (const size of [1, 2, 255]) {
          assert.deepStrictEqual(parse('00'.repeat(size)), parsed());
        }
      });

      it('padding of 256 bytes, which monero rejects', () => {
        assert.deepStrictEqual(parse('00'.repeat(256)), parsed());
      });

      it('padding with a non-zero byte, which monero rejects', () => {
        assert.deepStrictEqual(parse('002a'), parsed());
      });

      it('public key only', () => {
        assert.deepStrictEqual(parse(PUB_KEY_FIELD), parsed([PUB_KEY]));
      });

      it('nonce only, which is not a payment id', () => {
        assert.deepStrictEqual(parse('02012a'), parsed());
      });

      it('public key and 76 bytes of padding', () => {
        assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}${'00'.repeat(76)}`), parsed([PUB_KEY]));
      });

      // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/test_tx_utils.cpp#L156-L164
      it('nonce with a size of 255 and only 18 bytes', () => {
        assert.deepStrictEqual(parse(`02ff${'00'.repeat(18)}`), parsed());
      });
    });

    // monero-oxide keeps the fields before a malformed field, as monero parse_tx_extra does.
    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/wallet/src/tests/extra.rs#L164-L219
    describe('monero-oxide extra', () => {
      it('public key and invalid padding keeps the public key', () => {
        assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}0001`), parsed([PUB_KEY]));
      });

      it('mysterious minergate fields', () => {
        assert.deepStrictEqual(parse('de012a'), parsed());
        assert.deepStrictEqual(parse(`de8004${'00'.repeat(512)}`), parsed());
        assert.deepStrictEqual(parse(`deff${'00'.repeat(18)}`), parsed());
        assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}de012a`), parsed([PUB_KEY]));
      });

      it('empty nonce and arbitrary data nonce', () => {
        assert.deepStrictEqual(parse('0200'), parsed());
        assert.deepStrictEqual(parse('02017f'), parsed());
      });
    });

    describe('monero fuzz seeds', () => {
      for (const {
        label, source, hex,
      } of txExtraFixtures) {
        it(label, () => {
          const result = parse(hex);
          assert.deepStrictEqual(result.txPublicKeys, [hexToBytes(hex.slice(2, 66))], source);
          if (label.includes('payment id')) {
            // 02 09 01: nonce tag, nonce size 9, encrypted payment id tag
            assert.strictEqual(hex.slice(66, 72), '020901');
            assert.deepStrictEqual(result.encryptedPaymentId, hexToBytes(hex.slice(72, 88)));
          } else {
            // 04 10: additional public keys tag, 16 keys
            assert.strictEqual(hex.slice(66, 70), '0410');
            assert.deepStrictEqual(result.additionalTxPublicKeys, (hex.slice(70).match(/.{64}/g)).map(hexToBytes));
          }
        });
      }
    });

    it('keeps every tx public key, also an all-zero one', () => {
      const zero = '00'.repeat(32);
      assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}01${zero}${PUB_KEY_FIELD}`), parsed([PUB_KEY, zero, PUB_KEY]));
    });

    it('reads the encrypted payment id before or after the public key', () => {
      const nonce = '0209010102030405060708';
      assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}${nonce}`), parsed([PUB_KEY], [], '0102030405060708'));
      assert.deepStrictEqual(parse(`${nonce}${PUB_KEY_FIELD}`), parsed([PUB_KEY], [], '0102030405060708'));
    });

    it('takes the first additional public keys field and the first payment id', () => {
      const keys = ['11'.repeat(32), '22'.repeat(32)];
      assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}0401${keys[0]}0401${keys[1]}`), parsed([PUB_KEY], [keys[0]]));
      assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}0209010102030405060708020901${'ff'.repeat(8)}`), parsed([PUB_KEY], [], '0102030405060708'));
    });

    it('reads three additional public keys', () => {
      const keys = ['fc1776e142ade7a4ad5e00bd27a480013f06c45d5ac80807d3609500bdd26cf2', '98705ffac66ef63d67cb5872b6fc222879902edbe7a3ccb83278c82a5fad097c', 'cfc1d89d5e5fba53a68a238239ebd5f60d60327d22da3ee95a9c070674ea525a'];
      assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}0403${keys.join('')}`), parsed([PUB_KEY], keys));
    });

    it('accepts a nonce of 255 bytes, the monero maximum', () => {
      assert.deepStrictEqual(parse(`02ff01${'00'.repeat(255)}${PUB_KEY_FIELD}`), parsed([PUB_KEY]));
    });

    it('does not read a payment id from a nonce of the wrong size', () => {
      assert.deepStrictEqual(parse('02052a0109080706'), parsed());
    });

    it('stops at an unknown tag and keeps the fields before it', () => {
      assert.deepStrictEqual(parse(`${PUB_KEY_FIELD}9901${PUB_KEY_FIELD}`), parsed([PUB_KEY]));
    });

    it('does not emit truncated fields', () => {
      assert.deepStrictEqual(parse('010203'), parsed());
      assert.deepStrictEqual(parse('0401090909'), parsed());
    });

    // https://xmrchain.net/tx/f64bbe722d0ef4ae96d8b6dccf693ce8ca9b525e8c47fe9642040f744870d64b
    it('keeps nothing from a real extra that starts with a malformed field', () => {
      assert.deepStrictEqual(parse('0321001a36d20bc8a84a04be188f3a0f8b76b9f4e66f000230e8d3f8ab72777a7520f100000083d9c85c1dccceb0ee3532ef7c9528ae4dfe2ca79b139f4637a3ba16de8d02110000000000000000000000000000000000'), parsed());
    });
  });

  describe('buildTxExtra', () => {
    it('writes the public key, the additional public keys and the payment id nonce in monero order', () => {
      const keys = ['11'.repeat(32), '22'.repeat(32)];
      assert.strictEqual(bytesToHex(tx.buildTxExtra({ txPublicKey: hexToBytes(PUB_KEY) })), PUB_KEY_FIELD);
      assert.strictEqual(bytesToHex(tx.buildTxExtra({
        txPublicKey: hexToBytes(PUB_KEY),
        additionalTxPublicKeys: keys.map(hexToBytes),
        encryptedPaymentId: hexToBytes('0102030405060708'),
      })), `${PUB_KEY_FIELD}0402${keys.join('')}0209010102030405060708`);
    });

    // monero adds the payment id of an integrated address, or a zero dummy for at most two outputs.
    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/cryptonote_core/cryptonote_tx_utils.cpp#L265-L333
    for (const fixture of constructFixtures) {
      it(`builds the extra of ${fixture.label}`, () => {
        const r = scalar(fixture.txKeys.txSecretKey);
        const integrated = fixture.outputs.find((output) => output.type === 'integratedaddress');
        let encryptedPaymentId;
        if (integrated) {
          encryptedPaymentId = tx.encryptPaymentId(integrated.paymentID, integrated.publicViewKey, r);
        } else if (fixture.outputs.length <= 2) {
          const recipient = fixture.outputs.find((output) => !output.isChange);
          encryptedPaymentId = tx.encryptPaymentId(new Uint8Array(8), recipient.publicViewKey, r);
        }
        assert.deepStrictEqual(tx.buildTxExtra({
          txPublicKey: fixture.txKeys.txPublicKey,
          additionalTxPublicKeys: fixture.txKeys.additionalTxPublicKeys,
          encryptedPaymentId,
        }), fixture.decode().prefix.extra);
      });
    }
  });

  describe('encryptPaymentId', () => {
    const isIntegrated = (output) => output.type === 'integratedaddress';
    const fixture = constructFixtures.find(({ outputs }) => outputs.some(isIntegrated));
    const integrated = fixture.outputs.find(isIntegrated);

    it('encrypts the payment id of monero construct_tx with the tx secret key', () => {
      const { encryptedPaymentId } = tx.parseTxExtra(fixture.decode().prefix.extra);
      const r = scalar(fixture.txKeys.txSecretKey);
      const encrypted = tx.encryptPaymentId(integrated.paymentID, integrated.publicViewKey, r);
      assert.deepStrictEqual(encrypted, encryptedPaymentId);
    });

    it('decrypts it with the tx public key and the secret view key of the recipient', () => {
      const { encryptedPaymentId } = tx.parseTxExtra(fixture.decode().prefix.extra);
      const a = scalar(integrated.owner.secretViewKey);
      const decrypted = tx.encryptPaymentId(encryptedPaymentId, fixture.txKeys.txPublicKey, a);
      assert.deepStrictEqual(decrypted, integrated.paymentID);
    });
  });

  describe('generateOutputs', () => {
    for (const fixture of constructFixtures) {
      it(`derives the output keys and view tags of ${fixture.label}`, () => {
        const { outputs, secretViewKey } = fixture.params();
        const keys = [fixture.txKeys.txSecretKey, ...fixture.txKeys.additionalTxSecretKeys].map(scalar);
        const generated = tx.generateOutputs(outputs, fixedKeys(keys), secretViewKey);
        const { vout } = fixture.decode().prefix;
        assert.deepStrictEqual(generated.txKeys.txPublicKey, fixture.txKeys.txPublicKey);
        assert.deepStrictEqual(generated.txKeys.additionalTxPublicKeys, fixture.txKeys.additionalTxPublicKeys);
        generated.outputs.forEach((output, i) => {
          assert.deepStrictEqual(output.key, vout[i].target.data.key);
          assert.strictEqual(output.viewTag, vout[i].target.data.viewTag);
        });
      });
    }

    // classify_addresses and the tx key rules of construct_tx_with_tx_key
    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/cryptonote_core/cryptonote_tx_utils.cpp#L87-L111
    describe('tx public key rules', () => {
      // whether recipient finds output i with its view tag
      const finds = ({ txKeys, outputs }, i, recipient) => {
        const candidates = [txKeys.txPublicKey, ...txKeys.additionalTxPublicKeys];
        return candidates.some((R) => {
          const derivation = crypto.generateKeyDerivation(R, recipient.secretView);
          const outputKey = crypto.derivePublicKey(derivation, i, recipient.publicSpendKey);
          return bytesToHex(outputKey) === bytesToHex(outputs[i].key)
            && crypto.deriveViewTag(derivation, i)[0] === outputs[i].viewTag;
        });
      };

      it('standard recipients: R = r*G, no additional keys', () => {
        const generated = tx.generateOutputs([STANDARD, OTHER_STANDARD], fixedKeys([17n]));
        assert.deepStrictEqual(generated.txKeys.txPublicKey, crypto.secretKeyToPublicKey(17n));
        assert.deepStrictEqual(generated.txKeys.additionalTxPublicKeys, []);
        assert.ok(finds(generated, 0, STANDARD));
        assert.ok(finds(generated, 1, OTHER_STANDARD));
      });

      it('standard and subaddress: R = r*G, one additional key per output', () => {
        const generated = tx.generateOutputs([STANDARD, SUBADDRESS], fixedKeys([17n, 19n, 23n]));
        assert.deepStrictEqual(generated.txKeys.txPublicKey, crypto.secretKeyToPublicKey(17n));
        assert.deepStrictEqual(generated.txKeys.additionalTxPublicKeys, [
          crypto.secretKeyToPublicKey(19n),
          pointTimes(SUBADDRESS.publicSpendKey, 23n),
        ]);
        assert.ok(finds(generated, 0, STANDARD));
        assert.ok(finds(generated, 1, SUBADDRESS));
      });

      it('single subaddress: R = r*D, no additional keys', () => {
        const generated = tx.generateOutputs([SUBADDRESS], fixedKeys([17n]));
        assert.deepStrictEqual(generated.txKeys.txPublicKey, pointTimes(SUBADDRESS.publicSpendKey, 17n));
        assert.deepStrictEqual(generated.txKeys.additionalTxPublicKeys, []);
        assert.ok(finds(generated, 0, SUBADDRESS));
      });

      it('two different subaddresses: R = r*G, one additional key per output', () => {
        const generated = tx.generateOutputs([SUBADDRESS, OTHER_SUBADDRESS], fixedKeys([17n, 19n, 23n]));
        assert.deepStrictEqual(generated.txKeys.txPublicKey, crypto.secretKeyToPublicKey(17n));
        assert.deepStrictEqual(generated.txKeys.additionalTxPublicKeys, [
          pointTimes(SUBADDRESS.publicSpendKey, 19n),
          pointTimes(OTHER_SUBADDRESS.publicSpendKey, 23n),
        ]);
        assert.ok(finds(generated, 0, SUBADDRESS));
        assert.ok(finds(generated, 1, OTHER_SUBADDRESS));
      });

      it('the same subaddress twice counts once: R = r*D, no additional keys', () => {
        const generated = tx.generateOutputs([SUBADDRESS, SUBADDRESS], fixedKeys([17n]));
        assert.deepStrictEqual(generated.txKeys.txPublicKey, pointTimes(SUBADDRESS.publicSpendKey, 17n));
        assert.deepStrictEqual(generated.txKeys.additionalTxPublicKeys, []);
        assert.ok(finds(generated, 0, SUBADDRESS));
        assert.ok(finds(generated, 1, SUBADDRESS));
      });

      it('change of a single subaddress send derives from a*R with R = r*D', () => {
        const generated = tx.generateOutputs([SUBADDRESS, changeOf(1n)], fixedKeys([17n]), SENDER.secretView);
        assert.deepStrictEqual(generated.txKeys.txPublicKey, pointTimes(SUBADDRESS.publicSpendKey, 17n));
        assert.deepStrictEqual(generated.txKeys.additionalTxPublicKeys, []);
        assert.ok(finds(generated, 0, SUBADDRESS));
        assert.ok(finds(generated, 1, SENDER));
      });

      it('change gets an additional key next to standard and subaddress recipients', () => {
        const destinations = [STANDARD, SUBADDRESS, changeOf(1n)];
        const generated = tx.generateOutputs(destinations, fixedKeys([17n, 19n, 23n, 29n]), SENDER.secretView);
        assert.deepStrictEqual(generated.txKeys.txPublicKey, crypto.secretKeyToPublicKey(17n));
        assert.deepStrictEqual(generated.txKeys.additionalTxPublicKeys, [
          crypto.secretKeyToPublicKey(19n),
          pointTimes(SUBADDRESS.publicSpendKey, 23n),
          crypto.secretKeyToPublicKey(29n),
        ]);
        [STANDARD, SUBADDRESS, SENDER].forEach((recipient, i) => assert.ok(finds(generated, i, recipient)));
      });
    });
  });

  // Transactions built by monero v0.18.5.1 construct_tx_with_tx_key, with every construction input
  // recorded. Both implementations draw the transaction key, the Bulletproof+ nonces, the pseudo
  // output masks and the CLSAG nonces in the same order, so the same random stream must yield the
  // same bytes. The stream only lines up when the transaction keys are replayed the way monero
  // produced them, which generatedTxKeys records.
  describe('createTransaction against monero', () => {
    beforeEach(mockRandomBytes);
    afterEach(() => crypto.__mockRandomBytes__(randomBytes));

    for (const fixture of constructFixtures) {
      it(fixture.label, () => {
        const { bytes } = tx.createTransaction({
          ...fixture.params(),
          generateTxSecretKey: fixture.generatedTxKeys
            ? undefined
            : fixedKeys([fixture.txKeys.txSecretKey, ...fixture.txKeys.additionalTxSecretKeys].map(scalar)),
        });
        assert.strictEqual(bytesToHex(bytes), fixture.hex);
      });
    }
  });

  describe('createTransaction', () => {
    const MIXED = () => [{ ...STANDARD, amount: 1000000n }, { ...SUBADDRESS, amount: 2000000n }, changeOf(2000000n)];
    // constant random bytes give a known shuffle, [address, change, subaddress]; the fixed keys stay distinct
    const shuffled = () => withRandomSource((length) => new Uint8Array(length).fill(1), () => (
      tx.prepareTransaction(paramsOf(MIXED(), { generateTxSecretKey: fixedKeys([17n, 19n, 23n, 29n]) }))
    ));

    it('prepareTransaction and createTransaction build the same transaction from the same random stream', () => {
      let prepared;
      let created;
      try {
        mockRandomBytes();
        prepared = tx.prepareTransaction(paramsOf(MIXED()));
        mockRandomBytes();
        created = tx.createTransaction(paramsOf(MIXED()));
      } finally {
        crypto.__mockRandomBytes__(randomBytes);
      }
      assert.deepStrictEqual(Object.keys(prepared).sort(), ['destinations', 'transaction', 'txKeys']);
      assert.deepStrictEqual(Object.keys(created).sort(), ['bytes', 'destinations', 'txKeys']);
      assert.deepStrictEqual(created.bytes, raw.fullTransaction.encode(prepared.transaction));
      assert.deepStrictEqual(created.txKeys, prepared.txKeys);
      assert.deepStrictEqual(created.destinations, prepared.destinations);
    });

    it('returns the generated tx secret key, whose public key is in extra', () => {
      const { bytes, txKeys } = tx.createTransaction(paramsOf([{ ...STANDARD, amount: 1000000n }, changeOf(4000000n)]));
      assert.strictEqual(typeof txKeys.txSecretKey, 'bigint');
      assert.deepStrictEqual(txKeys.txPublicKey, crypto.secretKeyToPublicKey(txKeys.txSecretKey));
      const { extra } = raw.fullTransaction.decode(bytes).prefix;
      assert.deepStrictEqual(tx.parseTxExtra(extra).txPublicKeys, [txKeys.txPublicKey]);
      assert.deepStrictEqual(txKeys.additionalTxSecretKeys, []);
      assert.deepStrictEqual(txKeys.additionalTxPublicKeys, []);
    });

    it('uses the supplied tx secret keys in order, one additional key per output', () => {
      const { transaction, txKeys } = tx.prepareTransaction(paramsOf(MIXED(), {
        generateTxSecretKey: fixedKeys([17n, 19n, 23n, 29n]),
        shuffleOutputs: false,
      }));
      assert.strictEqual(txKeys.txSecretKey, 17n);
      assert.deepStrictEqual(txKeys.additionalTxSecretKeys, [19n, 23n, 29n]);
      const extra = tx.parseTxExtra(transaction.prefix.extra);
      assert.deepStrictEqual(extra.txPublicKeys, [crypto.secretKeyToPublicKey(17n)]);
      assert.deepStrictEqual(extra.additionalTxPublicKeys, [
        crypto.secretKeyToPublicKey(19n),
        pointTimes(SUBADDRESS.publicSpendKey, 23n),
        crypto.secretKeyToPublicKey(29n),
      ]);
      assert.deepStrictEqual(txKeys.additionalTxPublicKeys, extra.additionalTxPublicKeys);
      [STANDARD, SUBADDRESS, SENDER].forEach((recipient, i) => {
        assert.deepStrictEqual(receivedBy(transaction, i, recipient), { viewTag: true, amount: MIXED()[i].amount });
      });
    });

    for (const recipient of [STANDARD, SUBADDRESS]) {
      it(`takes only the main key from the generator for a single ${recipient.type}`, () => {
        const outputs = [{ ...recipient, amount: 1000000n }, changeOf(4000000n)];
        const { transaction, txKeys } = tx.prepareTransaction(paramsOf(outputs, {
          generateTxSecretKey: fixedKeys([17n]),
          shuffleOutputs: false,
        }));
        const R = recipient.type === 'subaddress'
          ? pointTimes(recipient.publicSpendKey, 17n)
          : crypto.secretKeyToPublicKey(17n);
        assert.strictEqual(txKeys.txSecretKey, 17n);
        assert.deepStrictEqual(txKeys.additionalTxSecretKeys, []);
        const extra = tx.parseTxExtra(transaction.prefix.extra);
        assert.deepStrictEqual(extra.txPublicKeys, [R]);
        assert.deepStrictEqual(extra.additionalTxPublicKeys, []);
        assert.deepStrictEqual(receivedBy(transaction, 0, recipient), { viewTag: true, amount: 1000000n });
        assert.deepStrictEqual(receivedBy(transaction, 1, SENDER), { viewTag: true, amount: 4000000n });
      });
    }

    it('uses one additional key for every mixed output, also for a zero change', () => {
      for (const amount of [0n, 5n]) {
        const outputs = [{ ...STANDARD, amount: 10n }, { ...SUBADDRESS, amount: 20n }, changeOf(amount)];
        const generateTxSecretKey = fixedKeys([7n, 11n, 13n, 17n]);
        const { transaction, txKeys } = tx.prepareTransaction(paramsOf(outputs, { generateTxSecretKey }));
        assert.strictEqual(txKeys.txSecretKey, 7n);
        assert.deepStrictEqual(txKeys.additionalTxSecretKeys, [11n, 13n, 17n]);
        assert.strictEqual(tx.parseTxExtra(transaction.prefix.extra).additionalTxPublicKeys.length, 3);
      }
    });

    // wallet2 shuffle_outs: Fisher-Yates over the outputs with the CSPRNG
    it('shuffles the outputs by default and keeps the caller order without shuffleOutputs', () => {
      const outputs = [{ ...STANDARD, amount: 1000000n }, { ...OTHER_STANDARD, amount: 2000000n }, changeOf(1000000n)];
      const ownersOf = (decoded) => decoded.prefix.vout.map((vout, i) => (
        [STANDARD, OTHER_STANDARD, SENDER].find((recipient) => receivedBy(decoded, i, recipient))
      ));
      // constant random bytes make Fisher-Yates deterministic: j = 0x01010101 % (i + 1) is 1 for
      // i = 2 and for i = 1, so [standard, other, change] becomes [standard, change, other]
      const build = (shuffleOutputs) => withRandomSource((length) => new Uint8Array(length).fill(1), () => (
        tx.prepareTransaction(paramsOf(outputs, { shuffleOutputs })).transaction
      ));
      assert.deepStrictEqual(ownersOf(build(true)), [STANDARD, SENDER, OTHER_STANDARD]);
      assert.deepStrictEqual(ownersOf(build(false)), [STANDARD, OTHER_STANDARD, SENDER]);
    });

    it('moves the additional keys with the shuffled outputs', () => {
      const {
        transaction, txKeys, destinations,
      } = shuffled();
      const kinds = destinations.map(({ type, isChange }) => (isChange ? 'change' : type));
      assert.deepStrictEqual(kinds, ['address', 'change', 'subaddress']);
      destinations.forEach((destination, i) => {
        const s = txKeys.additionalTxSecretKeys[i];
        const expected = destination.type === 'subaddress'
          ? pointTimes(destination.publicSpendKey, s)
          : crypto.secretKeyToPublicKey(s);
        assert.deepStrictEqual(txKeys.additionalTxPublicKeys[i], expected);
        assert.deepStrictEqual(receivedBy(transaction, i, destination), { viewTag: true, amount: destination.amount });
      });
    });

    it('signs a shuffled transaction: Bulletproof+ and every CLSAG verify', () => {
      const {
        prefix, rctSigBase, rctSigPrunable,
      } = shuffled().transaction;
      const [proof] = rctSigPrunable.bulletproofsPlus;
      assert.ok(bulletproofs.verifyBulletproofPlus(rctSigBase.outPk, proof));
      const message = tx.getPreMlsagHash(crypto.fastHash(raw.txPrefix.encode(prefix)), rctSigBase, proof);
      prefix.vin.forEach((vin, i) => {
        const signature = { ...rctSigPrunable.CLSAGs[i], I: vin.data.keyImage };
        assert.ok(clsag.verifyClsag(message, SOURCE.ringOf(vin), rctSigPrunable.pseudoOuts[i], signature));
      });
    });

    it('returns the destinations in output order without changing the caller outputs', () => {
      const outputs = MIXED();
      const snapshot = structuredClone(outputs);
      for (const result of [tx.prepareTransaction(paramsOf(outputs)), tx.createTransaction(paramsOf(outputs))]) {
        const decoded = result.transaction ?? raw.fullTransaction.decode(result.bytes);
        assert.deepStrictEqual(outputs.map((output) => result.destinations.indexOf(output)).sort(), [0, 1, 2]);
        result.destinations.forEach((destination, i) => {
          assert.deepStrictEqual(receivedBy(decoded, i, destination), { viewTag: true, amount: destination.amount });
        });
      }
      const unshuffled = tx.prepareTransaction(paramsOf(outputs, { shuffleOutputs: false })).destinations;
      assert.deepStrictEqual(unshuffled, outputs);
      assert.notStrictEqual(unshuffled, outputs);
      assert.deepStrictEqual(outputs, snapshot);
    });

    it('encrypts the payment id of an integrated address to its view key, next to another recipient', () => {
      const paymentID = hexToBytes('0123456789abcdef');
      const outputs = [{
        ...STANDARD, type: 'integratedaddress', paymentID, amount: 2000000n,
      }, { ...OTHER_STANDARD, amount: 3000000n }];
      const { transaction } = tx.prepareTransaction(paramsOf(outputs, { generateTxSecretKey: fixedKeys([17n]) }));
      const { encryptedPaymentId, txPublicKeys } = tx.parseTxExtra(transaction.prefix.extra);
      assert.deepStrictEqual(txPublicKeys, [crypto.secretKeyToPublicKey(17n)]);
      assert.deepStrictEqual(tx.encryptPaymentId(encryptedPaymentId, txPublicKeys[0], STANDARD.secretView), paymentID);
    });

    describe('rejects', () => {
      const TWO_OUTPUTS = () => [{ ...STANDARD, amount: 1000000n }, changeOf(4000000n)];

      it('a spend key that does not own the input', () => {
        assert.throws(() => {
          tx.createTransaction(paramsOf(TWO_OUTPUTS(), { secretSpendKey: SECRET_SPEND_KEY + 1n }));
        }, /wrong spend key/);
      });

      it('the same input twice and a duplicate ring member', () => {
        const [input] = INPUTS;
        assert.throws(() => {
          tx.createTransaction(paramsOf(TWO_OUTPUTS(), { inputs: [input, input] }));
        }, /duplicate input/);
        const { globalIndex } = input.decoys[1];
        const decoys = input.decoys.map((decoy, i) => (i === 0 ? { ...decoy, globalIndex } : decoy));
        assert.throws(() => {
          tx.createTransaction(paramsOf(TWO_OUTPUTS(), { inputs: [{ ...input, decoys }] }));
        }, /duplicate ring member/);
      });

      it('no inputs', () => {
        assert.throws(() => {
          tx.createTransaction(paramsOf(TWO_OUTPUTS(), { inputs: [] }));
        }, /empty inputs/);
      });

      // monero requires at least two outputs and at most 16
      it('fewer than two and more than 16 outputs', () => {
        assert.throws(() => {
          tx.createTransaction(paramsOf([]));
        }, /at least two outputs/);
        assert.throws(() => {
          tx.createTransaction(paramsOf([{ ...STANDARD, amount: 0n }]));
        }, /at least two outputs/);
        assert.throws(() => {
          tx.createTransaction(paramsOf(Array.from({ length: 17 }, () => ({ ...STANDARD, amount: 0n }))));
        }, /too many outputs/);
      });

      it('amounts, unlock time and global indexes outside uint64, and outputs that exceed the inputs', () => {
        const [input] = INPUTS;
        assert.throws(() => {
          tx.createTransaction(paramsOf(TWO_OUTPUTS(), { inputs: [{ ...input, amount: -1n }] }));
        }, /uint64 bigint/);
        assert.throws(() => {
          tx.createTransaction(paramsOf([{ ...STANDARD, amount: 2n ** 64n }, changeOf(0n)]));
        }, /uint64 bigint/);
        assert.throws(() => {
          tx.createTransaction(paramsOf(TWO_OUTPUTS(), { unlockTime: 2n ** 64n }));
        }, /uint64 bigint/);
        const decoys = input.decoys.map((decoy, i) => (i === 0 ? { ...decoy, globalIndex: -1n } : decoy));
        assert.throws(() => {
          tx.createTransaction(paramsOf(TWO_OUTPUTS(), { inputs: [{ ...input, decoys }] }));
        }, /uint64 bigint/);
        assert.throws(() => {
          tx.createTransaction(paramsOf([{ ...STANDARD, amount: 5010001n }, changeOf(0n)]));
        }, /outputs exceed inputs/);
      });

      it('more than one address with a payment id', () => {
        const outputs = [STANDARD, OTHER_STANDARD].map((recipient) => ({
          ...recipient, type: 'integratedaddress', paymentID: new Uint8Array(8), amount: 1000000n,
        }));
        assert.throws(() => {
          tx.createTransaction(paramsOf(outputs));
        }, /multiple addresses with payment ids/);
      });
    });
  });

  describe('globalIndexesFromOutputOffsets', () => {
    it('gives the ring global indexes of monero construct_tx', () => {
      const ringKey = (indexes) => indexes.join(',');
      const sorted = (indexes) => indexes.sort((a, b) => (a < b ? -1 : 1));
      const globalIndexesOf = (input) => [input, ...input.decoys].map((member) => member.globalIndex);
      for (const fixture of constructFixtures) {
        const expected = fixture.inputs.map((input) => sorted(globalIndexesOf(input)));
        const { vin } = fixture.decode().prefix;
        const actual = vin.map(({ data }) => tx.globalIndexesFromOutputOffsets(data.outputOffsets));
        assert.deepStrictEqual(actual.map(ringKey).sort(), expected.map(ringKey).sort(), fixture.label);
      }
    });

    it('reconstructs absolute indexes with uint64 wraparound (unsorted ring)', () => {
      const mask = (1n << 64n) - 1n;
      // a "negative" relative delta stored as 2^64 - 30 lowers the next index by 30
      assert.deepStrictEqual(tx.globalIndexesFromOutputOffsets([100n, mask - 29n]), [100n, 70n]);
    });
  });

  describe('getPreMlsagHash', () => {
    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/src/tests/vectors/transactions.json#L99-L101
    it('matches the signature hash of the monero-oxide type 6 vector', () => {
      for (const fixture of txFixtures.filter(({ signatureHash }) => signatureHash)) {
        const decoded = raw.fullTransaction.decode(hexToBytes(fixture.hex));
        const prefixHash = crypto.fastHash(raw.txPrefix.encode(decoded.prefix));
        const actual = tx.getPreMlsagHash(prefixHash, decoded.rctSigBase, decoded.rctSigPrunable.bulletproofsPlus[0]);
        assert.strictEqual(bytesToHex(actual), fixture.signatureHash);
      }
    });
  });

  describe('getTxId', () => {
    for (const {
      label, hex, id,
    } of [...txFixtures, ...constructFixtures].filter((fixture) => fixture.id)) {
      it(label, () => {
        assert.strictEqual(bytesToHex(tx.getTxId(hexToBytes(hex))), id);
      });
    }
  });

  describe('estimateExtraSize', () => {
    for (const fixture of constructFixtures) {
      it(`equals the extra size of ${fixture.label}`, () => {
        assert.strictEqual(tx.estimateExtraSize(fixture.params().outputs), fixture.decode().prefix.extra.length);
      });
    }

    // monero writes no nonce here; lib adds the dummy as monero-oxide does.
    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/wallet/src/send/tx.rs#L84-L96
    it('two standard recipients without change: public key and dummy payment id, 33 + 11 bytes', () => {
      assert.strictEqual(tx.estimateExtraSize([{ ...STANDARD, amount: 1n }, { ...OTHER_STANDARD, amount: 1n }]), 44);
    });
  });

  describe('fee estimation', () => {
    // estimateTxSize/estimateTxWeight/estimateFee flags: bulletproof, clsag, bulletproofPlus, useViewTags
    const BULLETPROOF_CLSAG = [true, true, false, false];
    const CASES = [
      {
        inputs: 1, outputs: 2, size: [1366, 1460], weight: [1366, 1460], fee: [10510000n, 11150000n],
      },
      {
        inputs: 2, outputs: 2, size: [1875, 1969], weight: [1875, 1969], fee: [15150000n, 15790000n],
      },
      {
        inputs: 3, outputs: 3, size: [2527, 2620], weight: [2987, 3157], fee: [23910000n, 25070000n],
      },
    ];

    for (const {
      inputs, outputs, size, weight, fee,
    } of CASES) {
      it(`${inputs} in ${outputs} out, with the defaults and with Bulletproof and CLSAG`, () => {
        assert.strictEqual(tx.estimateTxSize(inputs, 10, outputs, 44), size[0]);
        assert.strictEqual(tx.estimateTxSize(inputs, 10, outputs, 44, ...BULLETPROOF_CLSAG), size[1]);
        assert.strictEqual(tx.estimateTxWeight(inputs, 10, outputs, 44), weight[0]);
        assert.strictEqual(tx.estimateTxWeight(inputs, 10, outputs, 44, ...BULLETPROOF_CLSAG), weight[1]);
        assert.strictEqual(tx.estimateFee(inputs, 15, outputs, 44, 6836n, 1n, 10000n), fee[0]);
        assert.strictEqual(tx.estimateFee(inputs, 15, outputs, 44, 6836n, 1n, 10000n, ...BULLETPROOF_CLSAG), fee[1]);
      });
    }
  });
});
