import assert from 'node:assert';
import {
  bytesToHex, concatBytes, hexToBytes, utf8ToBytes,
} from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import * as clsag from '../lib/clsag.js';
import * as crypto from '../lib/crypto.js';
import * as helpers from '../lib/helpers.js';
import * as raw from '../lib/raw.js';
import * as ringct from '../lib/ringct.js';
import * as tx from '../lib/tx.js';
import * as wallet from '../lib/wallet.js';
import { address } from '../lib/address.js';

import { constructFixtures } from './helpers/construct.js';
import { fixedKeys } from './helpers/common.js';
// https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/wallet/src/tests/scan.rs#L119-L167
import scanVector from './fixtures/monero_oxide_scan.json' with { type: 'json' };
import zeroCommitments from './fixtures/zero_commitments.json' with { type: 'json' };
import { FUNCTIONAL_TESTS_WALLET, KNACCC_WALLET } from './helpers/wallets.js';

const coder = address('mainnet');
const MAIN = { major: 0, minor: 0 };
const KNACCC = wallet.keysFromSecretKeys(KNACCC_WALLET.secretSpendKey, KNACCC_WALLET.secretViewKey);
const KNACCC_VIEW_ONLY = wallet.viewOnlyKeys(KNACCC_WALLET.publicSpendKey, KNACCC_WALLET.secretViewKey);
const FUNCTIONAL = wallet.keysFromSecretKeys(
  FUNCTIONAL_TESTS_WALLET.secretSpendKey,
  FUNCTIONAL_TESTS_WALLET.secretViewKey
);

// One output of a construct_tx fixture in the TxOutput form that scanOutput takes.
function outputOf(fixture, decoded, index) {
  const vout = decoded.prefix.vout[index];
  return {
    txPublicKey: fixture.txKeys.txPublicKey,
    additionalTxPublicKey: fixture.txKeys.additionalTxPublicKeys[index],
    outputKey: vout.target.data.key,
    viewTag: vout.target.data.viewTag,
    index,
    rctType: decoded.rctSigBase.type,
    ecdhInfo: decoded.rctSigBase.ecdhInfo[index],
    outPk: decoded.rctSigBase.outPk[index],
  };
}

// x = keyOffset + b is the one-time secret of the output only if x*G is the output key.
function spendsOutputKey(keys, owned, outputKey) {
  const x = crypto.Fn.add(owned.keyOffset, helpers.decodeInt(keys.secretSpendKey));
  return bytesToHex(crypto.secretKeyToPublicKey(x)) === bytesToHex(outputKey);
}

// The subaddress table of account 0 with minor indexes 0..minors-1.
const lookup = (keys, minors = 1) => wallet.subaddressLookup(keys, 1, minors);

const pick = (object, fields) => Object.fromEntries(fields.map((field) => [field, object[field]]));

describe('wallet', () => {
  describe('keysFromSeed', () => {
    // wallet2 keeps a reduced seed as the spend key and derives the view key as Hs(b)
    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/functional_tests/wallet.py#L70-L93
    it('derives the keys and address of the monero functional tests wallet', () => {
      const keys = wallet.keysFromSeed(FUNCTIONAL_TESTS_WALLET.secretSpendKey);
      assert.deepStrictEqual(keys.secretSpendKey, FUNCTIONAL_TESTS_WALLET.secretSpendKey);
      assert.deepStrictEqual(keys.secretViewKey, FUNCTIONAL_TESTS_WALLET.secretViewKey);
      assert.strictEqual(wallet.getAddress(keys), FUNCTIONAL_TESTS_WALLET.address);
    });

    it('reduces a seed above the group order', () => {
      const keys = wallet.keysFromSeed(hexToBytes('ff'.repeat(32)));
      assert.deepStrictEqual(keys.secretSpendKey, hexToBytes('1c95988d7431ecd670cf7d73f45befc6feffffffffffffffffffffffffffff0f'));
      assert.deepStrictEqual(keys.publicSpendKey, hexToBytes('db27fe4b7a4beb8c1b8c38a21e943a852304c9bb3035a5f36626b51162a68f9c'));
      assert.deepStrictEqual(keys.secretViewKey, hexToBytes('9fe83aa6104612b587eb2e6ee1f0c929f85ce047804a789f4d579f9d2e20de0b'));
      assert.deepStrictEqual(keys.publicViewKey, hexToBytes('beb87b123ca0be6228ef692cecc4ba5170cc55f3987f08006dc638743776ebb3'));
    });
  });

  describe('keysFromSecretKeys', () => {
    it('derives the public keys of the knaccc wallet', () => {
      assert.deepStrictEqual(KNACCC.publicSpendKey, KNACCC_WALLET.publicSpendKey);
      assert.deepStrictEqual(KNACCC.publicViewKey, KNACCC_WALLET.publicViewKey);
    });

    it('derives public keys', () => {
      const keys = wallet.keysFromSecretKeys(
        hexToBytes('99095987370c530487be61900a4b167e4107ad39bb08b60256dc3c6a3e83ff03'),
        hexToBytes('21c7754089a21b4c326181f30c9616dce510e9007eaea65ef952b0a4de4bee0c')
      );
      assert.deepStrictEqual(keys.publicSpendKey, hexToBytes('3d5ac932714307e24e10971a93ed267de205768387c55e4a097def70dadadd11'));
      assert.deepStrictEqual(keys.publicViewKey, hexToBytes('181e4f7b6815c390b86db550b3f08b35e9b55931fc1215e4c97ee07d59d7e839'));
    });
  });

  describe('viewOnlyKeys', () => {
    it('derives the view public key of the knaccc wallet and has no secret spend key', () => {
      const keys = wallet.viewOnlyKeys(KNACCC_WALLET.publicSpendKey, KNACCC_WALLET.secretViewKey);
      assert.deepStrictEqual(keys.publicViewKey, KNACCC_WALLET.publicViewKey);
      assert.strictEqual(keys.secretSpendKey, undefined);
    });

    it('derives the view public key and has no secret spend key', () => {
      const keys = wallet.viewOnlyKeys(
        hexToBytes('74621fc98ad596d225e38f580836c85b50097c06bfba379599168bad649ec618'),
        hexToBytes('5fa548f256045ebe8e53f83554c106bbac2b34d9dacd040b6c5e0f96478bf005')
      );
      assert.deepStrictEqual(keys.publicViewKey, hexToBytes('cfda349dd1949862de366d070830c57bcbe1a53cbd8640016abde6f898abc273'));
      assert.strictEqual(keys.secretSpendKey, undefined);
    });
  });

  describe('getAddress', () => {
    it('gives the address of the knaccc and the monero functional tests wallets', () => {
      assert.strictEqual(wallet.getAddress(KNACCC), KNACCC_WALLET.address);
      assert.strictEqual(wallet.getAddress(FUNCTIONAL), FUNCTIONAL_TESTS_WALLET.address);
    });

    it('encodes the same keys for another network', () => {
      for (const nettype of ['testnet', 'stagenet']) {
        const { publicSpendKey, publicViewKey } = address(nettype).decode(wallet.getAddress(KNACCC, nettype));
        assert.deepStrictEqual([publicSpendKey, publicViewKey], [KNACCC.publicSpendKey, KNACCC.publicViewKey]);
      }
    });
  });

  describe('getSubaddress', () => {
    for (const [name, keys, { address: main, subaddresses }] of [
      ['knaccc', KNACCC, KNACCC_WALLET],
      ['knaccc view-only', KNACCC_VIEW_ONLY, KNACCC_WALLET],
      ['monero functional tests', FUNCTIONAL, FUNCTIONAL_TESTS_WALLET],
    ]) {
      it(`gives the subaddresses of the ${name} wallet`, () => {
        assert.strictEqual(wallet.getSubaddress(keys, MAIN), main);
        for (const { index, address: subaddress } of subaddresses) {
          assert.strictEqual(wallet.getSubaddress(keys, index), subaddress, `(${index.major}, ${index.minor})`);
        }
      });
    }

    it('gives subaddress (1, 1) of the knaccc wallet, full and view-only', () => {
      for (const keys of [KNACCC, KNACCC_VIEW_ONLY]) {
        assert.deepStrictEqual(coder.decode(wallet.getSubaddress(keys, { major: 1, minor: 1 })), {
          type: 'subaddress',
          publicSpendKey: hexToBytes('4a3e863f2a7a43f7fbaa0320e06982009f2986dd04173eaee32aa8473317f19d'),
          publicViewKey: hexToBytes('d247f90799916273407c1c71230d5ae0a9c71b8a7492da035e5e8ad972eea18b'),
        });
      }
    });
  });

  describe('getIntegratedAddress', () => {
    it('gives the integrated address of the monero functional tests wallet', () => {
      for (const { paymentID, address: integrated } of FUNCTIONAL_TESTS_WALLET.integratedAddresses) {
        assert.strictEqual(wallet.getIntegratedAddress(FUNCTIONAL, paymentID), integrated);
      }
    });

    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/wallet/address/src/tests.rs#L15-L18
    it('gives the integrated address of the monero-oxide vector for the knaccc wallet', () => {
      assert.strictEqual(
        wallet.getIntegratedAddress(KNACCC, hexToBytes('b8963a57855cf73f')),
        '4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbaTH6MnpXSn88oBX35'
      );
    });

    it('gives the integrated address of the knaccc wallet', () => {
      assert.strictEqual(
        wallet.getIntegratedAddress(KNACCC, hexToBytes('9d4d3c5cd422a218')),
        '4Ljin4CrSNHKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KbZRJmgNnw4d3pJGW3B'
      );
    });
  });

  describe('subaddressLookup', () => {
    it('maps the spend key of every monero functional tests subaddress to its index', () => {
      const lookup = wallet.subaddressLookup(FUNCTIONAL, 3, 1000);
      for (const { index, address: subaddress } of FUNCTIONAL_TESTS_WALLET.subaddresses) {
        assert.deepStrictEqual(lookup.get(bytesToHex(coder.decode(subaddress).publicSpendKey)), index);
      }
      assert.deepStrictEqual(lookup.get(bytesToHex(FUNCTIONAL.publicSpendKey)), MAIN);
    });

    // check_expected_max: the last index of the table is present, the next ones are not
    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/subaddress.cpp#L107-L117
    it('covers accounts 0..accounts-1 and minor indexes 0..count-1', () => {
      const lookup = wallet.subaddressLookup(FUNCTIONAL, 2, 2);
      const spendKey = ({ major, minor }) => {
        const subaddress = FUNCTIONAL_TESTS_WALLET.subaddresses
          .find(({ index }) => index.major === major && index.minor === minor);
        return bytesToHex(coder.decode(subaddress.address).publicSpendKey);
      };
      assert.strictEqual(lookup.size, 4);
      assert.deepStrictEqual(lookup.get(spendKey({ major: 1, minor: 1 })), { major: 1, minor: 1 });
      assert.strictEqual(lookup.get(spendKey({ major: 2, minor: 0 })), undefined);
      assert.strictEqual(lookup.get(spendKey({ major: 1, minor: 2 })), undefined);
    });
  });

  describe('scanOutput', () => {
    const fixture = constructFixtures[1]; // standard, subaddress with an additional key, change
    const decoded = fixture.decode();
    const [standard, subaddress] = fixture.outputs;

    // the output key and the commitment of the monero tx, and the key image x*Hp(P)
    const assertSpendMaterial = (owner, owned, index) => {
      const outputKey = decoded.prefix.vout[index].target.data.key;
      assert.ok(spendsOutputKey(owner, owned, outputKey));
      assert.deepStrictEqual(owned.publicKey, outputKey);
      assert.deepStrictEqual(owned.commitment, decoded.rctSigBase.outPk[index]);
      const x = crypto.Fn.add(owned.keyOffset, helpers.decodeInt(owner.secretSpendKey));
      assert.deepStrictEqual(owned.keyImage, crypto.generateKeyImage(outputKey, x));
    };

    it('finds an output to a main address with its amount and spend material', () => {
      const owned = wallet.scanOutput(standard.owner, outputOf(fixture, decoded, 0), lookup(standard.owner));
      assert.strictEqual(owned.amount, standard.amount);
      assert.deepStrictEqual(owned.subaddress, MAIN);
      assertSpendMaterial(standard.owner, owned, 0);
    });

    it('finds an output to a subaddress through its additional key', () => {
      const owned = wallet.scanOutput(subaddress.owner, outputOf(fixture, decoded, 1), lookup(subaddress.owner, 2));
      assert.strictEqual(owned.amount, subaddress.amount);
      assert.deepStrictEqual(owned.subaddress, subaddress.subaddress);
      assertSpendMaterial(subaddress.owner, owned, 1);
    });

    it('view-only: finds the amount and the key offset, but not the key image', () => {
      const viewOnly = wallet.viewOnlyKeys(standard.owner.publicSpendKey, standard.owner.secretViewKey);
      const owned = wallet.scanOutput(viewOnly, outputOf(fixture, decoded, 0), lookup(viewOnly));
      assert.strictEqual(owned.amount, standard.amount);
      assert.ok(spendsOutputKey(standard.owner, owned, decoded.prefix.vout[0].target.data.key));
      assert.strictEqual(owned.keyImage, undefined);
    });

    it('skips an output whose commitment does not match the encrypted amount', () => {
      const output = outputOf(fixture, decoded, 0);
      const outPk = output.outPk.slice();
      outPk[0] ^= 1;
      assert.strictEqual(wallet.scanOutput(standard.owner, { ...output, outPk }, lookup(standard.owner)), null);
    });

    it('skips an output whose view tag does not match', () => {
      const output = outputOf(fixture, decoded, 0);
      const viewTag = output.viewTag ^ 0xff;
      assert.strictEqual(wallet.scanOutput(standard.owner, { ...output, viewTag }, lookup(standard.owner)), null);
    });

    it('skips an output to a subaddress outside the lookup table', () => {
      const output = outputOf(fixture, decoded, 1);
      assert.strictEqual(wallet.scanOutput(subaddress.owner, output, lookup(subaddress.owner)), null);
    });

    it('uses a given primary derivation', () => {
      const output = outputOf(fixture, decoded, 0);
      const secretViewKey = helpers.decodeInt(standard.owner.secretViewKey);
      const derivation = crypto.generateKeyDerivation(output.txPublicKey, secretViewKey);
      const withoutTxKey = { ...output, txPublicKey: undefined };
      const owned = wallet.scanOutput(standard.owner, withoutTxKey, lookup(standard.owner), derivation);
      assert.strictEqual(owned.amount, standard.amount);
    });

    it('does not compute the additional-key derivation when the primary matches', () => {
      // reading any byte of the additional key means its derivation was computed; an eager scan would
      let additionalRead = false;
      const additionalTxPublicKey = new Proxy(fixture.txKeys.additionalTxPublicKeys[0], {
        get(target, prop, receiver) {
          additionalRead = true;
          return Reflect.get(target, prop, receiver);
        },
      });
      const output = { ...outputOf(fixture, decoded, 0), additionalTxPublicKey };
      const owned = wallet.scanOutput(standard.owner, output, lookup(standard.owner));
      assert.strictEqual(owned.amount, standard.amount);
      assert.strictEqual(additionalRead, false);
    });

    it('finds a coinbase output: cleartext amount, mask 1, zero commitment', () => {
      const { amount, commitment } = zeroCommitments.commitments.find((entry) => entry.amount === '600000000000');
      const derivation = crypto.generateKeyDerivation(KNACCC.publicViewKey, 17n);
      const outputKey = crypto.derivePublicKey(derivation, 0, KNACCC.publicSpendKey);
      const owned = wallet.scanOutput(KNACCC, {
        txPublicKey: crypto.secretKeyToPublicKey(17n),
        outputKey,
        index: 0,
        rctType: ringct.RCTTypes.Null,
        amount: BigInt(amount),
      }, lookup(KNACCC));
      assert.strictEqual(owned.amount, BigInt(amount));
      assert.strictEqual(owned.mask, 1n);
      assert.deepStrictEqual(owned.commitment, hexToBytes(commitment));
      assert.ok(spendsOutputKey(KNACCC, owned, outputKey));
    });
  });

  describe('isMature', () => {
    it('regular output needs DEFAULT_SPENDABLE_AGE (10) confirmations', () => {
      assert.strictEqual(wallet.isMature({ height: 100 }, 109), false);
      assert.strictEqual(wallet.isMature({ height: 100 }, 110), true);
    });

    it('coinbase output needs COINBASE_UNLOCK_WINDOW (60) confirmations', () => {
      assert.strictEqual(wallet.isMature({ height: 100, isCoinbase: true }, 159), false);
      assert.strictEqual(wallet.isMature({ height: 100, isCoinbase: true }, 160), true);
    });
  });

  describe('scanTransaction', () => {
    for (const fixture of constructFixtures) {
      it(`finds the outputs of every owner and the spent key images: ${fixture.label}`, () => {
        const decoded = fixture.decode();
        const owners = new Map();
        for (const output of fixture.outputs) {
          const id = bytesToHex(output.owner.secretViewKey);
          owners.set(id, [...(owners.get(id) ?? []), output]);
        }
        for (const outputs of owners.values()) {
          const { owner } = outputs[0];
          const result = wallet.scanTransaction(owner, decoded, lookup(owner, 2));
          const fields = ['index', 'amount', 'subaddress'];
          const found = result.outputs.map((owned) => pick(owned, fields));
          assert.deepStrictEqual(found, outputs.map((output) => pick(output, fields)));
          for (const owned of result.outputs) {
            assert.ok(spendsOutputKey(owner, owned, decoded.prefix.vout[owned.index].target.data.key));
          }
          assert.deepStrictEqual(result.spentKeyImages, decoded.prefix.vin.map((vin) => vin.data.keyImage));
        }
        assert.deepStrictEqual(wallet.scanTransaction(KNACCC, decoded, lookup(KNACCC, 2)).outputs, []);
      });
    }

    it('decrypts the payment id of an integrated address', () => {
      const isIntegrated = (output) => output.type === 'integratedaddress';
      const fixture = constructFixtures.find(({ outputs }) => outputs.some(isIntegrated));
      const integrated = fixture.outputs.find(isIntegrated);
      const [owned] = wallet.scanTransaction(integrated.owner, fixture.decode(), lookup(integrated.owner)).outputs;
      assert.deepStrictEqual(owned.paymentId, integrated.paymentID);
    });

    it('decrypts the zero dummy payment id for the recipient', () => {
      const fixture = constructFixtures[0];
      const { owner } = fixture.outputs[0];
      const [owned] = wallet.scanTransaction(owner, fixture.decode(), lookup(owner)).outputs;
      assert.deepStrictEqual(owned.paymentId, new Uint8Array(8));
    });

    // the 2016 cold-signing bug wrote a stray tx public key field before the real one
    it('finds an output paid through the second of two tx public keys', () => {
      const fixture = constructFixtures[0];
      const { owner, amount } = fixture.outputs[0];
      const decoded = fixture.decode();
      decoded.prefix.extra = concatBytes(Uint8Array.of(1), KNACCC.publicSpendKey, decoded.prefix.extra);
      const { outputs } = wallet.scanTransaction(owner, decoded, lookup(owner));
      assert.deepStrictEqual(outputs.map((output) => [output.amount, output.paymentId]), [[amount, new Uint8Array(8)]]);
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/wallet/wallet2.cpp#L2860-L2885
    it('keeps an output found through an additional key when the payment id cannot be decrypted', () => {
      const fixture = constructFixtures[1];
      const {
        owner, index, amount,
      } = fixture.outputs[1];
      const decoded = fixture.decode();
      decoded.prefix.extra = tx.buildTxExtra({
        txPublicKey: new Uint8Array(32).fill(0xff),
        additionalTxPublicKeys: fixture.txKeys.additionalTxPublicKeys,
        encryptedPaymentId: new Uint8Array(8),
      });
      const { outputs } = wallet.scanTransaction(owner, decoded, lookup(owner, 2));
      const found = outputs.map((output) => [output.index, output.amount, output.paymentId]);
      assert.deepStrictEqual(found, [[index, amount, undefined]]);
    });

    // https://github.com/monero-oxide/monero-oxide/blob/0.1.0/monero-oxide/wallet/src/scan.rs#L127-L130
    it('finds no outputs in a version 1 transaction', () => {
      const fixture = constructFixtures[0];
      const { owner } = fixture.outputs[0];
      const decoded = fixture.decode();
      decoded.prefix.version = 1;
      assert.deepStrictEqual(wallet.scanTransaction(owner, decoded, lookup(owner)).outputs, []);
    });

    it('spends a scanned output with a non-zero spend key, signing against the real output key', () => {
      const fixture = constructFixtures[1];
      const { owner } = fixture.outputs[0];
      const [owned] = wallet.scanTransaction(owner, fixture.decode(), lookup(owner)).outputs;
      const { decoys } = fixture.inputs[0];
      const input = {
        ...owned, globalIndex: 5000n, decoys,
      };
      const { bytes } = tx.createTransaction({
        inputs: [input],
        outputs: [{ ...coder.decode(KNACCC_WALLET.address), amount: 1000000n }, wallet.changeOutput(owner, 990000n)],
        secretSpendKey: helpers.decodeInt(owner.secretSpendKey),
        secretViewKey: helpers.decodeInt(owner.secretViewKey),
      });
      const spend = raw.fullTransaction.decode(bytes);
      const [vin] = spend.prefix.vin;

      // the key image of the spend is the one that scanOutput computed, so x = keyOffset + b
      assert.deepStrictEqual(vin.data.keyImage, owned.keyImage);

      // the CLSAG verifies against the ring that holds the scanned output key and commitment
      const ring = [input, ...decoys]
        .sort((a, b) => (a.globalIndex < b.globalIndex ? -1 : 1))
        .map(({ publicKey, commitment }) => ({ publicKey, commitment }));
      const [proof] = spend.rctSigPrunable.bulletproofsPlus;
      const message = tx.getPreMlsagHash(crypto.fastHash(raw.txPrefix.encode(spend.prefix)), spend.rctSigBase, proof);
      const signature = { ...spend.rctSigPrunable.CLSAGs[0], I: vin.data.keyImage };
      assert.ok(clsag.verifyClsag(message, ring, spend.rctSigPrunable.pseudoOuts[0], signature));
    });

    it('scans the pruned RCTTypeFull vector of monero-oxide', () => {
      const keys = wallet.keysFromSecretKeys(
        hexToBytes(scanVector.secretSpendKey),
        hexToBytes(scanVector.secretViewKey)
      );
      const decoded = raw.prunedTransaction.decode(hexToBytes(scanVector.hex));
      const { outputs } = wallet.scanTransaction(keys, decoded, lookup(keys));
      const expected = scanVector.outputs.map((output) => ({
        index: output.index,
        amount: BigInt(output.amount),
        mask: helpers.decodeInt(hexToBytes(output.mask)),
        keyOffset: helpers.decodeInt(hexToBytes(output.keyOffset)),
        paymentId: new Uint8Array(8),
      }));
      const fields = ['index', 'amount', 'mask', 'keyOffset', 'paymentId'];
      assert.deepStrictEqual(outputs.map((output) => pick(output, fields)), expected);
    });
  });

  describe('createTransaction', () => {
    const BASE_FEE = 100n;
    const FEE_QUANTIZATION = 10000n;
    // one input of 5010000, spendable with the sender keys of the construct_tx fixtures
    const ONE_INPUT = constructFixtures[1].params().inputs;
    const SENDER = constructFixtures[1].sender;
    const recipientOf = (str) => coder.decode(str);
    const toKnaccc = (amount) => ({ ...recipientOf(KNACCC_WALLET.address), amount });
    const SUBADDRESS = FUNCTIONAL_TESTS_WALLET.subaddresses
      .find(({ index }) => index.major === 0 && index.minor === 1).address;
    const paramsOf = (outputs, options = {}) => ({
      inputs: ONE_INPUT, outputs, keys: SENDER, baseFee: BASE_FEE, feeQuantization: FEE_QUANTIZATION, ...options,
    });

    // monero multisig tx key derivation, with our own domain tags
    // https://github.com/monero-project/monero/blob/v0.18.5.1/src/multisig/multisig_tx_builder_ringct.cpp#L247-L301
    const txKeyGenerator = (secret, keyImages) => {
      const seed = crypto.fastHash(concatBytes(crypto.fastHash(utf8ToBytes('tx_secret_keys_seed')), secret, ...keyImages));
      let previous = crypto.fastHash(utf8ToBytes('tx_secret_keys'));
      return () => {
        const key = crypto.hashToScalar(seed, previous);
        previous = helpers.encodeInt(key);
        return key;
      };
    };

    it('changeOutput and dummyOutput shapes', () => {
      const change = wallet.changeOutput(KNACCC, 123n);
      assert.strictEqual(change.type, 'address');
      assert.strictEqual(change.isChange, true);
      assert.strictEqual(change.amount, 123n);
      assert.deepStrictEqual(change.publicSpendKey, KNACCC.publicSpendKey);

      const dummy = wallet.dummyOutput();
      assert.strictEqual(dummy.type, 'address');
      assert.strictEqual(dummy.isChange, true);
      assert.strictEqual(dummy.amount, 0n);
      assert.strictEqual(dummy.publicSpendKey.length, 32);
      assert.notDeepEqual(dummy.publicSpendKey, wallet.dummyOutput().publicSpendKey); // random each call
    });

    it('appends a change output the wallet can scan', () => {
      const {
        transaction: decoded, bytes, txKeys: { txSecretKey, additionalTxSecretKeys },
      } = wallet.createTransaction(paramsOf([toKnaccc(1000000n)]));
      assert.ok(txSecretKey instanceof Uint8Array);
      assert.equal(txSecretKey.length, 32);
      assert.deepStrictEqual(additionalTxSecretKeys, []);
      const txPublicKey = crypto.secretKeyToPublicKey(helpers.decodeInt(txSecretKey));
      assert.deepStrictEqual(tx.parseTxExtra(decoded.prefix.extra).txPublicKeys, [txPublicKey]);
      assert.deepStrictEqual(bytes, raw.fullTransaction.encode(decoded));
      assert.strictEqual(decoded.prefix.vout.length, 2);
      const found = wallet.scanTransaction(SENDER, decoded, lookup(SENDER)).outputs;
      const change = ONE_INPUT[0].amount - 1000000n - decoded.rctSigBase.txnFee;
      assert.deepStrictEqual(found.map((output) => output.amount), [change]);
    });

    it('pads a single-subaddress send to two outputs with a dummy, extra not inflated', () => {
      const sub = recipientOf(SUBADDRESS);
      // exact funds: the input pays the recipient and the two-output fee, so no change is left and a dummy is added
      const extraSize = tx.estimateExtraSize([{ ...sub, amount: 1n }, { isChange: true }]);
      const fee = tx.estimateFee(1, 15, 2, extraSize, BASE_FEE, 1n, FEE_QUANTIZATION);
      const recipientAmount = ONE_INPUT[0].amount - fee;
      const suppliedKey = helpers.encodeInt(17n);
      const outputs = [{ ...sub, amount: recipientAmount }];
      const {
        transaction: decoded, txKeys: { txSecretKey, additionalTxSecretKeys }, destinations,
      } = wallet.createTransaction(paramsOf(outputs, { generateTxSecretKey: fixedKeys([suppliedKey]) }));
      assert.strictEqual(decoded.prefix.vout.length, 2);
      assert.strictEqual(decoded.prefix.extra.length, 44); // the dummy counts as change: no additional keys
      assert.strictEqual(decoded.rctSigBase.txnFee, fee);
      assert.deepStrictEqual(txSecretKey, suppliedKey);
      assert.deepStrictEqual(additionalTxSecretKeys, []);
      const R = crypto.encodePoint(crypto.decodePoint(sub.publicSpendKey).multiply(17n));
      assert.deepStrictEqual(tx.parseTxExtra(decoded.prefix.extra).txPublicKeys, [R]);
      const found = wallet.scanTransaction(FUNCTIONAL, decoded, lookup(FUNCTIONAL, 2)).outputs;
      assert.deepStrictEqual(found.map((output) => output.amount), [recipientAmount]);
      assert.strictEqual(destinations[found[0].index].isChange, undefined);
      const changes = destinations.filter((destination) => destination.isChange);
      assert.deepStrictEqual(changes.map((destination) => destination.amount), [0n]);
    });

    it('returns the destinations in output order, with the change marked', () => {
      const addresses = [KNACCC_WALLET.address, FUNCTIONAL_TESTS_WALLET.address];
      const outputs = addresses.map((str, i) => ({ ...recipientOf(str), amount: BigInt(i + 1) * 1000000n }));
      const snapshot = structuredClone(outputs);
      const {
        transaction: decoded, txKeys, destinations,
      } = wallet.createTransaction(paramsOf(outputs));
      assert.strictEqual(destinations.length, decoded.prefix.vout.length);
      const recipients = wallet.checkTxKey(decoded, txKeys, addresses);
      assert.strictEqual(recipients.length, 2);
      for (const { index, ...recipient } of recipients) {
        assert.ok(!destinations[index].isChange);
        assert.strictEqual(destinations[index].amount, recipient.amount);
        assert.strictEqual(coder.encode(destinations[index]), recipient.destination);
      }
      const owned = wallet.scanTransaction(SENDER, decoded, lookup(SENDER)).outputs;
      assert.strictEqual(owned.length, 1);
      assert.strictEqual(destinations[owned[0].index].isChange, true);
      assert.strictEqual(destinations[owned[0].index].amount, owned[0].amount);
      assert.deepStrictEqual(outputs, snapshot);
    });

    describe('tx keys from a caller generator', () => {
      // two inputs of 2000000 and 3000000, and the vin key images that monero computed for them
      const fixture = constructFixtures[0];
      const { inputs } = fixture.params();
      const keyImages = fixture.decode().prefix.vin.map((vin) => vin.data.keyImage);
      const addresses = [KNACCC_WALLET.address, SUBADDRESS]; // a subaddress needs additional keys
      const amounts = [1000000n, 2000000n];
      const outputs = () => [
        ...addresses.map((str, i) => ({ ...recipientOf(str), amount: amounts[i] })),
        wallet.changeOutput(SENDER, 1990000n),
      ];
      const secretKeys = {
        secretSpendKey: helpers.decodeInt(SENDER.secretSpendKey),
        secretViewKey: helpers.decodeInt(SENDER.secretViewKey),
      };
      const recover = (decoded) => {
        const nextTxKey = txKeyGenerator(SENDER.secretSpendKey, decoded.prefix.vin.map((vin) => vin.data.keyImage));
        const { additionalTxPublicKeys } = tx.parseTxExtra(decoded.prefix.extra);
        return {
          txSecretKey: helpers.encodeInt(nextTxKey()),
          additionalTxSecretKeys: additionalTxPublicKeys.map(() => helpers.encodeInt(nextTxKey())),
        };
      };

      it('recovers the tx keys from the parsed tx and finds every recipient', () => {
        const generateTxSecretKey = txKeyGenerator(SENDER.secretSpendKey, keyImages);
        const { bytes, destinations } = tx.createTransaction({
          inputs, outputs: outputs(), ...secretKeys, generateTxSecretKey,
        });
        const decoded = raw.fullTransaction.decode(bytes);
        const extra = tx.parseTxExtra(decoded.prefix.extra);
        const txKeys = recover(decoded);
        assert.equal(extra.additionalTxPublicKeys.length, 3);
        const txPublicKey = crypto.secretKeyToPublicKey(helpers.decodeInt(txKeys.txSecretKey));
        assert.deepStrictEqual(extra.txPublicKeys, [txPublicKey]);
        const additionalTxPublicKeys = txKeys.additionalTxSecretKeys.map((key, i) => {
          const s = helpers.decodeInt(key);
          return destinations[i].type === 'subaddress'
            ? crypto.encodePoint(crypto.decodePoint(destinations[i].publicSpendKey).multiply(s))
            : crypto.secretKeyToPublicKey(s);
        });
        assert.deepStrictEqual(extra.additionalTxPublicKeys, additionalTxPublicKeys);
        assert.deepStrictEqual(
          wallet.checkTxKey(decoded, txKeys, addresses).map(({ destination, amount }) => [destination, amount]).sort(),
          addresses.map((destination, i) => [destination, amounts[i]]).sort()
        );
        const change = wallet.scanTransaction(SENDER, decoded, lookup(SENDER)).outputs;
        assert.deepStrictEqual(change.map((output) => output.amount), [1990000n]);
      });

      it('finds no recipient with generator keys in a tx built with random keys', () => {
        const { bytes } = tx.createTransaction({
          inputs, outputs: outputs(), ...secretKeys,
        });
        const decoded = raw.fullTransaction.decode(bytes);
        assert.deepStrictEqual(wallet.checkTxKey(decoded, recover(decoded), addresses), []);
      });
    });

    for (const supplied of [false, true]) {
      it(`returns ${supplied ? 'supplied' : 'generated'} byte keys for mixed recipients and change`, () => {
        const sub = recipientOf(SUBADDRESS);
        const params = paramsOf([toKnaccc(1000000n), { ...sub, amount: 2000000n }], { shuffleOutputs: false });
        const suppliedKeys = [17n, 19n, 23n, 29n].map(helpers.encodeInt);
        const generateTxSecretKey = supplied ? fixedKeys(suppliedKeys) : undefined;
        const result = wallet.createTransaction({ ...params, generateTxSecretKey });
        assert.deepStrictEqual(Object.keys(result).sort(), ['bytes', 'destinations', 'transaction', 'txKeys']);
        assert.ok(result.txKeys.txSecretKey instanceof Uint8Array);
        assert.equal(result.txKeys.txSecretKey.length, 32);
        assert.equal(result.txKeys.additionalTxSecretKeys.length, 3);
        if (supplied) {
          assert.deepStrictEqual(result.txKeys.txSecretKey, suppliedKeys[0]);
          assert.deepStrictEqual(result.txKeys.additionalTxSecretKeys, suppliedKeys.slice(1));
          const repeated = wallet.createTransaction({ ...params, generateTxSecretKey: fixedKeys(suppliedKeys) });
          assert.deepStrictEqual(repeated.txKeys, result.txKeys);
          assert.deepStrictEqual(repeated.transaction.prefix, result.transaction.prefix);
          assert.deepStrictEqual(repeated.transaction.rctSigBase, result.transaction.rctSigBase);
        }
        const decoded = raw.fullTransaction.decode(result.bytes);
        assert.deepStrictEqual(decoded, result.transaction);
        const extra = tx.parseTxExtra(decoded.prefix.extra);
        assert.deepStrictEqual(extra.txPublicKeys, [result.txKeys.txPublicKey]);
        assert.deepStrictEqual(extra.additionalTxPublicKeys, result.txKeys.additionalTxPublicKeys);
        const txPublicKey = crypto.secretKeyToPublicKey(helpers.decodeInt(result.txKeys.txSecretKey));
        assert.deepStrictEqual(extra.txPublicKeys, [txPublicKey]);
        result.txKeys.additionalTxSecretKeys.forEach((key, i) => {
          const s = helpers.decodeInt(key);
          const expected = i === 1
            ? crypto.encodePoint(crypto.decodePoint(sub.publicSpendKey).multiply(s))
            : crypto.secretKeyToPublicKey(s);
          assert.deepStrictEqual(extra.additionalTxPublicKeys[i], expected);
        });
        [KNACCC, FUNCTIONAL, SENDER].forEach((owner, i) => {
          const found = wallet.scanTransaction(owner, decoded, lookup(owner, 2)).outputs;
          assert.deepStrictEqual(found.map((output) => output.index), [i]);
          const change = ONE_INPUT[0].amount - 3000000n - decoded.rctSigBase.txnFee;
          assert.equal(found[0].amount, i === 2 ? change : params.outputs[i].amount);
        });
      });
    }

    it('rejects a generator that does not return a 32-byte Uint8Array', () => {
      for (const key of [new Uint8Array(31), new Uint8Array(33), 17n]) {
        assert.throws(() => {
          wallet.createTransaction(paramsOf([toKnaccc(1000000n)], { generateTxSecretKey: fixedKeys([key]) }));
        }, /tx secret key/);
      }
    });

    it('throws when the inputs cannot cover the outputs and the fee', () => {
      assert.throws(() => {
        wallet.createTransaction(paramsOf([toKnaccc(ONE_INPUT[0].amount)]));
      }, /not enough funds/);
    });
  });

  describe('checkTxKey', () => {
    // shuffleOutputs is false in every fixture, so vout[i] is outputs[i]
    const recipientsOf = (fixture) => fixture.outputs.filter((output) => !output.isChange);

    for (const fixture of constructFixtures) {
      it(`finds every recipient: ${fixture.label}`, () => {
        const recipients = recipientsOf(fixture);
        const found = wallet.checkTxKey(fixture.decode(), fixture.txKeys, recipients.map((output) => output.address));
        const expected = recipients.map((output) => ({
          index: output.index,
          destination: output.address,
          amount: output.amount,
        }));
        assert.deepStrictEqual(found.map((recipient) => pick(recipient, ['index', 'destination', 'amount'])), expected);
      });
    }

    const mixed = constructFixtures[1]; // standard + subaddress, with additional keys
    const [standard, subaddress] = mixed.outputs.map((output) => output.address);
    const { txSecretKey, additionalTxSecretKeys } = mixed.txKeys;
    const indexes = (found) => found.map(({ index, destination }) => ({ index, destination }));

    it('without the tx secret key finds only the additional-key subaddress output', () => {
      const found = wallet.checkTxKey(mixed.decode(), { additionalTxSecretKeys }, [standard, subaddress]);
      assert.deepStrictEqual(indexes(found), [{ index: 1, destination: subaddress }]);
    });

    it('without additional keys finds only the standard output', () => {
      const found = wallet.checkTxKey(mixed.decode(), { txSecretKey }, [standard, subaddress]);
      assert.deepStrictEqual(indexes(found), [{ index: 0, destination: standard }]);
    });

    it('accepts a short additional key list', () => {
      const txKeys = { txSecretKey, additionalTxSecretKeys: additionalTxSecretKeys.slice(0, 1) };
      const found = wallet.checkTxKey(mixed.decode(), txKeys, [standard, subaddress]);
      assert.deepStrictEqual(found.map(({ index }) => index), [0]);
    });

    it('keeps additional keys at their vout index when entries are missing', () => {
      const [, key1] = additionalTxSecretKeys;
      // eslint-disable-next-line no-sparse-arrays
      for (const keys of [[undefined, key1, null], [null, key1], [, key1]]) {
        const txKeys = { txSecretKey: null, additionalTxSecretKeys: keys };
        const found = wallet.checkTxKey(mixed.decode(), txKeys, [standard, subaddress]);
        assert.deepStrictEqual(indexes(found), [{ index: 1, destination: subaddress }]);
      }
    });

    it('checks only the given addresses', () => {
      const found = wallet.checkTxKey(mixed.decode(), mixed.txKeys, [subaddress]);
      assert.deepStrictEqual(indexes(found), [{ index: 1, destination: subaddress }]);
    });

    it('keeps a matched recipient without an amount when the amount does not decode', () => {
      const decoded = mixed.decode();
      decoded.rctSigBase.ecdhInfo[0].amount = new Uint8Array(8).fill(0xff);
      delete decoded.rctSigBase.outPk[1];
      const found = wallet.checkTxKey(decoded, mixed.txKeys, [standard, subaddress]);
      assert.deepStrictEqual(found, [{ index: 0, destination: standard }, { index: 1, destination: subaddress }]);
    });

    it('continues after a malformed output key', () => {
      const decoded = mixed.decode();
      decoded.prefix.vout[0].target.data.key = new Uint8Array(32).fill(0xff);
      const found = wallet.checkTxKey(decoded, mixed.txKeys, [standard, subaddress]);
      assert.deepStrictEqual(found.map(({ index, amount }) => ({ index, amount })), [{ index: 1, amount: 2000000n }]);
    });

    it('has no amount, not 0n, for a v2 tx without its RingCT base', () => {
      const decoded = mixed.decode();
      delete decoded.rctSigBase;
      const found = wallet.checkTxKey(decoded, mixed.txKeys, [standard, subaddress]);
      assert.deepStrictEqual(found, [{ index: 0, destination: standard }, { index: 1, destination: subaddress }]);
    });

    // check_tx_key with an all-zero tx key reports no received amount
    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/functional_tests/proofs.py#L117-L120
    it('finds nothing with an all-zero tx key', () => {
      const found = wallet.checkTxKey(mixed.decode(), { txSecretKey: new Uint8Array(32) }, [standard, subaddress]);
      assert.deepStrictEqual(found, []);
    });

    it('returns nothing for bad or missing data without throwing', () => {
      const decoded = mixed.decode();
      const stagenet = address('stagenet').encode(coder.decode(standard));
      const badPoint = coder.encode({
        type: 'address', publicSpendKey: new Uint8Array(32).fill(0xff), publicViewKey: new Uint8Array(32).fill(0xff),
      });
      const others = [KNACCC_WALLET.address, 'not an address', stagenet, badPoint];
      assert.deepStrictEqual(wallet.checkTxKey(decoded, mixed.txKeys, others), []);
      assert.deepStrictEqual(wallet.checkTxKey(decoded, {}, [standard, subaddress]), []);
      const badKey = { txSecretKey: new Uint8Array(32).fill(0xff) };
      assert.deepStrictEqual(wallet.checkTxKey(decoded, badKey, [standard]), []);
      assert.deepStrictEqual(wallet.checkTxKey(decoded, mixed.txKeys, []), []);
    });
  });

  describe('annotateTransaction', () => {
    const mixed = constructFixtures[1];
    const decodedTx = mixed.decode();
    const keys = mixed.sender;
    const subaddresses = wallet.subaddressLookup(keys, 1, 1);
    const { txKeys } = mixed;
    const destinations = mixed.outputs.filter((output) => !output.isChange).map((output) => output.address);

    it('marks recipients and the change', () => {
      const { prefix } = wallet.annotateTransaction(decodedTx, {
        keys, subaddresses, txKeys, destinations,
      });
      assert.deepStrictEqual(prefix.vout.map((vout) => vout.recipient?.destination), [...destinations, undefined]);
      assert.deepStrictEqual(prefix.vout.map((vout) => vout.recipient?.amount), [2000000n, 2000000n, undefined]);
      assert.deepStrictEqual(prefix.vout.map((vout) => vout.owned?.amount), [undefined, undefined, 1000000n]);
      assert.deepStrictEqual(prefix.vout[2].owned.subaddress, MAIN);
    });

    it('keeps the transaction unchanged without data and does not mutate the input', () => {
      const before = structuredClone(decodedTx);
      assert.deepStrictEqual(wallet.annotateTransaction(decodedTx), decodedTx);
      wallet.annotateTransaction(decodedTx, {
        keys, subaddresses, txKeys, destinations,
      });
      assert.deepStrictEqual(decodedTx, before);
    });

    it('accumulates annotations over calls and keeps a decoded amount', () => {
      const withOwned = wallet.annotateTransaction(decodedTx, { keys, subaddresses });
      const full = wallet.annotateTransaction(withOwned, { txKeys, destinations });
      assert.deepStrictEqual(full, wallet.annotateTransaction(decodedTx, {
        keys, subaddresses, txKeys, destinations,
      }));
      assert.deepStrictEqual(wallet.annotateTransaction(full), full);

      const withoutBase = structuredClone(full);
      delete withoutBase.rctSigBase;
      const again = wallet.annotateTransaction(withoutBase, { txKeys, destinations });
      assert.deepStrictEqual(again.prefix.vout, full.prefix.vout);
    });

    it('adds the amount to a recipient found earlier without it', () => {
      const withoutBase = structuredClone(decodedTx);
      delete withoutBase.rctSigBase;
      const partial = wallet.annotateTransaction(withoutBase, { txKeys, destinations });
      assert.deepStrictEqual(partial.prefix.vout[0].recipient, { index: 0, destination: destinations[0] });
      const withBase = { ...partial, rctSigBase: decodedTx.rctSigBase };
      const restored = wallet.annotateTransaction(withBase, { txKeys, destinations });
      assert.strictEqual(restored.prefix.vout[0].recipient.amount, 2000000n);
    });

    it('annotates a pruned transaction the same way', () => {
      const pruned = raw.prunedTransaction.decode(raw.prunedTransaction.encode(decodedTx));
      const params = {
        keys, subaddresses, txKeys, destinations,
      };
      const fromPruned = wallet.annotateTransaction(pruned, params).prefix.vout;
      assert.deepStrictEqual(fromPruned, wallet.annotateTransaction(decodedTx, params).prefix.vout);
    });
  });

  describe('isOwnKeyImage', () => {
    it('is true for the vin key images of monero construct_tx', () => {
      for (const fixture of constructFixtures) {
        const keyImages = fixture.decode().prefix.vin.map((vin) => vin.data.keyImage);
        for (const input of fixture.inputs) {
          const output = {
            txPublicKey: input.prevTxPublicKey, index: input.prevOutputIndex, subaddress: MAIN,
          };
          const own = keyImages.filter((keyImage) => wallet.isOwnKeyImage(fixture.sender, output, keyImage));
          assert.strictEqual(own.length, 1, fixture.label);
        }
      }
    });

    it('is false for the key image of another output', () => {
      const fixture = constructFixtures[0];
      const [input] = fixture.inputs;
      const output = {
        txPublicKey: input.prevTxPublicKey, index: input.prevOutputIndex, subaddress: MAIN,
      };
      // the vin of the monero-oxide scan vector spends an output of another wallet
      const otherKeyImage = raw.prunedTransaction.decode(hexToBytes(scanVector.hex)).prefix.vin[0].data.keyImage;
      assert.strictEqual(wallet.isOwnKeyImage(KNACCC, output, otherKeyImage), false);
      assert.strictEqual(wallet.isOwnKeyImage(fixture.sender, output, otherKeyImage), false);
    });

    describe('subaddress output of a mixed transaction', () => {
      const fixture = constructFixtures[1];
      const decoded = fixture.decode();
      const output = fixture.outputs[1];
      const { owner } = output;
      const outputKey = decoded.prefix.vout[1].target.data.key;
      const a = helpers.decodeInt(owner.secretViewKey);
      const d = crypto.subaddressSecretSpendKey(a, helpers.decodeInt(owner.secretSpendKey), output.subaddress);
      const derivation = crypto.generateKeyDerivation(fixture.txKeys.additionalTxPublicKeys[1], a);
      const x = crypto.deriveSecretKey(derivation, 1, d);
      const keyImage = crypto.generateKeyImage(outputKey, x);

      it('the expected one-time secret spends the monero output key', () => {
        assert.deepStrictEqual(crypto.secretKeyToPublicKey(x), outputKey);
      });

      it('uses the additional tx public key', () => {
        const ownedOutput = {
          txPublicKey: fixture.txKeys.txPublicKey,
          additionalTxPublicKey: fixture.txKeys.additionalTxPublicKeys[1],
          index: 1,
          subaddress: output.subaddress,
        };
        assert.strictEqual(wallet.isOwnKeyImage(owner, ownedOutput, keyImage), true);
      });
    });

    it('matches through the primary key despite a malformed additional public key', () => {
      const fixture = constructFixtures[1];
      const [input] = fixture.inputs;
      const [keyImage] = fixture.decode().prefix.vin.map((vin) => vin.data.keyImage);
      const output = {
        txPublicKey: input.prevTxPublicKey,
        additionalTxPublicKey: new Uint8Array(32).fill(0xff),
        index: input.prevOutputIndex,
        subaddress: MAIN,
      };
      assert.strictEqual(wallet.isOwnKeyImage(fixture.sender, output, keyImage), true);
    });
  });
});
