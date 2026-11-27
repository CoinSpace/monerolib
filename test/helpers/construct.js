import { hexToBytes } from '@noble/hashes/utils.js';

import * as crypto from '../../lib/crypto.js';
import * as raw from '../../lib/raw.js';
import * as wallet from '../../lib/wallet.js';
import { address } from '../../lib/address.js';
import { decodeInt } from '../../lib/helpers.js';

import fixtures from '../fixtures/construct_txs.json' with { type: 'json' };

const scalar = (hex) => decodeInt(hexToBytes(hex));

const ringMember = (member) => ({
  publicKey: hexToBytes(member.publicKey),
  commitment: hexToBytes(member.commitment),
  globalIndex: BigInt(member.globalIndex),
});

/**
 * Transactions built by monero v0.18.5.1 construct_tx, with every construction input and the
 * secret keys of every output owner. Values are converted once here, so tests use lib types.
 */
export const constructFixtures = fixtures.map(({
  label, hex, id, construct,
}) => {
  const inputs = construct.inputs.map((input) => ({
    keyOffset: scalar(input.keyOffset),
    publicKey: hexToBytes(input.publicKey),
    amount: BigInt(input.amount),
    mask: scalar(input.mask),
    commitment: hexToBytes(input.commitment),
    globalIndex: BigInt(input.globalIndex),
    decoys: input.decoys.map(ringMember),
    prevTxPublicKey: hexToBytes(input.prevTxPublicKey),
    prevOutputIndex: Number(input.prevOutputIndex),
  }));

  const outputs = construct.outputs.map((output, index) => {
    const destination = {
      type: output.type,
      publicSpendKey: hexToBytes(output.publicSpendKey),
      publicViewKey: hexToBytes(output.publicViewKey),
      ...(output.paymentID ? { paymentID: hexToBytes(output.paymentID) } : {}),
    };
    return {
      index,
      ...destination,
      amount: BigInt(output.amount),
      ...(output.isChange ? { isChange: true } : {}),
      subaddress: output.subaddressIndex ?? { major: 0, minor: 0 },
      owner: wallet.keysFromSecretKeys(
        hexToBytes(output.ownerSecretSpendKey),
        hexToBytes(output.ownerSecretViewKey)
      ),
      address: address('mainnet').encode(destination),
    };
  });

  // The rings of different inputs reuse global indexes with other keys, so each input keeps its own ring.
  const rings = inputs.map((input) => [input, ...input.decoys]
    .sort((a, b) => (a.globalIndex < b.globalIndex ? -1 : 1)));

  return {
    label,
    hex,
    id,
    decode: () => raw.fullTransaction.decode(hexToBytes(hex)),
    sender: wallet.keysFromSecretKeys(hexToBytes(construct.secretSpendKey), hexToBytes(construct.secretViewKey)),
    inputs,
    outputs,
    txKeys: {
      txSecretKey: hexToBytes(construct.txKeys.txSecretKey),
      txPublicKey: hexToBytes(construct.txKeys.txPublicKey),
      additionalTxSecretKeys: construct.txKeys.additionalTxSecretKeys.map(hexToBytes),
      additionalTxPublicKeys: construct.txKeys.additionalTxPublicKeys.map(hexToBytes),
    },
    // monero generated the tx keys from its random stream, so a rebuild must not supply them
    generatedTxKeys: Boolean(construct.generatedTxKeys),
    params: () => ({
      inputs,
      outputs,
      secretSpendKey: scalar(construct.secretSpendKey),
      secretViewKey: scalar(construct.secretViewKey),
      unlockTime: BigInt(construct.unlockTime),
      shuffleOutputs: construct.shuffleOutputs,
    }),
    /**
     * The ring of a vin, in vin order.
     * The fixture rings stay far below 2^64, so a plain sum of the relative offsets is enough.
     *
     * @param {import('../../lib/raw.js').Vin} vin
     * @returns {{ publicKey: Uint8Array, commitment: Uint8Array }[]}
     */
    ringOf: (vin) => {
      let globalIndex = 0n;
      const globalIndexes = vin.data.outputOffsets.map((offset) => {
        globalIndex += offset;
        return globalIndex;
      });
      const matches = rings.filter((members) => members.every((member, i) => member.globalIndex === globalIndexes[i]));
      if (matches.length !== 1) {
        throw new Error(`${label}: ${matches.length} rings match the vin`);
      }
      return matches[0].map(({ publicKey, commitment }) => ({ publicKey, commitment }));
    },
  };
});

/**
 * The receive derivation of a construct_tx output, as its owner computes it.
 * monero derives a subaddress output from its additional key when the tx has them.
 *
 * @param {object} fixture - an entry of constructFixtures
 * @param {object} output - an entry of fixture.outputs
 * @returns {Uint8Array}
 */
export function ownerDerivation(fixture, output) {
  const { txPublicKey, additionalTxPublicKeys } = fixture.txKeys;
  const R = output.type === 'subaddress' && additionalTxPublicKeys.length
    ? additionalTxPublicKeys[output.index]
    : txPublicKey;
  return crypto.generateKeyDerivation(R, decodeInt(output.owner.secretViewKey));
}
