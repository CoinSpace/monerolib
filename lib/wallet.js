import { equalBytes } from '@noble/curves/utils.js';
import { abytes, bytesToHex } from '@noble/hashes/utils.js';

import { address } from './address.js';
import { selectInputs } from './coinselect.js';
import {
  COINBASE_UNLOCK_WINDOW,
  DEFAULT_SPENDABLE_AGE,
  RING_SIZE,
} from './config.js';
import {
  RCTTypes,
  decodeCoinbase,
  decodeRct,
} from './ringct.js';
import {
  TXIN_TO_KEY_TAG,
  fullTransaction,
} from './raw.js';
import {
  decodeInt,
  encodeInt,
} from './helpers.js';
import {
  deriveSubaddressPublicKey,
  deriveViewTag,
  fastHash,
  generateKeyDerivation,
  generateKeys,
  outputKeyImage,
  outputKeyOffset,
  secretKeyToPublicKey,
  subaddressPublicKeys,
  subaddressPublicSpendKey,
} from './crypto.js';
import {
  encryptPaymentId,
  parseTxExtra,
  prepareTransaction,
} from './tx.js';

/**
 * @typedef {object} WalletKeys
 * @property {Uint8Array} [secretSpendKey] - absent for a view-only wallet
 * @property {Uint8Array} publicSpendKey
 * @property {Uint8Array} secretViewKey
 * @property {Uint8Array} publicViewKey
 */

/**
 * account_base::generate: spend keypair from seed, view keypair from keccak(spend).
 * b = reduce(seed) (a random canonical scalar when seed is absent), B = b*G
 * a = Hs(encode(b)), A = a*G
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/account.cpp#L166-L195
 *
 * @param {Uint8Array} [seed] - 32-byte recovery seed; omit for a random account
 * @returns {WalletKeys}
 */
export function keysFromSeed(seed) {
  const spend = generateKeys(seed);
  const secretSpendKey = encodeInt(spend.sec);
  const view = generateKeys(fastHash(secretSpendKey));
  return {
    secretSpendKey,
    publicSpendKey: spend.pub,
    secretViewKey: encodeInt(view.sec),
    publicViewKey: view.pub,
  };
}

/**
 * A fresh random account: random spend key, view key from keccak(spend) - account_base::generate()
 * with no recovery key. Used to build dummy outputs.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/account.cpp#L166-L195
 *
 * @returns {WalletKeys}
 */
export function randomKeys() {
  return keysFromSeed();
}

/**
 * account_base::create_from_keys
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/account.cpp#L197-L215
 *
 * @param {Uint8Array} secretSpendKey
 * @param {Uint8Array} secretViewKey
 * @returns {WalletKeys}
 */
export function keysFromSecretKeys(secretSpendKey, secretViewKey) {
  abytes(secretSpendKey, 32, 'secret spend key');
  abytes(secretViewKey, 32, 'secret view key');
  return {
    secretSpendKey,
    publicSpendKey: secretKeyToPublicKey(decodeInt(secretSpendKey)),
    secretViewKey,
    publicViewKey: secretKeyToPublicKey(decodeInt(secretViewKey)),
  };
}

/**
 * account_base::create_from_viewkey (watch-only)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/account.cpp#L251-L266
 *
 * @param {Uint8Array} publicSpendKey
 * @param {Uint8Array} secretViewKey
 * @returns {WalletKeys}
 */
export function viewOnlyKeys(publicSpendKey, secretViewKey) {
  abytes(publicSpendKey, 32, 'public spend key');
  abytes(secretViewKey, 32, 'secret view key');
  return {
    publicSpendKey,
    secretViewKey,
    publicViewKey: secretKeyToPublicKey(decodeInt(secretViewKey)),
  };
}

/**
 * @param {WalletKeys} keys
 * @param {import('./config.js').Nettype} [nettype]
 * @returns {string} the primary address
 */
export function getAddress(keys, nettype = 'mainnet') {
  return address(nettype).encode({
    type: 'address',
    publicSpendKey: keys.publicSpendKey,
    publicViewKey: keys.publicViewKey,
  });
}

/**
 * @param {WalletKeys} keys
 * @param {import('./crypto.js').SubaddressIndex} index
 * @param {import('./config.js').Nettype} [nettype]
 * @returns {string} the (sub)address
 */
export function getSubaddress(keys, index, nettype = 'mainnet') {
  if (index.major === 0 && index.minor === 0) {
    return getAddress(keys, nettype);
  }
  const secView = decodeInt(keys.secretViewKey);
  const { publicSpendKey, publicViewKey } = subaddressPublicKeys(secView, keys.publicSpendKey, index);
  return address(nettype).encode({
    type: 'subaddress',
    publicSpendKey,
    publicViewKey,
  });
}

/**
 * @param {WalletKeys} keys
 * @param {Uint8Array} paymentID - 8-byte payment id
 * @param {import('./config.js').Nettype} [nettype]
 * @returns {string} the integrated address
 */
export function getIntegratedAddress(keys, paymentID, nettype = 'mainnet') {
  return address(nettype).encode({
    type: 'integratedaddress',
    publicSpendKey: keys.publicSpendKey,
    publicViewKey: keys.publicViewKey,
    paymentID,
  });
}

/**
 * A lookup of our (sub)address spend public keys → index, for output scanning.
 * get_subaddress_spend_public_keys
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L143-L159
 *
 * @param {WalletKeys} keys
 * @param {number} accounts - number of major indices (major in [0, accounts))
 * @param {number} count - number of minor indices per account (minor in [0, count))
 * @returns {Map<string, import('./crypto.js').SubaddressIndex>} hex(spend public key) → index
 */
export function subaddressLookup(keys, accounts, count) {
  const secView = decodeInt(keys.secretViewKey);
  const map = new Map();
  for (let major = 0; major < accounts; major++) {
    for (let minor = 0; minor < count; minor++) {
      const index = { major, minor };
      const publicSpendKey = subaddressPublicSpendKey(secView, keys.publicSpendKey, index);
      map.set(bytesToHex(publicSpendKey), index);
    }
  }
  return map;
}

/**
 * @typedef {object} TxOutput
 * @property {Uint8Array} outputKey - the output one-time public key
 * @property {Uint8Array} [txPublicKey] - the tx public key R; used to derive when derivations are omitted
 * @property {Uint8Array} [additionalTxPublicKey] - the per-output additional key R, if any
 * @property {number} [viewTag] - the one-byte view tag, absent for pre-HF15 (untagged) outputs
 * @property {number} index - output index in the tx
 * @property {import('./ringct.js').RctType} rctType
 * @property {import('./raw.js').EcdhTuple} [ecdhInfo] - the per-output ecdh entry (RingCT only)
 * @property {Uint8Array} [outPk] - the per-output commitment (RingCT only)
 * @property {bigint} [amount] - cleartext vout amount, for a coinbase (Null rct) output
 */

/**
 * @typedef {object} OwnedOutput - a detected output belonging to the wallet
 * @property {import('./crypto.js').SubaddressIndex} subaddress
 * @property {number} index - output index in the tx
 * @property {bigint} amount
 * @property {bigint} mask - the output commitment mask (blinding scalar)
 * @property {Uint8Array} commitment - the per-output commitment
 * @property {Uint8Array} publicKey - the output one-time public key P (for xG == P checks when spending)
 * @property {bigint} keyOffset - view-only offset; the one-time secret is keyOffset + spend secret
 * @property {Uint8Array} [keyImage] - absent for a view-only wallet (needs the spend key)
 */

/**
 * The receive derivation D = 8 * secretViewKey * R for one tx public key, or undefined if the key is
 * missing or malformed (skipped so a bad key can't abort the scan).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L293-L305
 *
 * @param {Uint8Array | undefined} publicKey
 * @param {bigint} secretViewKey
 * @returns {Uint8Array | undefined}
 */
export function receiveDerivation(publicKey, secretViewKey) {
  if (!publicKey) {
    return undefined;
  }
  try {
    return generateKeyDerivation(publicKey, secretViewKey);
  } catch {
    return undefined;
  }
}

/**
 * The amount, mask and commitment of an output, or undefined if its RingCT data does not decode.
 * A malformed output is skipped, not fatal, so one bad output cannot stall the scan: wallet2 catches
 * the decode error, monero-oxide skips the output.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L2189-L2215
 *
 * @param {TxOutput} output
 * @param {Uint8Array} derivation
 * @returns {import('./ringct.js').DecodedOutput | undefined}
 */
function decodeOutput(output, derivation) {
  const {
    ecdhInfo, outPk, rctType, index,
  } = output;
  // coinbase (miner) outputs are not RingCT (Null type): cleartext amount, transparent commitment
  if (rctType === RCTTypes.Null) {
    return decodeCoinbase(output.amount);
  }
  try {
    return { ...decodeRct(ecdhInfo, outPk, rctType, index, derivation), commitment: outPk };
  } catch {
    return undefined;
  }
}

/**
 * Detect whether an output is ours and, if so, return the data needed to spend it.
 * is_out_to_acc_precomp + generate_key_image_helper_precomp
 * Math (effective tx pubkey R, one-time output key P at index):
 * D = 8*a*R; B_candidate = P - Hs(D || index)*G, matched against known (sub)address spend keys
 * x = Hs(D || index) + b + m, I = x*Hp(P) (spend material, full wallet only)
 * RingCT v2: amount = ecdh XOR H("amount" || Hs(D||index))[0..8], mask = Hs("commitment_mask" || Hs(D||index))
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L1065-L1095
 *
 * @param {WalletKeys} keys - full or view-only wallet
 * @param {TxOutput} output
 * @param {Map<string, import('./crypto.js').SubaddressIndex>} subaddresses - from subaddressLookup
 * @param {Uint8Array} [primaryDerivation] - the tx public key derivation, shared across a tx; derived
 *   from output.txPublicKey when omitted
 * @returns {OwnedOutput | null}
 */
export function scanOutput(keys, output, subaddresses, primaryDerivation) {
  const {
    outputKey, index, viewTag, txPublicKey, additionalTxPublicKey,
  } = output;
  const secView = decodeInt(keys.secretViewKey);
  // the additional-key derivation is computed only if the primary one does not match
  function* derivations() {
    const primary = primaryDerivation ?? receiveDerivation(txPublicKey, secView);
    if (primary) yield primary;
    const additional = receiveDerivation(additionalTxPublicKey, secView);
    if (additional) yield additional;
  }
  for (const derivation of derivations()) {
    // HF15+ outputs carry a view tag; skip the scalar-mult derivation on a mismatch (~255/256).
    // Pre-HF15 outputs have no tag (viewTag === undefined) and take the full path.
    if (viewTag !== undefined && deriveViewTag(derivation, index)[0] !== viewTag) {
      continue;
    }
    const publicSpendKey = deriveSubaddressPublicKey(outputKey, derivation, index);
    const found = subaddresses.get(bytesToHex(publicSpendKey));
    if (!found) {
      continue;
    }
    const decoded = decodeOutput(output, derivation);
    if (!decoded) {
      return null;
    }
    /** @type {OwnedOutput} */
    const owned = {
      subaddress: found,
      index,
      ...decoded,
      publicKey: outputKey,
      keyOffset: outputKeyOffset(secView, derivation, index, found),
    };
    // the view-only keyOffset alone is not spendable; the key image needs the spend key (x = keyOffset + b)
    if (keys.secretSpendKey) {
      owned.keyImage = outputKeyImage(secView, decodeInt(keys.secretSpendKey), derivation, index, found);
    }
    return owned;
  }
  return null;
}

/**
 * @typedef {object} OutputPaymentId
 * @property {Uint8Array} [paymentId]
 */

/**
 * @typedef {object} ScanTransactionResult
 * @property {(OwnedOutput & OutputPaymentId)[]} outputs
 * @property {Uint8Array[]} spentKeyImages
 */

/**
 * Scan every output of a decoded transaction (or a block's minerTx) for ones we own, and collect
 * the key images it spends. Per-output ownership and amounts follow scanOutput. Decrypts the short
 * payment id at most once, only if some output is ours, with the same symmetric mask as
 * encryptPaymentId (paymentId XOR keccak(8*a*R || 0x8d)[:8]).
 *
 * @param {WalletKeys} keys
 * @param {import('./raw.js').Transaction} decodedTx - from raw.fullTransaction.decode, or a block's minerTx
 * @param {Map<string, import('./crypto.js').SubaddressIndex>} subaddresses - from subaddressLookup
 * @returns {ScanTransactionResult}
 */
export function scanTransaction(keys, decodedTx, subaddresses) {
  const { prefix, rctSigBase } = decodedTx;
  const spentKeyImages = prefix.vin
    .filter((vin) => vin.TAG === TXIN_TO_KEY_TAG)
    .map((vin) => vin.data.keyImage);

  const txExtra = parseTxExtra(prefix.extra);
  const secView = decodeInt(keys.secretViewKey);
  // wallet2 tries every tx public key field (pk_index): a 2016 cold-signing bug wrote two, the real one second
  // https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L2352-L2366
  const txKeys = txExtra.txPublicKeys.map((publicKey) => ({
    publicKey, derivation: receiveDerivation(publicKey, secView),
  }));
  const outputs = [];
  let paymentId;
  prefix.vout.forEach((vout, index) => {
    for (const txKey of txKeys) {
      const candidate = {
        txPublicKey: txKey.publicKey,
        outputKey: vout.target.data.key,
        additionalTxPublicKey: txExtra.additionalTxPublicKeys[index],
        viewTag: vout.target.data.viewTag,
        index,
        rctType: rctSigBase?.type ?? RCTTypes.Null,
        ecdhInfo: rctSigBase?.ecdhInfo?.[index],
        outPk: rctSigBase?.outPk?.[index],
        amount: vout.amount,
      };
      const owned = scanOutput(keys, candidate, subaddresses, txKey.derivation);
      if (!owned) {
        continue;
      }
      if (paymentId === undefined && txExtra.encryptedPaymentId) {
        paymentId = encryptPaymentId(txExtra.encryptedPaymentId, txKey.publicKey, secView);
      }
      outputs.push({ ...owned, paymentId });
      break;
    }
  });

  return { outputs, spentKeyImages };
}

/**
 * Whether keyImage is the key image of the output at (txPublicKey, index, subaddress) for these
 * keys - distinguishes a genuine spend of ours from an output merely used as someone else's ring
 * decoy (a server without our spend key can't tell those apart on its own).
 *
 * Both the primary and the additional tx public key R are tried (D = 8 * secretViewKey * R). For each:
 * one-time secret x = Hs(D || index) + b + m (b the spend secret, m the subaddress secret, 0 for main),
 * key image I = x * Hp(P) for the one-time output key P. Ours if some derivation reproduces keyImage.
 *
 * @param {WalletKeys} keys - full wallet (needs secretSpendKey)
 * @param {object} output
 * @param {Uint8Array} output.txPublicKey
 * @param {Uint8Array} [output.additionalTxPublicKey]
 * @param {number} output.index
 * @param {import('./crypto.js').SubaddressIndex} output.subaddress
 * @param {Uint8Array} keyImage
 * @returns {boolean}
 */
export function isOwnKeyImage(keys, output, keyImage) {
  const secView = decodeInt(keys.secretViewKey);
  const secSpend = decodeInt(keys.secretSpendKey);
  for (const publicKey of [output.txPublicKey, output.additionalTxPublicKey]) {
    const derivation = receiveDerivation(publicKey, secView);
    if (!derivation) {
      continue;
    }
    const derived = outputKeyImage(secView, secSpend, derivation, output.index, output.subaddress);
    if (equalBytes(derived, keyImage)) {
      return true;
    }
  }
  return false;
}

/**
 * Whether an output has aged enough to be spendable. Only the default spendable age / coinbase
 * unlock window; a custom per-output unlock_time is a separate check.
 * is_transfer_unlocked
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L11364-L11396
 *
 * @param {object} output
 * @param {number} output.height
 * @param {boolean} [output.isCoinbase]
 * @param {number} currentHeight - current blockchain height
 * @returns {boolean}
 */
export function isMature(output, currentHeight) {
  const window = output.isCoinbase ? COINBASE_UNLOCK_WINDOW : DEFAULT_SPENDABLE_AGE;
  return currentHeight >= output.height + window;
}

/**
 * A change output to the wallet's primary address. isChange makes it derive via 8*a*R, so the wallet
 * scans and spends it later. (Monero sends change to the source account's subaddress {account, 0}.)
 *
 * @param {WalletKeys} keys
 * @param {bigint} amount
 * @returns {import('./tx.js').Destination}
 */
export function changeOutput(keys, amount) {
  return {
    type: 'address',
    publicSpendKey: keys.publicSpendKey,
    publicViewKey: keys.publicViewKey,
    amount,
    isChange: true,
  };
}

/**
 * A zero-amount output to a fresh random address, used to pad a transaction to two outputs when the
 * change is 0. isChange keeps it out of recipient classification (a change_dts, not a recipient).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L10230-L10244
 *
 * @returns {import('./tx.js').Destination}
 */
export function dummyOutput() {
  const keys = randomKeys();
  return {
    type: 'address',
    publicSpendKey: keys.publicSpendKey,
    publicViewKey: keys.publicViewKey,
    amount: 0n,
    isChange: true,
  };
}

/**
 * @typedef {object} TxKeys
 * @property {Uint8Array} txSecretKey - 32-byte tx secret key
 * @property {Uint8Array} txPublicKey
 * @property {Uint8Array[]} additionalTxSecretKeys - 32-byte keys; index i matches the additional public key and vout[i] after output shuffling
 * @property {Uint8Array[]} additionalTxPublicKeys
 */

/**
 * @typedef {object} CreatedTransaction
 * @property {import('./raw.js').Transaction} transaction
 * @property {Uint8Array} bytes
 * @property {TxKeys} txKeys
 */

/**
 * Build and sign a transaction: pick inputs and the change/dummy plan with selectInputs, append the
 * change output (or a dummy when there would be fewer than two outputs), and sign. Returns the decoded
 * transaction object, its serialized bytes, and its keys.
 *
 * @param {object} params
 * @param {import('./tx.js').TxInput[]} params.inputs - spendable candidates, each with RING_SIZE - 1 decoys
 * @param {import('./tx.js').Destination[]} params.outputs - recipient outputs (no change/dummy)
 * @param {WalletKeys} params.keys - full wallet (needs secretSpendKey)
 * @param {bigint} params.baseFee
 * @param {bigint} params.feeQuantization
 * @param {bigint} [params.feeMultiplier=1n]
 * @param {bigint} [params.unlockTime=0n]
 * @param {Partial<Pick<TxKeys, 'txSecretKey' | 'additionalTxSecretKeys'>>} [params.txKeys] - omitted secret keys are generated when needed
 * @param {boolean} [params.shuffleOutputs=true] - randomize the output order, see prepareTransaction
 * @returns {CreatedTransaction}
 */
export function createTransaction({
  inputs,
  outputs,
  keys,
  baseFee,
  feeQuantization,
  feeMultiplier = 1n,
  unlockTime = 0n,
  txKeys: { txSecretKey, additionalTxSecretKeys } = {},
  shuffleOutputs = true,
}) {
  if (txSecretKey !== undefined) {
    abytes(txSecretKey, 32, 'tx secret key');
  }
  if (additionalTxSecretKeys !== undefined) {
    additionalTxSecretKeys.forEach((key) => abytes(key, 32, 'additional tx secret key'));
  }

  const {
    selected, changeAmount, needsDummy,
  } = selectInputs({
    candidates: inputs,
    destinations: outputs,
    ringSize: RING_SIZE,
    baseFee,
    feeQuantization,
    feeMultiplier,
  });

  const finalOutputs = [...outputs];
  if (changeAmount !== undefined) {
    finalOutputs.push(changeOutput(keys, changeAmount));
  }
  if (needsDummy) {
    finalOutputs.push(dummyOutput());
  }

  const { transaction, txKeys } = prepareTransaction({
    inputs: selected,
    outputs: finalOutputs,
    secretSpendKey: decodeInt(keys.secretSpendKey),
    secretViewKey: decodeInt(keys.secretViewKey),
    unlockTime,
    txKeys: {
      txSecretKey: txSecretKey === undefined ? undefined : decodeInt(txSecretKey),
      additionalTxSecretKeys: additionalTxSecretKeys === undefined ? undefined : additionalTxSecretKeys.map(decodeInt),
    },
    shuffleOutputs,
  });
  return {
    transaction,
    bytes: fullTransaction.encode(transaction),
    txKeys: {
      txSecretKey: encodeInt(txKeys.txSecretKey),
      txPublicKey: txKeys.txPublicKey,
      additionalTxSecretKeys: txKeys.additionalTxSecretKeys.map(encodeInt),
      additionalTxPublicKeys: txKeys.additionalTxPublicKeys,
    },
  };
}
