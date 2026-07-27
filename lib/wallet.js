import { equalBytes } from '@noble/curves/utils.js';
import { abytes, bytesToHex } from '@noble/hashes/utils.js';

import { TXIN_TO_KEY_TAG } from './raw.js';
import { address } from './address.js';
import {
  COINBASE_UNLOCK_WINDOW,
  DEFAULT_SPENDABLE_AGE,
} from './config.js';
import {
  RCTTypes,
  decodeCoinbase,
  decodeRct,
} from './ringct.js';
import {
  decodeInt,
  encodeInt,
} from './helpers.js';
import {
  deriveSubaddressPublicKey,
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
 * @property {Uint8Array} txPublicKey
 * @property {Uint8Array} [additionalPublicKey] - the additional pub key for this output index, if any
 * @property {Uint8Array} outputKey - the output one-time public key
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
 * The receive derivations to try for an output (D = 8 * secretViewKey * R), yielded lazily: the tx
 * public key, then the per-output additional key (used by a subaddress output in a mixed tx). A
 * malformed key is skipped, not thrown, so it can't abort a scan that matches on another derivation.
 * Mirrors recv_derivation + additional_recv_derivations.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L293-L305
 *
 * @param {Uint8Array} txPublicKey
 * @param {Uint8Array | undefined} additionalPublicKey
 * @param {bigint} secretViewKey
 * @yields {Uint8Array}
 */
function* receiveDerivations(txPublicKey, additionalPublicKey, secretViewKey) {
  for (const publicKey of [txPublicKey, additionalPublicKey]) {
    if (!publicKey) {
      continue;
    }
    let derivation;
    try {
      derivation = generateKeyDerivation(publicKey, secretViewKey);
    } catch {
      continue;
    }
    yield derivation;
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
 * @returns {OwnedOutput | null}
 */
export function scanOutput(keys, output, subaddresses) {
  const {
    txPublicKey, additionalPublicKey, outputKey, index, ecdhInfo, outPk, rctType,
  } = output;
  const secView = decodeInt(keys.secretViewKey);
  for (const derivation of receiveDerivations(txPublicKey, additionalPublicKey, secView)) {
    const publicSpendKey = deriveSubaddressPublicKey(outputKey, derivation, index);
    const found = subaddresses.get(bytesToHex(publicSpendKey));
    if (!found) {
      continue;
    }
    // coinbase (miner) outputs are not RingCT (Null type): cleartext amount, transparent commitment
    const {
      amount, mask, commitment,
    } = rctType === RCTTypes.Null
      ? decodeCoinbase(output.amount)
      : { ...decodeRct(ecdhInfo, outPk, rctType, index, derivation), commitment: outPk };
    const owned = {
      subaddress: found,
      index,
      amount,
      mask,
      commitment,
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
 * Scan every output of a decoded transaction (or a block's minerTx) for ones we own, and collect
 * the key images it spends. Per-output ownership and amounts follow scanOutput. Decrypts the short
 * payment id at most once, only if some output is ours, with the same symmetric mask as
 * encryptPaymentId (paymentId XOR keccak(8*a*R || 0x8d)[:8]).
 *
 * @param {WalletKeys} keys
 * @param {import('./raw.js').Transaction} decodedTx - from raw.transaction.decode, or a block's minerTx
 * @param {Map<string, import('./crypto.js').SubaddressIndex>} subaddresses - from subaddressLookup
 * @returns {{
 *   outputs: (OwnedOutput & { paymentId?: Uint8Array })[],
 *   spentKeyImages: Uint8Array[]
 * }}
 */
export function scanTransaction(keys, decodedTx, subaddresses) {
  const { prefix, rctSigBase } = decodedTx;
  const spentKeyImages = prefix.vin
    .filter((vin) => vin.TAG === TXIN_TO_KEY_TAG)
    .map((vin) => vin.data.keyImage);

  const txExtra = parseTxExtra(prefix.extra);
  const outputs = [];
  let paymentId;
  prefix.vout.forEach((vout, index) => {
    const candidate = {
      txPublicKey: txExtra.txPublicKey,
      additionalPublicKey: txExtra.additionalPublicKeys[index],
      outputKey: vout.target.data.key,
      index,
      rctType: rctSigBase?.type ?? RCTTypes.Null,
      ecdhInfo: rctSigBase?.ecdhInfo?.[index],
      outPk: rctSigBase?.outPk?.[index],
      amount: vout.amount,
    };
    const owned = scanOutput(keys, candidate, subaddresses);
    if (!owned) {
      return;
    }
    if (paymentId === undefined && txExtra.encryptedPaymentId.length === 8) {
      paymentId = encryptPaymentId(txExtra.encryptedPaymentId, txExtra.txPublicKey, decodeInt(keys.secretViewKey));
    }
    outputs.push({ ...owned, paymentId });
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
 * @param {{
 *   txPublicKey: Uint8Array,
 *   additionalPublicKey?: Uint8Array,
 *   index: number,
 *   subaddress: import('./crypto.js').SubaddressIndex
 * }} output
 * @param {Uint8Array} keyImage
 * @returns {boolean}
 */
export function isOwnKeyImage(keys, output, keyImage) {
  const secView = decodeInt(keys.secretViewKey);
  const secSpend = decodeInt(keys.secretSpendKey);
  for (const derivation of receiveDerivations(output.txPublicKey, output.additionalPublicKey, secView)) {
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
 * @param {{ height: number, isCoinbase?: boolean }} output
 * @param {number} currentHeight - current blockchain height
 * @returns {boolean}
 */
export function isMature(output, currentHeight) {
  const window = output.isCoinbase ? COINBASE_UNLOCK_WINDOW : DEFAULT_SPENDABLE_AGE;
  return currentHeight >= output.height + window;
}
