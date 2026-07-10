import { abytes, bytesToHex } from '@noble/hashes/utils.js';

import { address } from './address.js';
import { decodeRct } from './ringct.js';
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
  secretKeyToPublicKey,
  subaddressPublicKeys,
  subaddressPublicSpendKey,
} from './crypto.js';

/**
 * @typedef {object} WalletKeys
 * @property {Uint8Array} [secretSpendKey] - absent for a view-only wallet
 * @property {Uint8Array} publicSpendKey
 * @property {Uint8Array} secretViewKey
 * @property {Uint8Array} publicViewKey
 */

/**
 * account_base::generate: spend keypair from seed, view keypair from keccak(spend).
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/account.cpp#L166-L195
 *
 * @param {Uint8Array} seed - 32-byte recovery seed
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
 * @property {import('./raw.js').EcdhTuple} ecdhInfo - the per-output ecdh entry
 * @property {Uint8Array} outPk - the per-output commitment
 * @property {import('./ringct.js').RctType} rctType
 */

/**
 * @typedef {object} OwnedOutput - a detected output belonging to the wallet
 * @property {import('./crypto.js').SubaddressIndex} subaddress
 * @property {number} index - output index in the tx
 * @property {bigint} amount
 * @property {bigint} mask - the output commitment mask (blinding scalar)
 * @property {Uint8Array} commitment - the per-output commitment
 * @property {bigint} [secretKey] - the one-time secret key; absent for a view-only wallet
 * @property {Uint8Array} [keyImage] - absent for a view-only wallet
 */

/**
 * Detect whether an output is ours and, if so, return the data needed to spend it.
 * is_out_to_acc_precomp + generate_key_image_helper_precomp
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_basic/cryptonote_format_utils.cpp#L1065-L1095
 *
 * @param {WalletKeys} keys - full or view-only wallet
 * @param {TxOutput} output
 * @param {Map<string, import('./crypto.js').SubaddressIndex>} subaddresses - from subaddressLookup
 * @returns {OwnedOutput | null}
 */
export function scanOutput(keys, output, subaddresses) {
  const { txPublicKey, additionalPublicKey, outputKey, index, ecdhInfo, outPk, rctType } = output;
  const secView = decodeInt(keys.secretViewKey);
  for (const publicKey of [txPublicKey, additionalPublicKey]) {
    if (!publicKey) {
      continue;
    }
    const derivation = generateKeyDerivation(publicKey, secView);
    const publicSpendKey = deriveSubaddressPublicKey(outputKey, derivation, index);
    const found = subaddresses.get(bytesToHex(publicSpendKey));
    if (!found) {
      continue;
    }
    const { mask, amount } = decodeRct(ecdhInfo, outPk, rctType, index, derivation);
    const owned = {
      subaddress: found,
      index,
      amount,
      mask: decodeInt(mask),
      commitment: outPk,
    };
    // a view-only wallet detects the output and reads its amount, but cannot compute the key image
    if (keys.secretSpendKey) {
      const secSpend = decodeInt(keys.secretSpendKey);
      const { secret: secretKey, keyImage } = outputKeyImage(secView, secSpend, derivation, index, found);
      owned.secretKey = secretKey;
      owned.keyImage = keyImage;
    }
    return owned;
  }
  return null;
}
