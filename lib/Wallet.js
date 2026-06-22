import Address from './Address.js';
import { HASH_KEY_SUBADDRESS } from './config.js';
import { numberToBytesLE } from '@noble/curves/utils.js';
import {
  Fn,
  Point,
  fastHash,
  generateKeys,
  hashToScalar,
  secretKeyToPublicKey,
} from './crypto-util.js';
import { abytes, concatBytes } from '@noble/hashes/utils.js';
import {
  decodeInt,
  decodePoint,
  encodeInt,
  encodePoint,
} from './helpers.js';

export default class Wallet {
  #nettype;
  #seed;
  #secretSpendKey;
  #publicSpendKey;
  #secretViewKey;
  #publicViewKey;

  get nettype() {
    return this.#nettype;
  }

  get seed() {
    if (!this.#seed) {
      throw new TypeError('Wallet in view only mode');
    }
    return this.#seed;
  }

  get secretSpendKey() {
    if (!this.#secretSpendKey) {
      throw new TypeError('Wallet in view only mode');
    }
    return this.#secretSpendKey;
  }

  get publicSpendKey() {
    return this.#publicSpendKey;
  }

  get secretViewKey() {
    return this.#secretViewKey;
  }

  get publicViewKey() {
    return this.#publicViewKey;
  }

  get isViewOnly() {
    return !this.#secretSpendKey;
  }

  /**
   * wallet2::generate
   * https://github.com/monero-project/monero/blob/v0.17.1.9/src/wallet/wallet2.cpp#L4600-L4840
   */

  constructor({ seed, secretSpendKey, secretViewKey, publicSpendKey, nettype = 'mainnet' } = {}) {
    this.#nettype = nettype || 'mainnet';

    if (seed) {
      // Generate wallet from seed
      abytes(seed, 32, 'seed');
      this.#seed = seed;
      const { sec: secretSpendKey, pub: publicSpendKey } = generateKeys(seed);
      // supports only deterministic wallet
      const { sec: secretViewKey, pub: publicViewKey } = generateKeys(fastHash(secretSpendKey));

      this.#secretSpendKey = secretSpendKey;
      this.#publicSpendKey = publicSpendKey;

      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = publicViewKey;
    } else if (secretSpendKey && secretViewKey) {
      // Generate wallet from secret keys pair
      abytes(secretSpendKey, 32, 'secret spend key');
      abytes(secretViewKey, 32, 'secret view key');
      this.#secretSpendKey = secretSpendKey;
      this.#publicSpendKey = secretKeyToPublicKey(secretSpendKey);
      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = secretKeyToPublicKey(secretViewKey);
    } else if (publicSpendKey && secretViewKey) {
      // Generate watch/view only wallet
      abytes(publicSpendKey, 32, 'public spend key');
      abytes(secretViewKey, 32, 'secret view key');
      this.#publicSpendKey = publicSpendKey;
      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = secretKeyToPublicKey(secretViewKey);
    } else {
      // Generate random wallet
      const { sec: secretSpendKey, pub: publicSpendKey } = generateKeys();
      // supports only deterministic wallet
      const { sec: secretViewKey, pub: publicViewKey } = generateKeys(fastHash(secretSpendKey));

      this.#seed = secretSpendKey;

      this.#secretSpendKey = secretSpendKey;
      this.#publicSpendKey = publicSpendKey;

      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = publicViewKey;
    }
  }

  getAddress() {
    return new Address({
      secretSpendKey: this.#secretSpendKey, // undefined for view only
      publicSpendKey: this.#publicSpendKey,
      publicViewKey: this.#publicViewKey,
    }, { index: { major: 0, minor: 0 }, type: 'address', nettype: this.#nettype });
  }

  // it is not a key!
  getSubaddressSecret(major, minor) {
    const data = concatBytes(
      HASH_KEY_SUBADDRESS,
      new Uint8Array(1),
      this.#secretViewKey,
      numberToBytesLE(major, 4),
      numberToBytesLE(minor, 4)
    );
    return hashToScalar(data);
  }

  getSubaddress(major = 0, minor = 0) {
    if (major === 0 && minor === 0) {
      return this.getAddress();
    } else {
      const m = decodeInt(this.getSubaddressSecret(major, minor));
      if (this.#secretSpendKey) {
        const b = decodeInt(this.#secretSpendKey);
        const d = Fn.add(b, m);
        const D = Point.BASE.multiplyUnsafe(d);
        const C = D.multiplyUnsafe(decodeInt(this.#secretViewKey));
        return new Address({
          secretSpendKey: encodeInt(d),
          publicSpendKey: encodePoint(D),
          publicViewKey: encodePoint(C),
        }, { index: { major, minor }, type: 'subaddress', nettype: this.#nettype });
      } else {
        const M = Point.BASE.multiplyUnsafe(m);
        const B = decodePoint(this.#publicSpendKey);
        const D = B.add(M);
        const C = D.multiplyUnsafe(decodeInt(this.#secretViewKey));
        return new Address({
          publicSpendKey: encodePoint(D),
          publicViewKey: encodePoint(C),
        }, { index: { major, minor }, type: 'subaddress', nettype: this.#nettype });
      }
    }
  }

  getIntegratedAddress(paymentID) {
    return new Address({
      secretSpendKey: this.#secretSpendKey, // undefined for view only
      publicSpendKey: this.#publicSpendKey,
      publicViewKey: this.#publicViewKey,
      paymentID,
    }, { type: 'integratedaddress', nettype: this.#nettype });
  }

  addressFromString(str) {
    return Address.fromString(str, this.#nettype);
  }
}
