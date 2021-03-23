import {
  fastHash,
  generateKeys,
  secretKeyToPublicKey,
} from './crypto-util.js';
import { getConfig } from './config.js';

function isBuffer32(buf) {
  return Buffer.isBuffer(buf) && buf.length === 32;
}

export default class Wallet {
  #config;
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

  /**
   * wallet2::generate
   * https://github.com/monero-project/monero/blob/v0.17.1.9/src/wallet/wallet2.cpp#L4600-L4840
   */

  constructor(options = {}) {
    this.#config = getConfig(options.nettype || 'mainnet');
    this.#nettype = options.nettype || 'mainnet';

    if (options.seed) {
      // Generate wallet from seed
      if (!isBuffer32(options.seed)) {
        throw TypeError('Incorrect seed');
      }
      this.#seed = options.seed;
      const { sec: secretSpendKey, pub: publicSpendKey } = generateKeys(options.seed);
      // supports only deterministic wallet
      const { sec: secretViewKey, pub: publicViewKey } = generateKeys(fastHash(secretSpendKey));

      this.#secretSpendKey = secretSpendKey;
      this.#publicSpendKey = publicSpendKey;

      this.#secretViewKey = secretViewKey;
      this.#publicViewKey = publicViewKey;
    } else if (options.secretSpendKey && options.secretViewKey) {
      // Generate wallet from secret keys pair
      if (!isBuffer32(options.secretSpendKey)) {
        throw TypeError('Incorrect secret spend key');
      }
      if (!isBuffer32(options.secretViewKey)) {
        throw TypeError('Incorrect secret view key');
      }
      this.#secretSpendKey = options.secretSpendKey;
      this.#publicSpendKey = secretKeyToPublicKey(options.secretSpendKey);
      this.#secretViewKey = options.secretViewKey;
      this.#publicViewKey = secretKeyToPublicKey(options.secretViewKey);
    } else if (options.publicSpendKey && options.secretViewKey) {
      // Generate watch/view only wallet
      if (!isBuffer32(options.publicSpendKey)) {
        throw TypeError('Incorrect public spend key');
      }
      if (!isBuffer32(options.secretViewKey)) {
        throw TypeError('Incorrect secret view key');
      }
      this.#publicSpendKey = options.publicSpendKey;
      this.#secretViewKey = options.secretViewKey;
      this.#publicViewKey = secretKeyToPublicKey(options.secretViewKey);
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
}
