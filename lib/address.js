import base58 from 'base58-monero';
import { getConfig } from './config.js';
import { fastHash } from './crypto-util.js';

export default class Address {
  #config;

  constructor(publicSpendKey, publicViewKey, isSubaddress = false, nettype = 'mainnet') {
    this.publicSpendKey = publicSpendKey;
    this.publicViewKey = publicViewKey;
    this.isSubaddress = isSubaddress;
    this.#config = getConfig(nettype);
    this.nettype = nettype;
  }

  toString() {
    const prefix = this.isSubaddress ?
      this.#config.CRYPTONOTE_PUBLIC_SUBADDRESS_BASE58_PREFIX :
      this.#config.CRYPTONOTE_PUBLIC_ADDRESS_BASE58_PREFIX;
    const data = Buffer.concat([
      prefix,
      this.publicSpendKey,
      this.publicViewKey,
    ]);
    const checksum = fastHash(data).slice(0, 4);
    return base58.encode(Buffer.concat([data, checksum]));
  }
}
