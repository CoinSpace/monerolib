import assert from 'node:assert/strict';
import { hexToBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

import { address } from '../lib/address.js';

const NETTYPES = ['mainnet', 'testnet', 'stagenet'];

// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/base58.cpp#L462-L489
const KEYS = {
  publicSpendKey: hexToBytes('f724bc5c6cfbb9d97602c300423a2f28641874513a035778a0c1778d833201e9'),
  publicViewKey: hexToBytes('220939689edf1abd5bc1d031f73ecd6c993add66d6808870456afeb8e7eeb68d'),
};
const KEYS_ADDRESS = '4AzKEX4gXdJdNeM6dfiBFL7kqund3HYGvMBF3ttsNd9SfzgYB6L7ep1Yg1osYJzLdaKAYSLVh6e6jKnAuzj3bw1oGy9kXCb';

// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/uri.cpp#L32-L34
const TESTNET_ADDRESS = '9tTLtauaEKSj7xoVXytVH32R1pLZBk4VV4mZFGEh4wkXhDWqw1soPyf3fGixf1kni31VznEZkWNEza9d5TvjWwq5PaohYHC';
const TESTNET_INTEGRATED_ADDRESS = 'A4A1uPj4qaxj7xoVXytVH32R1pLZBk4VV4mZFGEh4wkXhDWqw1soPyf3fGixf1kni31VznEZkWNEza9d5TvjWwq5acaPMJfMbn3ReTsBpp';
const TESTNET_PAYMENT_ID = hexToBytes('f612cac0b6cb1cda');

// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/functional_tests/validate_address.py#L67-L82
const GOOD_ADDRESSES = [
  ['mainnet', 'address', '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm'],
  ['mainnet', 'address', '44Kbx4sJ7JDRDV5aAhLJzQCjDz2ViLRduE3ijDZu3osWKBjMGkV1XPk4pfDUMqt1Aiezvephdqm6YD19GKFD9ZcXVUTp6BW'],
  ['testnet', 'address', '9ujeXrjzf7bfeK3KZdCqnYaMwZVFuXemPU8Ubw335rj2FN1CdMiWNyFV3ksEfMFvRp9L9qum5UxkP5rN9aLcPxbH1au4WAB'],
  ['stagenet', 'address', '53teqCAESLxeJ1REzGMAat1ZeHvuajvDiXqboEocPaDRRmqWoVPzy46GLo866qRFjbNhfkNckyhST3WEvBviDwpUDd7DSzB'],
  ['mainnet', 'integratedaddress', '4BxSHvcgTwu25WooY4BVmgdcKwZu5EksVZSZkDd6ooxSVVqQ4ubxXkhLF6hEqtw96i9cf3cVfLw8UWe95bdDKfRQeYtPwLm1Jiw7AKt2LY'],
  ['mainnet', 'subaddress', '8AsN91rznfkBGTY8psSNkJBg9SZgxxGGRUhGwRptBhgr5XSQ1XzmA9m8QAnoxydecSh5aLJXdrgXwTDMMZ1AuXsN1EX5Mtm'],
  ['mainnet', 'subaddress', '86kKnBKFqzCLxtK1Jmx2BkNBDBSMDEVaRYMMyVbeURYDWs8uNGDZURKCA5yRcyMxHzPcmCf1q2fSdhQVcaKsFrtGRsdGfNk'],
  ['testnet', 'integratedaddress', 'AApMA1VuhiCaHzr5X2KXi2Zc9oJ3VaGjkfChxxpRpxkyKf1NetvbRbQTbFMrGkr85DjnEH7JsBaoUFsgKwZnmtnVWnoB8MDotCsLb7eWwz'],
  ['testnet', 'subaddress', 'BdKg9udkvckC5T58a8Nmtb6BNsgRAxs7uA2D49sWNNX5HPW5Us6Wxu8QMXrnSx3xPBQQ2iu9kwEcRGAoiz6EPmcZKbF62GS'],
  ['testnet', 'subaddress', 'BcFvPa3fT4gVt5QyRDe5Vv7VtUFao9ci8NFEy3r254KF7R1N2cNB5FYhGvrHbMStv4D6VDzZ5xtxeKV8vgEPMnDcNFuwZb9'],
  ['stagenet', 'integratedaddress', '5K8mwfjumVseCcQEjNbf59Um6R9NfVUNkHTLhhPCmNvgDLVS88YW5tScnm83rw9mfgYtchtDDTW5jEfMhygi27j1QYphX38hg6m4VMtN29'],
  ['stagenet', 'subaddress', '73LhUiix4DVFMcKhsPRG51QmCsv8dYYbL6GcQoLwEEFvPvkVvc7BhebfA4pnEFF9Lq66hwvLqBvpHjTcqvpJMHmmNjPPBqa'],
  ['stagenet', 'subaddress', '7A1Hr63MfgUa8pkWxueD5xBqhQczkusYiCMYMnJGcGmuQxa7aDBxN1G7iCuLCNB3VPeb2TW7U9FdxB27xKkWKfJ8VhUZthF'],
];

// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/functional_tests/validate_address.py#L56-L63
const BAD_ADDRESSES = ['', 'a', '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWD9', ' ', '@', '42ey'];

// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/base58.cpp#L444-L460
const BAD_BASE58_ADDRESSES = [
  'zuT7GAdgbA819VwdWVDP', '0uT7GAdgbA819VwdWVDP', 'IuT7GAdgbA819VwdWVDP', 'OuT7GAdgbA819VwdWVDP', 'luT7GAdgbA819VwdWVDP',
  '\0uT7GAdgbA819VwdWVDP', 'PuT7GAdgbA819VwdWVD', '11efCaY6UjG7JrxuC', 'jerj2e4mESo', '1', '1111', '11', '111', '11111',
  '111111', '999999', 'ZZZZZZ',
];

const MAINNET_ADDRESSES = [
  {
    str: '47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1xXgiDt',
    descriptor: {
      type: 'address',
      publicSpendKey: hexToBytes('9f93f94f9d38602cb9e0157d8df46a08fb99a1518e2fddea9e0da53af3bebaa7'),
      publicViewKey: hexToBytes('b09a138e8fe3e69e4bf23a4521b07900c8caa94a3376fcc54d089ead0b742108'),
    },
  },
  {
    str: '8BKDtGLgpy8GKMhxBYNjK3Y1XW1yzKQ8aeR88i84521NZ4XHtk9wtTZX988HHUdsFL5eYZTrzPGmtiiLvdDJVvNRNCJKsR7',
    descriptor: {
      type: 'subaddress',
      publicSpendKey: hexToBytes('e9d78cb7bebdbb5b924556a5ce5e36b9641ee7b90c14d3dfb1f4189ffdc929bf'),
      publicViewKey: hexToBytes('adb6f3010be5c0b4321191f6f9d9171bc8d2d231e0fe67f962789feeb789bebb'),
    },
  },
  {
    str: '4HNXMYnW5mZ8Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax2SEU4v4fc3hLJGgron',
    descriptor: {
      type: 'integratedaddress',
      publicSpendKey: hexToBytes('9f93f94f9d38602cb9e0157d8df46a08fb99a1518e2fddea9e0da53af3bebaa7'),
      publicViewKey: hexToBytes('b09a138e8fe3e69e4bf23a4521b07900c8caa94a3376fcc54d089ead0b742108'),
      paymentID: hexToBytes('945c0d11d13908ab'),
    },
  },
];

describe('address', () => {
  describe('encode', () => {
    it('encodes the keys of the monero vector', () => {
      assert.equal(address('mainnet').encode({ type: 'address', ...KEYS }), KEYS_ADDRESS);
    });

    it('encodes keys into an address, a subaddress and an integrated address', () => {
      for (const { str, descriptor } of MAINNET_ADDRESSES) {
        assert.equal(address('mainnet').encode(descriptor), str);
      }
    });

    it('encodes a testnet integrated address from the standard address keys and a payment id', () => {
      const { publicSpendKey, publicViewKey } = address('testnet').decode(TESTNET_ADDRESS);
      assert.equal(address('testnet').encode({
        type: 'integratedaddress', publicSpendKey, publicViewKey, paymentID: TESTNET_PAYMENT_ID,
      }), TESTNET_INTEGRATED_ADDRESS);
    });

    it('re-encodes every valid monero address', () => {
      for (const [nettype, , str] of GOOD_ADDRESSES) {
        const coder = address(nettype);
        assert.equal(coder.encode(coder.decode(str)), str);
      }
    });

    it('rejects an unsupported type', () => {
      assert.throws(() => {
        address('mainnet').encode({ type: 'featured', ...KEYS });
      }, /Unsupported address type/);
    });
  });

  describe('decode', () => {
    it('decodes the monero vector to its keys', () => {
      assert.deepEqual(address('mainnet').decode(KEYS_ADDRESS), { type: 'address', ...KEYS });
    });

    it('decodes an address, a subaddress and an integrated address to their keys', () => {
      for (const { str, descriptor } of MAINNET_ADDRESSES) {
        assert.deepEqual(address('mainnet').decode(str), descriptor);
      }
    });

    it('rejects a wrong checksum', () => {
      assert.throws(() => {
        address('mainnet').decode('47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1uMFe9D');
      }, { message: 'Invalid address checksum' });
    });

    it('rejects an unknown prefix', () => {
      assert.throws(() => {
        address('mainnet').decode('173k6DE8Xgj8Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1yJVx47');
      }, { message: 'Invalid address prefix' });
    });

    // valid checksum, wrong payload length: 40 bytes, 66 bytes, and an integrated prefix with 65 bytes
    it('rejects a payload of the wrong length for its type', () => {
      for (const str of [
        '47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv14BLxJe',
        '47frLjy1UW38Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax14z8kkjTC',
        '4HNXMYnW5mZ8Uu96bLC38d2W9PE7AeYExgF5nyWt4b8MV3oVd4v9vv1TUgCruhxSac18cL2PpiHuVa14q2zxw9Ax1yCAcXA',
      ]) {
        assert.throws(() => {
          address('mainnet').decode(str);
        }, { message: 'Invalid address length' });
      }
    });

    it('decodes the payment id of a testnet integrated address', () => {
      const standard = address('testnet').decode(TESTNET_ADDRESS);
      assert.deepEqual(address('testnet').decode(TESTNET_INTEGRATED_ADDRESS), {
        type: 'integratedaddress',
        publicSpendKey: standard.publicSpendKey,
        publicViewKey: standard.publicViewKey,
        paymentID: TESTNET_PAYMENT_ID,
      });
    });

    for (const [nettype, type, str] of GOOD_ADDRESSES) {
      it(`accepts a ${nettype} ${type} only on ${nettype}: ${str.slice(0, 12)}`, () => {
        assert.equal(address(nettype).decode(str).type, type);
        for (const other of NETTYPES.filter((name) => name !== nettype)) {
          assert.throws(() => {
            address(other).decode(str);
          }, { message: 'Invalid address prefix' });
        }
      });
    }

    it('rejects the bad addresses of monero validate_address', () => {
      for (const str of BAD_ADDRESSES) {
        assert.throws(() => {
          address('mainnet').decode(str);
        }, `accepted '${str}'`);
      }
    });

    it('rejects the bad strings of monero base58 decode_addr', () => {
      for (const str of BAD_BASE58_ADDRESSES) {
        assert.throws(() => {
          address('mainnet').decode(str);
        }, `accepted '${str}'`);
      }
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/base58.cpp#L491-L498
    it('rejects an address with an invalid first character', () => {
      assert.throws(() => {
        address('mainnet').decode(`0${KEYS_ADDRESS.slice(1)}`);
      });
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/base58.cpp#L500-L506
    it('rejects prefix 0', () => {
      assert.throws(() => {
        address('mainnet').decode('1ANCyzKoaozdNeM6dfiBFL7kqund3HYGvMBF3ttsNd9SfzgYB6L7ep1Yg1osYJzLdaKAYSLVh6e6jKnAuzj3bw1oGzPj2tT');
      }, { message: 'Invalid address prefix' });
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/base58.cpp#L508-L514
    it('rejects a 63-byte payload', () => {
      assert.throws(() => {
        address('mainnet').decode('431rMAUezAtLjrSi5A9DwmHk41r85CVgTTtXrW6J2uVi6hC9PNfSGMrGMACgbD3DrKSdXJFaSj5PdCcSajvSw5g825rWpx');
      }, { message: 'Invalid address length' });
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/base58.cpp#L516-L524
    it('rejects a spend key that is not a point', () => {
      assert.throws(() => {
        address('mainnet').decode('41dRYYZdAjrdNeM6dfiBFL7kqund3HYGvMBF3ttsNd9SfzgYB6L7ep1Yg1osYJzLdaKAYSLVh6e6jKnAuzj3bw1oGypw7dZ');
      });
    });

    // https://github.com/monero-project/monero/blob/v0.18.5.1/tests/unit_tests/base58.cpp#L526-L534
    it('rejects a view key that is not a point', () => {
      assert.throws(() => {
        address('mainnet').decode('4AzKEX4gXdJdNeM6dfiBFL7kqund3HYGvMBF3ttsNd9SfzgYB6L7ep1Yg1osYJzLdaKAYSLVh6e6jKnAuzj3bw1o1CFNHsz');
      });
    });
  });

  it('rejects an unknown network type', () => {
    assert.throws(() => {
      address('mainnet2');
    }, { message: 'Invalid network type: mainnet2' });
  });
});
