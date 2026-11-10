import { hexToBytes } from '@noble/hashes/utils.js';

// https://github.com/knaccc/subaddress-js/blob/21b05dcee308c74a04aa9a7e17c22922ae348b2d/test/index.test.js#L3-L30
export const KNACCC_WALLET = {
  mnemonic: 'vary ambush western rafts session laboratory jerseys napkin muffin exult tolerant efficient ensign fewest sulking wonders pledge alerts acquire tubes rogue outbreak lifestyle lopped pledge',
  secretSpendKey: hexToBytes('8d8c8eeca38ac3b46aa293fd519b3860e96b5f873c12a95e3e1cdeda0bac4903'),
  publicSpendKey: hexToBytes('f8631661f6ab4e6fda310c797330d86e23a682f20d5bc8cc27b18051191f16d7'),
  secretViewKey: hexToBytes('99c57d1f0f997bc8ca98559a0ccc3fada3899756e63d1516dba58b7e468cfc05'),
  publicViewKey: hexToBytes('4a1535063ad1fee2dabbf909d4fd9a873e29541b401f0944754e17c9a41820ce'),
  address: '4B33mFPMq6mKi7Eiyd5XuyKRVMGVZz1Rqb9ZTyGApXW5d1aT7UBDZ89ewmnWFkzJ5wPd2SFbn313vCT8a4E2Qf4KQH4pNey',
  subaddresses: [
    { index: { major: 0, minor: 1 }, address: '8C5zHM5ud8nGC4hC2ULiBLSWx9infi8JUUmWEat4fcTf8J4H38iWYVdFmPCA9UmfLTZxD43RsyKnGEdZkoGij6csDeUnbEB' },
    { index: { major: 0, minor: 256 }, address: '883z7xonbVBGXpsatJZ53vcDiXQkrkTHUHPxrdrHXiPnZY8DMaYJ7a88C5ovncy5zHWkLc2cQ2hUoaKYCjFtjwFV4vtcpiF' },
    { index: { major: 256, minor: 1 }, address: '87X4ksVMRv2UGhHcgVjY6KJDjqP9S4zrCNkmomL1ziQVeZXF3RXbAx7i2rRt3UU5eXDzG9TWZ6Rk1Fyg6pZrAKQCNfLrSne' },
    { index: { major: 256, minor: 256 }, address: '86gYdT7yqDJUXegizt1vbF3YKz5qSYVaMB61DFBDzrpVEpYgDbmuXJbXE77LQfAygrVGwYpw8hxxx9DRTiyHAemA8B5yBAq' },
  ],
};

// The wallet of monero's functional tests: keys, address and subaddresses that wallet2 reports.
// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/functional_tests/wallet.py#L70-L171
// https://github.com/monero-project/monero/blob/v0.18.5.1/tests/functional_tests/integrated_address.py#L63-L64
export const FUNCTIONAL_TESTS_WALLET = {
  mnemonic: 'velvet lymph giddy number token physics poetry unquoted nibs useful sabotage limits benches lifestyle eden nitrogen anvil fewest avoid batch vials washing fences goat unquoted',
  secretSpendKey: hexToBytes('148d78d2aba7dbca5cd8f6abcfb0b3c009ffbdbea1ff373d50ed94d78286640e'),
  secretViewKey: hexToBytes('49774391fa5e8d249fc2c5b45dadef13534bf2483dede880dac88f061e809100'),
  address: '42ey1afDFnn4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfJJQAWDm',
  subaddresses: [
    { index: { major: 1, minor: 0 }, address: '82pP87g1Vkd3LUMssBCumk3MfyEsFqLAaGDf6oxddu61EgSFzt8gCwUD4tr3kp9TUfdPs2CnpD7xLZzyC1Ei9UsW3oyCWDf' },
    { index: { major: 2, minor: 0 }, address: '8Bdb75y2MhvbkvaBnG7vYP6DCNneLWcXqNmfPmyyDkavAUUgrHQEAhTNK3jEq69kGPDrd3i5inPivCwTvvA12eQ4SJk9iyy' },
    { index: { major: 0, minor: 1 }, address: '84QRUYawRNrU3NN1VpFRndSukeyEb3Xpv8qZjjsoJZnTYpDYceuUTpog13D7qPxpviS7J29bSgSkR11hFFoXWk2yNdsR9WF' },
    { index: { major: 1, minor: 1 }, address: '87qyoPVaEcWikVBmG1TaP1KumZ3hB3Q5f4wZRjuppNdwYjWzs2RgbLYQgtpdu2YdoTT3EZhiUGaPJQt2FsykeFZbCtaGXU4' },
    { index: { major: 1, minor: 2 }, address: '87KfgTZ8ER5D3Frefqnrqif11TjVsTPaTcp37kqqKMrdDRUhpJRczeR7KiBmSHF32UJLP3HHhKUDmEQyJrv2mV8yFDCq8eB' },
    { index: { major: 0, minor: 999 }, address: '8BQKgTSSqJjP14AKnZUBwnXWj46MuNmLvHfPTpmry52DbfNjjHVvHUk4mczU8nj8yZ57zBhksTJ8kM5xKeJXw55kCMVqyG7' },
  ],
  integratedAddresses: [
    { paymentID: hexToBytes('0123456789abcdef'), address: '4CMe2PUhs4J4886T7196doS9GPMzexD9gXpsZJDwVjeRVdFCSoHnv7KPbBeGpzJBzHRCAs9UxqeoyFQMYbqSWYTfSbLRB61BQVATzerHGj' },
  ],
};
