
import assert from 'node:assert';
import ringct from '../lib/ringct.js';
import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js';
import { describe, it } from 'node:test';

describe('ringct', () => {

  describe('ecdhEncode', () => {

    it('should work for v1', () => {
      assert.deepStrictEqual(ringct.ecdhEncode({
        amount: hexToBytes('c32eac9cec686d5c9b1397d31ce8f2e5d8ccdba118724ef332da1e9854af9a0a'),
        mask: hexToBytes('0f78b8c44cc7eef45371b2faea30871552f0d74be195720f0ff9395d302a7a05'),
      }, hexToBytes('e720a09f2e3a0bbf4e4ba7ad93653bb296885510121f806acb2a5f9168fafa01'), ringct.RCTTypes.Bulletproof),
      {
        amount: hexToBytes('ce0ae31063ed7d5f87db7a312b99cadd77786cd366970e3d82e4735a2d65ce05'),
        mask: hexToBytes('b4bb3837a56b6e63eda0706c08754461fb813eac1eba083497dd149f2ddbae0d'),
      });
    });

    it('should work for v2', () => {
      assert.deepStrictEqual(ringct.ecdhEncode({
        amount: hexToBytes('bb477feedbe8a2f8000000000000000000000000000000000000000000000000'),
      }, hexToBytes('ce0ae31063ed7d5f87db7a312b99cadd77786cd366970e3d82e4735a2d65ce05'), ringct.RCTTypes.Bulletproof2),
      {
        amount: hexToBytes('e745cf6a1fe5f04a000000000000000000000000000000000000000000000000'),
        mask: new Uint8Array(32),
      });
    });
  });

  describe('ecdhDecode', () => {

    it('should work for v1', () => {
      assert.deepStrictEqual(ringct.ecdhDecode({
        amount: hexToBytes('ce0ae31063ed7d5f87db7a312b99cadd77786cd366970e3d82e4735a2d65ce05'),
        mask: hexToBytes('b4bb3837a56b6e63eda0706c08754461fb813eac1eba083497dd149f2ddbae0d'),
      }, hexToBytes('e720a09f2e3a0bbf4e4ba7ad93653bb296885510121f806acb2a5f9168fafa01'), ringct.RCTTypes.Bulletproof),
      {
        amount: hexToBytes('c32eac9cec686d5c9b1397d31ce8f2e5d8ccdba118724ef332da1e9854af9a0a'),
        mask: hexToBytes('0f78b8c44cc7eef45371b2faea30871552f0d74be195720f0ff9395d302a7a05'),
      });
    });

    it('should work for v2', () => {
      assert.deepStrictEqual(ringct.ecdhDecode({
        amount: hexToBytes('e745cf6a1fe5f04a'),
      }, hexToBytes('ce0ae31063ed7d5f87db7a312b99cadd77786cd366970e3d82e4735a2d65ce05'), ringct.RCTTypes.Bulletproof2),
      {
        amount: hexToBytes('bb477feedbe8a2f8000000000000000000000000000000000000000000000000'),
        mask: hexToBytes('13eed709380e0f6fe1eb340291a96c56dae4189a07f32c09bd0fe8b94bd4440b'),
      });
    });
  });

  describe('pedersenCommitment', () => {
    it('should work', () => {
      assert.strictEqual(bytesToHex(ringct.pedersenCommitment(
        hexToBytes('c32eac9cec686d5c9b1397d31ce8f2e5d8ccdba118724ef332da1e9854af9a0a'),
        hexToBytes('0f78b8c44cc7eef45371b2faea30871552f0d74be195720f0ff9395d302a7a05')
      )), 'a2b64f8a5f10a19d41c74714b069f6a7e78a782488e02646e3c0fb7b0d91d84b');
    });
  });

  describe('decodeRct', () => {
    it('should work', () => {
      const result = ringct.decodeRct(
        { amount: hexToBytes('e745cf6a1fe5f04a') },
        hexToBytes('59ef441cbb7f79d814f763a40d2c6a30a3c7f6ee340859711243a12e460cbf8b'),
        ringct.RCTTypes.CLSAG,
        0,
        hexToBytes('c21ac180b9702ffb85930724a28698ebf2a196bcc8ee205b159c5755f3b32a69')
      );
      assert.deepStrictEqual(result, {
        mask: hexToBytes('29888c690b7a9f99e5294d1494b684e38a1747d586c51c130b2933dcfdb7cc08'),
        amount: '1000000000000',
      });
      const result2 = ringct.decodeRct(
        { amount: hexToBytes('6d5b3047f314a32e') },
        hexToBytes('b3330c0eeccd033e4f417f858b63dada88a629148ba2bc26d214f1d29b89353b'),
        ringct.RCTTypes.CLSAG,
        1,
        hexToBytes('5c673fbe576152ce517dc463a7b9db68fcd21117a46b4ee9e4cd34b44d0a8b98')
      );
      assert.deepStrictEqual(result2, {
        mask: hexToBytes('6c75a44d7c8b34603c5bd80dfce4b3bb4c8bab190c0470374111c50d2f576f09'),
        amount: '69365204653916',
      });
    });
  });

  describe('zeroCommit', () => {
    it('should work', () => {
      const commit = ringct.zeroCommit(1038074340649);
      assert.strictEqual(bytesToHex(commit), '9a14487f7a9cce89d066bce74173817b17a5b293827c19c8fbf6b51d01594241');
    });
  });
});
