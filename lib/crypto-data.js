import { ed25519 } from '@noble/curves/ed25519.js';

export const A = 486662n;

// -A
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L868
export const ma = 0x7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffff892e7n;

// sqrt(-1)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L38
export const sqrtm1 = 0x2b8324804fc1df0b2b4d00993dfbd7a72f431806ad2fe478c4ee1b274a0ea0b0n;

// sqrt(-2 * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L869
export const fffb1 = 0x7e71fbefdad61b1720a9c53741fb19e3d19404a8b92a738d22a76975321c41een;

// sqrt(2 * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L870
export const fffb2 = 0x4d061e0a045a2cf691d451b7c0165fbe51de03460456f7dfd2de6483607c9ae0n;

// sqrt(-sqrt(-1) * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L871
export const fffb3 = 0x674a110d14c208efb89546403f0da2ed4024ff4ea5964229581b7d8717302c66n;

// sqrt(sqrt(-1) * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/crypto/crypto-ops-data.c#L872
export const fffb4 = 0x1a43f3031067dbf926c0f4887ef7432eee46fc08a13f4a49853d1903b6b39186n;

// rct::H — second Pedersen generator, H = 8 * ge_frombytes(cn_fast_hash(G)), G the basepoint
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctTypes.h#L633
// eslint-disable-next-line max-len
export const H = ed25519.Point.fromBytes(new Uint8Array([0x8b, 0x65, 0x59, 0x70, 0x15, 0x37, 0x99, 0xaf, 0x2a, 0xea, 0xdc, 0x9f, 0xf1, 0xad, 0xd0, 0xea, 0x6c, 0x72, 0x51, 0xd5, 0x41, 0x54, 0xcf, 0xa9, 0x2c, 0x17, 0x3a, 0x0d, 0xd3, 0x9c, 0x1f, 0x94]), false);

// rct::INV_EIGHT — 1/8 mod l (the curve order)
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctOps.h#L67
export const INV_EIGHT = 0x600000000000000000000000000000007d39db37d1cdad06106e529e2dc2f79n;
