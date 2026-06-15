import { ed25519 } from '@noble/curves/ed25519.js';

export const { Point } = ed25519;
export const { Fp } = Point;
export const CURVE = Point.CURVE();

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
