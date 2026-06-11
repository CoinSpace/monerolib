import { ed25519 } from '@noble/curves/ed25519.js';

export const { Point } = ed25519;
export const { Fp } = Point;
export const CURVE = Point.CURVE();

export const A = 486662n;

// sqrt(-1)
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L38
// export const sqrtm1 = Fp.sqrt(Fp.neg(1n));
export const sqrtm1 = 0x547cdb7fb03e20f4d4b2ff66c2042858d0bce7f952d01b873b11e4d8b5f15f3dn;

// sqrt(-2 * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L869
// export const fffb1 = Fp.sqrt(Fp.mul(Fp.mul(Fp.add(A, 2n), A), Fp.neg(2n)));
export const fffb1 = 0x7e71fbefdad61b1720a9c53741fb19e3d19404a8b92a738d22a76975321c41een;

// sqrt(2 * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L870
// export const fffb2 = Fp.sqrt(Fp.mul(Fp.mul(Fp.add(A, 2n), A), 2n));
export const fffb2 = 0x32f9e1f5fba5d3096e2bae483fe9a041ae21fcb9fba908202d219b7c9f83650dn;

// sqrt(-sqrt(-1) * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L871
// export const fffb3 = Fp.sqrt(Fp.mul(Fp.mul(Fp.add(A, 2n), A), Fp.neg(sqrtm1)));
export const fffb3 = 0x1a43f3031067dbf926c0f4887ef7432eee46fc08a13f4a49853d1903b6b39186n;

// sqrt(sqrt(-1) * A * (A + 2))
// https://github.com/monero-project/monero/blob/v0.17.1.9/src/crypto/crypto-ops-data.c#L872
// export const fffb4 = Fp.sqrt(Fp.mul(Fp.mul(Fp.add(A, 2n), A), sqrtm1));
export const fffb4 = 0x674a110d14c208efb89546403f0da2ed4024ff4ea5964229581b7d8717302c66n;
