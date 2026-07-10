import { concatBytes, utf8ToBytes } from '@noble/hashes/utils.js';

import { INV_EIGHT } from './crypto-data.js';
import { encodeInt } from './helpers.js';
import {
  Fn,
  Point,
  decodePoint,
  decodeScalar,
  encodePoint,
  hashToEc,
  hashToScalar,
  randomScalar,
} from './crypto.js';

/**
 * @typedef {object} ClsagSignature
 * @property {Uint8Array[]} s
 * @property {Uint8Array} c1
 * @property {Uint8Array} I - key image
 * @property {Uint8Array} D - auxiliary key image
 */

/**
 * @typedef {object} ClsagSigner
 * @property {number} index - the real output's position in the ring
 * @property {bigint} secretKey - the real output one-time secret key
 * @property {bigint} commitmentScalar - inputMask - pseudoOutMask
 */

// Domain-separation tags, each a 32-byte block: the ascii tag zero-padded (monero memcpy of len-1).
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/cryptonote_config.h#L256-L258
const domain = (tag) => {
  const out = new Uint8Array(32);
  out.set(utf8ToBytes(tag));
  return out;
};
const HASH_KEY_CLSAG_AGG_0 = domain('CLSAG_agg_0');
const HASH_KEY_CLSAG_AGG_1 = domain('CLSAG_agg_1');
const HASH_KEY_CLSAG_ROUND = domain('CLSAG_round');

// aggregation scalar: Hs(tag || P || C_nonzero || I || D || C_offset)
const aggHash = (tag, P, Cnonzero, I, D, pseudoOut) =>
  hashToScalar(tag, ...P, ...Cnonzero, I, D, pseudoOut);

const buildAggregationScalars = (P, Cnonzero, I, D, pseudoOut) => ({
  muP: aggHash(HASH_KEY_CLSAG_AGG_0, P, Cnonzero, I, D, pseudoOut),
  muC: aggHash(HASH_KEY_CLSAG_AGG_1, P, Cnonzero, I, D, pseudoOut),
});

const buildRoundHash = (P, Cnonzero, pseudoOut, message) => {
  const roundPrefix = concatBytes(HASH_KEY_CLSAG_ROUND, ...P, ...Cnonzero, pseudoOut, message);
  return (L, R) => hashToScalar(roundPrefix, L, R);
};

const prepareRing = (ring, pseudoOutPoint) => {
  const P = ring.map((member) => member.publicKey);
  const Cnonzero = ring.map((member) => member.commitment);
  return {
    P,
    Cnonzero,
    Ppoints: P.map((publicKey) => decodePoint(publicKey)),
    Cpoints: Cnonzero.map((commitment) => decodePoint(commitment).subtract(pseudoOutPoint)),
    Phashes: P.map((publicKey) => hashToEc(publicKey)),
  };
};

const computeRound = (roundContext, memberIndex, scalar, challenge) => {
  const {
    preparedRing, muP, muC, keyImagePoint, auxiliaryImagePoint,
  } = roundContext;
  const challengeP = Fn.mul(muP, challenge);
  const challengeC = Fn.mul(muC, challenge);
  const L = Point.BASE.multiplyUnsafe(scalar)
    .add(preparedRing.Ppoints[memberIndex].multiplyUnsafe(challengeP))
    .add(preparedRing.Cpoints[memberIndex].multiplyUnsafe(challengeC));
  const R = preparedRing.Phashes[memberIndex].multiplyUnsafe(scalar)
    .add(keyImagePoint.multiplyUnsafe(challengeP))
    .add(auxiliaryImagePoint.multiplyUnsafe(challengeC));
  return {
    L: encodePoint(L),
    R: encodePoint(R),
  };
};

/**
 * CLSAG ring signature over a single input (the rct "simple" form).
 * Ports CLSAG_Gen + proveRctCLSAGSimple + the default-device clsag_prepare/hash/sign.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L241-L363
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L764-L791
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/device/device_default.cpp#L419-L440
 *
 * Math:
 * build key images I = p*Hp(P[l]) and D = (mask_in - mask_pseudoOut)*Hp(P[l]),
 * derive aggregation scalars mu_P and mu_C from the ring transcript, then walk the ring with
 * L_i = s_i*G + c*mu_P*P_i + c*mu_C*(C_i - C_out)
 * R_i = s_i*Hp(P_i) + c*mu_P*I + c*mu_C*D
 * and close it with s_l = alpha - c*(mu_P*p + mu_C*z).
 *
 * @param {Uint8Array} message - 32-byte signature message (get_pre_mlsag_hash)
 * @param {{
 *   publicKey: Uint8Array,
 *   commitment: Uint8Array
 * }[]} ring - ring members (output key + commitment)
 * @param {Uint8Array} pseudoOut - 32-byte pseudoOut commitment (C_offset)
 * @param {ClsagSigner} signer
 * @returns {ClsagSignature}
 */
export function proveClsag(message, ring, pseudoOut, signer) {
  const {
    index, secretKey, commitmentScalar,
  } = signer;
  const n = ring.length;
  if (n < 1 || !Number.isInteger(index) || index < 0 || index >= n) {
    throw new Error('proveClsag: signing index out of range');
  }
  const preparedRing = prepareRing(ring, decodePoint(pseudoOut));

  const signerHashPoint = preparedRing.Phashes[index];
  const keyImagePoint = signerHashPoint.multiplyUnsafe(secretKey);
  const auxiliaryImagePoint = signerHashPoint.multiplyUnsafe(commitmentScalar);
  const keyImage = encodePoint(keyImagePoint);
  const auxiliaryImage = encodePoint(auxiliaryImagePoint.multiplyUnsafe(INV_EIGHT));

  const alpha = randomScalar();

  const { muP, muC } = buildAggregationScalars(
    preparedRing.P,
    preparedRing.Cnonzero,
    keyImage,
    auxiliaryImage,
    pseudoOut
  );
  const roundHash = buildRoundHash(preparedRing.P, preparedRing.Cnonzero, pseudoOut, message);
  const roundContext = {
    preparedRing,
    muP,
    muC,
    keyImagePoint,
    auxiliaryImagePoint,
  };

  const s = new Array(n);
  const firstRingIndex = (index + 1) % n;
  let challenge = roundHash(
    encodePoint(Point.BASE.multiplyUnsafe(alpha)),
    encodePoint(signerHashPoint.multiplyUnsafe(alpha))
  );
  let c1 = firstRingIndex === 0 ? challenge : undefined;

  for (let step = 0; step < n - 1; step++) {
    const memberIndex = (firstRingIndex + step) % n;
    const response = randomScalar();
    s[memberIndex] = encodeInt(response);

    const { L, R } = computeRound(roundContext, memberIndex, response, challenge);
    const nextChallenge = roundHash(L, R);
    if ((memberIndex + 1) % n === 0) {
      c1 = nextChallenge;
    }
    challenge = nextChallenge;
  }

  // s[l] = alpha - c*(mu_P*p + mu_C*z), as device_default clsag_sign (sc_muladd then sc_mulsub)
  const aggregatedSecret = Fn.add(Fn.mul(muP, secretKey), Fn.mul(muC, commitmentScalar));
  s[index] = encodeInt(Fn.sub(alpha, Fn.mul(challenge, aggregatedSecret)));

  return {
    s, c1: encodeInt(c1), I: keyImage, D: auxiliaryImage,
  };
}

/**
 * Verify a CLSAG signature.
 * Ports verRctCLSAGSimple.
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/ringct/rctSigs.cpp#L872-L985
 *
 * Math:
 * reconstruct the same aggregation scalars and replay the ring equations
 * L_i = s_i*G + c*mu_P*P_i + c*mu_C*(C_i - C_out)
 * R_i = s_i*Hp(P_i) + c*mu_P*I + c*mu_C*D
 * around the full ring; the signature is valid iff the final challenge closes back to c1.
 *
 * @param {Uint8Array} message - 32-byte signature message
 * @param {{
 *   publicKey: Uint8Array,
 *   commitment: Uint8Array
 * }[]} ring - ring members
 * @param {Uint8Array} pseudoOut - 32-byte pseudoOut commitment (C_offset)
 * @param {ClsagSignature} signature
 * @returns {boolean}
 */
export function verifyClsag(message, ring, pseudoOut, signature) {
  try {
    const n = ring.length;
    if (n < 1 || signature.s.length !== n) {
      return false;
    }
    const responses = signature.s.map((scalar) => decodeScalar(scalar, 'Bad signature scalar'));
    const initialChallenge = decodeScalar(signature.c1, 'Bad signature commitment');

    const keyImagePoint = decodePoint(signature.I);
    if (keyImagePoint.is0()) {
      return false;
    }
    const fullAuxiliaryImagePoint = decodePoint(signature.D).clearCofactor();
    if (fullAuxiliaryImagePoint.is0()) {
      return false;
    }

    const preparedRing = prepareRing(ring, decodePoint(pseudoOut));
    const { muP, muC } = buildAggregationScalars(
      preparedRing.P,
      preparedRing.Cnonzero,
      signature.I,
      signature.D,
      pseudoOut
    );
    const roundHash = buildRoundHash(preparedRing.P, preparedRing.Cnonzero, pseudoOut, message);
    const roundContext = {
      preparedRing,
      muP,
      muC,
      keyImagePoint,
      auxiliaryImagePoint: fullAuxiliaryImagePoint,
    };

    let challenge = initialChallenge;
    for (const [memberIndex, response] of responses.entries()) {
      const { L, R } = computeRound(roundContext, memberIndex, response, challenge);
      const nextChallenge = roundHash(L, R);
      if (nextChallenge === 0n) {
        return false;
      }
      challenge = nextChallenge;
    }
    return Fn.sub(challenge, initialChallenge) === 0n;
  } catch {
    return false;
  }
}
