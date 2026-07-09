// decoy selection mirrors monero wallet2 gamma_picker: outputs are sampled by age from a gamma
// distribution biased toward recent outputs, so the ring passes the daemon tx_sanity_check
// (median global index must be >= 60% of all rct outputs). Uniform random would fail that check.
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L1039-L1103
const DIFFICULTY_TARGET = 120;
const SPENDABLE_AGE = 10;
const DEFAULT_UNLOCK_TIME = SPENDABLE_AGE * DIFFICULTY_TARGET;
const RECENT_SPEND_WINDOW = 15 * DIFFICULTY_TARGET;
const GAMMA_SHAPE = 19.28;
const GAMMA_SCALE = 1 / 1.61;

function gaussian() {
  return Math.sqrt(-2 * Math.log(1 - Math.random())) * Math.cos(2 * Math.PI * Math.random());
}

// gamma sample for shape >= 1 (Marsaglia–Tsang)
function gammaSample(shape, scale) {
  const d = shape - 1 / 3;
  const c = 1 / Math.sqrt(9 * d);
  for (;;) {
    let x;
    let v;
    do {
      x = gaussian();
      v = 1 + c * x;
    } while (v <= 0);
    v = v * v * v;
    const u = Math.random();
    if (u < 1 - 0.0331 * x ** 4 || Math.log(u) < 0.5 * x * x + d * (1 - v + Math.log(v))) {
      return d * v * scale;
    }
  }
}

/**
 * Build a decoy picker over a cumulative rct output distribution.
 *
 * @param {number[]} rctOffsets - cumulative count of rct outputs per block (get_output_distribution)
 * @returns {() => number} pick() → a global rct output index, or -1 if it falls out of range
 */
export function gammaPicker(rctOffsets) {
  const blocksInYear = Math.floor((86400 * 365) / DIFFICULTY_TARGET);
  const blocksToConsider = Math.min(rctOffsets.length, blocksInYear);
  const outputsToConsider = rctOffsets[rctOffsets.length - 1]
    - (blocksToConsider < rctOffsets.length ? rctOffsets[rctOffsets.length - blocksToConsider - 1] : 0);
  const endIndex = rctOffsets.length - (Math.max(1, SPENDABLE_AGE) - 1);
  const numRctOutputs = rctOffsets[endIndex - 1];
  const averageOutputTime = (DIFFICULTY_TARGET * blocksToConsider) / outputsToConsider;
  return function pick() {
    let x = Math.exp(gammaSample(GAMMA_SHAPE, GAMMA_SCALE));
    x = x > DEFAULT_UNLOCK_TIME ? x - DEFAULT_UNLOCK_TIME : Math.floor(Math.random() * RECENT_SPEND_WINDOW);
    let outputIndex = Math.floor(x / averageOutputTime);
    if (outputIndex >= numRctOutputs) {
      return -1;
    }
    outputIndex = numRctOutputs - 1 - outputIndex;
    let lo = 0;
    let hi = endIndex;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (rctOffsets[mid] < outputIndex) {
        lo = mid + 1;
      } else {
        hi = mid;
      }
    }
    const firstRct = lo === 0 ? 0 : rctOffsets[lo - 1];
    const nRct = rctOffsets[lo] - firstRct;
    return nRct === 0 ? -1 : firstRct + Math.floor(Math.random() * nRct);
  };
}
