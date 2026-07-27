import { estimateExtraSize, estimateFee } from './tx.js';

// Fee-estimation placeholders (never returned): isChange keeps them out of classifyDestinations (no
// needAdditional flip) but still counts them in the output length. Monero's zero-change dummy is a
// change_dts too, hence classified as change:
// https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L10228-L10287
const CHANGE_OUTPUT = { isChange: true };
const DUMMY_OUTPUT = { isChange: true };

/**
 * @typedef {Omit<import('./tx.js').Destination, 'amount'> & { amount?: undefined }} SweepDestination
 *   a destination without an amount; it shares whatever is left. Only valid as a selectInputs destination.
 */

/**
 * Monero-specific input selection for a RingCT transaction.
 *
 * A destination with an `amount` is a fixed output; a destination without one is a sweep target
 * (0+ allowed) that shares whatever is left. Any sweep target switches the whole tx to sweep mode:
 * every candidate is spent and the remainder (after fixed outputs and fee) is returned as
 * `sweepAmount`, with no change. Otherwise inputs are taken largest-first until they cover the fixed
 * amount plus fee, and the leftover becomes the change output (`changeAmount`, when > 0).
 *
 * `needsDummy` is set when the real output count would be under two (monero requires >= 2 outputs);
 * the caller adds the extra output. The fee already accounts for change/dummy, so it is exact for
 * the output set the caller will build.
 *
 * Selection is a simple deterministic largest-first pick, not wallet2's randomized relatedness-based one.
 *
 * monero wallet2::create_transactions_2 (fee/change loop)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L11041
 * monero get_num_outputs (change output, and < 2 outputs -> extra dummy output)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L223-L237
 * monero wallet2::create_transactions_all (sweep: spend everything, no change)
 * https://github.com/monero-project/monero/blob/v0.18.5.0/src/wallet/wallet2.cpp#L11813
 * monero-oxide SignableTransaction validation (change-to-fee, dummy, NotEnoughFunds)
 * https://github.com/monero-oxide/monero-oxide/blob/946ec5f00ff071b129758ee8cba5528539fccfe4/monero-oxide/wallet/src/send/mod.rs#L341-L419
 *
 * @template {{ amount: bigint }} T
 *
 * @param {object} params
 * @param {T[]} params.candidates - spendable candidates, unsorted
 * @param {(import('./tx.js').Destination | SweepDestination)[]} params.destinations - fixed outputs and/or sweep targets; no entry may carry isChange
 * @param {number} params.ringSize - total ring size (decoys = ringSize - 1)
 * @param {bigint} params.baseFee
 * @param {bigint} params.feeQuantization
 * @param {bigint} [params.feeMultiplier=1n]
 * @returns {{
 *   selected: T[],
 *   fee: bigint,
 *   changeAmount?: bigint,
 *   sweepAmount?: bigint,
 *   needsDummy: boolean
 * }}
 */
export function selectInputs({
  candidates,
  destinations,
  ringSize,
  baseFee,
  feeQuantization,
  feeMultiplier = 1n,
}) {
  if (destinations.length === 0) {
    throw new Error('selectInputs: no destinations');
  }
  if (destinations.some((destination) => destination.isChange)) {
    throw new Error('selectInputs: destinations must not include change');
  }

  const mixin = ringSize - 1;
  const fixed = destinations.reduce((sum, destination) => sum + (destination.amount ?? 0n), 0n);
  const isSweep = destinations.some((destination) => destination.amount === undefined);

  // fee for the given inputs and output list (destinations plus change/dummy placeholders)
  const calculateFee = (inputs, outputs) => estimateFee(
    inputs.length, mixin, outputs.length, estimateExtraSize(outputs), baseFee, feeMultiplier, feeQuantization
  );

  if (isSweep) {
    // sweep = send everything: spend all candidates, remainder goes to the sweep targets, no change
    const needsDummy = destinations.length < 2;
    const outputs = needsDummy ? [...destinations, DUMMY_OUTPUT] : destinations;
    const fee = calculateFee(candidates, outputs);
    const sweepAmount = candidates.reduce((sum, c) => sum + c.amount, 0n) - fixed - fee;
    if (sweepAmount < 0n) {
      throw new Error('selectInputs: not enough funds');
    }
    return {
      selected: candidates,
      fee,
      sweepAmount,
      needsDummy,
    };
  }

  // normal mode: take the biggest candidates until they cover the cheapest valid tx (no change
  // output). A dummy keeps a single-destination tx at two outputs.
  const sorted = [...candidates].sort((a, b) => (b.amount > a.amount ? 1 : b.amount < a.amount ? -1 : 0));
  const noChange = destinations.length < 2 ? [...destinations, DUMMY_OUTPUT] : destinations;
  const withChange = [...destinations, CHANGE_OUTPUT];
  const selected = [];
  let sum = 0n;
  let covered = false;
  for (const candidate of sorted) {
    selected.push(candidate);
    sum += candidate.amount;
    if (sum >= fixed + calculateFee(selected, noChange)) {
      covered = true;
      break;
    }
  }
  if (!covered) {
    throw new Error('selectInputs: not enough funds');
  }

  // Add a change output only when the leftover covers the extra fee it costs; otherwise the small
  // remainder is absorbed into the fee (no change output), matching monero's "change to fee" case.
  const feeWithChange = calculateFee(selected, withChange);
  const change = sum - fixed - feeWithChange;
  if (change > 0n) {
    return {
      selected,
      fee: feeWithChange,
      changeAmount:
      change,
      needsDummy: false,
    };
  }
  return {
    selected,
    fee: sum - fixed,
    needsDummy: destinations.length < 2,
  };
}
