// Group 59
// ----------------------------------
// Muhammad Tayyab Rashid - a1988298
// Nguyen Duc Tung Bui - a1976012
// Guilin Luo - a1989840
// Mazharul Islam Rakib - a1990942
// Masud Ahammad - a1993200

import { currentTimestamp } from '../../utils/time';

export const createEnvelope = (type, from, to, payload, sig = '', ts = null) => {
  return {
    type,
    from,
    to,
    ts: ts ?? currentTimestamp(),
    payload,
    sig,
  };
};

export default createEnvelope;
