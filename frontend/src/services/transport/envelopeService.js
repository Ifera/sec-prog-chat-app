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
