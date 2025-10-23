// Group 59
// ----------------------------------
// Muhammad Tayyab Rashid - a1988298
// Nguyen Duc Tung Bui - a1976012
// Guilin Luo - a1989840
// Mazharul Islam Rakib - a1990942
// Masud Ahammad - a1993200

import { useEffect, useState } from 'react';
import { generateRsaKeypair } from '../services/crypto/cryptoService';

export const useSocpIdentity = () => {
  const [userId, setUserId] = useState('');
  const [privateKeyB64, setPrivateKeyB64] = useState(null);
  const [publicKeyB64, setPublicKeyB64] = useState(null);

  useEffect(() => {
    // Generate keys once on mount
    generateRsaKeypair().then(({ private_key_b64, public_key_b64 }) => {
      setPrivateKeyB64(private_key_b64);
      setPublicKeyB64(public_key_b64);
    });
  }, []);

  return {
    userId,
    setUserId,
    privateKeyB64,
    publicKeyB64,
  };
};

export default useSocpIdentity;
