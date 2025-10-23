// Group 59
// ----------------------------------
// Muhammad Tayyab Rashid - a1988298
// Nguyen Duc Tung Bui - a1976012
// Guilin Luo - a1989840
// Mazharul Islam Rakib - a1990942
// Masud Ahammad - a1993200

import React, { useEffect, useState } from 'react';
import styles from './Login.module.css';
import { useSocpContext } from '../../contexts/SocpContext';

const Login = () => {
  const { auth, login } = useSocpContext();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [localError, setLocalError] = useState('');

  useEffect(() => {
    if (auth.status === 'error') {
      setLocalError(auth.errorDetail || auth.errorCode || 'Login failed');
    } else {
      setLocalError('');
    }
  }, [auth]);

  const handleSubmit = (e) => {
    e.preventDefault();
    if (!username.trim() || !password) {
      setLocalError('Username and password are required');
      return;
    }
    setLocalError('');
    login(username.trim(), password);
  };

  const handleRandom = () => {
    const id = crypto.randomUUID();
    setUsername(id);
    setLocalError('');
  };

  const disabled = auth.status === 'pending';

  return (
    <section className={styles.container}>
      <form className={styles.card} onSubmit={handleSubmit}>
        <h2 className={styles.title}>Welcome</h2>
        <p className={styles.subtitle}>Input your credentials to continue</p>

        <label className={styles.label}>
          Username
          <div className={styles.inputWrapper}>
            <input
              className={`${styles.input} ${styles.inputWithButton}`}
              type="text"
              value={username}
              autoComplete="username"
              onChange={(e) => setUsername(e.target.value)}
              required
              disabled={disabled}
            />
            <button
              type="button"
              className={styles.randomBtn}
              onClick={handleRandom}
              disabled={disabled}
              aria-label="Generate random username"
              title="Generate random username"
            >
              Random
            </button>
          </div>
        </label>

        <label className={styles.label}>
          Password
          <input
            className={styles.input}
            type="password"
            value={password}
            autoComplete="current-password"
            onChange={(e) => setPassword(e.target.value)}
            required
            disabled={disabled}
          />
        </label>

        {(localError || auth.errorDetail) && (
          <p className={styles.error}>
            {localError || auth.errorDetail}
          </p>
        )}

        <button className={styles.button} type="submit" disabled={disabled}>
          {disabled ? 'Proceeding...' : 'Proceed'}
        </button>
      </form>
    </section>
  );
};

export default Login;
