import React, { useEffect, useState } from 'react';
import styles from './Login.module.css';
import { useSocpContext } from '../../contexts/SocpContext';

const Login = () => {
  const { auth, login } = useSocpContext();
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [localError, setLocalError] = useState('');

  useEffect(() => {
    // Bubble up server-side login errors
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

  const disabled = auth.status === 'pending';

  return (
    <section className={styles.container}>
      <form className={styles.card} onSubmit={handleSubmit}>
        <h2 className={styles.title}>Welcome</h2>
        <p className={styles.subtitle}>Input your credentials to continue</p>

        <label className={styles.label}>
          Username
          <input
            className={styles.input}
            type="text"
            value={username}
            autoComplete="username"
            onChange={(e) => setUsername(e.target.value)}
            required
            disabled={disabled}
          />
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
