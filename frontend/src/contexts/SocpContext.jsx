// Group 59
// ----------------------------------
// Muhammad Tayyab Rashid - a1988298
// Nguyen Duc Tung Bui - a1976012
// Guilin Luo - a1989840
// Mazharul Islam Rakib - a1990942
// Masud Ahammad - a1993200

import React, {
  createContext, useCallback, useContext, useEffect, useMemo, useState, useRef,
} from 'react';
import MESSAGE_TYPES from '../constants/messageTypes';
import { ReadyState, useSocpConnection } from '../hooks/useSocpConnection';
import useSocpIdentity from '../hooks/useSocpIdentity';
import useSocpMessageHandlers from '../hooks/useSocpMessageHandlers';
import { createEnvelope } from '../services/transport/envelopeService';
import { loadPrivateKey, computeTransportSig } from '../services/crypto/cryptoService';

const SocpCtx = createContext(null);

export function SocpProvider({ children }) {
  const WS_PORT = process.env.REACT_APP_BACKEND_WS_PORT || '8080';
  const WS_URL = `wss://${window.location.hostname}:${WS_PORT}/ws`;
  const serverUri = process.env.REACT_APP_BACKEND_WS_URL || WS_URL;

  // Identity + creds
  const { userId, setUserId, privateKeyB64, publicKeyB64 } = useSocpIdentity();
  const [password, setPassword] = useState('');

  // Auth state
  const [auth, setAuth] = useState({ status: 'idle', errorCode: null, errorDetail: null });
  // status: 'idle' | 'pending' | 'authenticated' | 'error'

  // App state
  const [knownPubkeys, setKnownPubkeys] = useState({});
  const [groupKeys, setGroupKeys] = useState({});
  const [fileTransfers, setFileTransfers] = useState({});
  const [onlineUsers, setOnlineUsers] = useState([]);
  const [messages, setMessages] = useState({});
  const [activePeerId, setActivePeerId] = useState(null);
  const lastHandledRef = useRef(null);

  const { sendJsonMessage, lastJsonMessage, readyState, wsState } =
    useSocpConnection(serverUri, {
      reconnectAttempts: Number(process.env.REACT_APP_RECONNECT_ATTEMPTS) || 3,
      reconnectInterval: 2000,
    });

  // Login API for the UI
  const login = useCallback((username, pwd) => {
    setAuth({ status: 'pending', errorCode: null, errorDetail: null });
    setUserId(String(username || '').trim());
    setPassword(String(pwd || ''));
  }, [setUserId]);

  const logout = useCallback(() => {
    setAuth({ status: 'idle', errorCode: null, errorDetail: null });
    setUserId('');
    setPassword('');
    setKnownPubkeys({});
    setGroupKeys({});
    setFileTransfers({});
    setOnlineUsers([]);
    setMessages({});
    setActivePeerId(null);
  }, [setUserId]);

  // Send USER_HELLO after WS is up, we have keys, userId and password, and we're in 'pending'
  const sendUserHello = useCallback(() => {
    if (!publicKeyB64 || !privateKeyB64 || !userId || !password) return;

    const payload = {
      client: 'local-cli-v1',
      pubkey: publicKeyB64,
      enc_pubkey: publicKeyB64,
      password, 
    };

    try {
      const privKey = loadPrivateKey(privateKeyB64);
      const sig = computeTransportSig(privKey, payload);
      const body = createEnvelope(MESSAGE_TYPES.USER_HELLO, userId, 'server', payload, sig);
      sendJsonMessage(body);
      console.info('[SOCP] → USER_HELLO sent', body);
    } catch (err) {
      console.error('[SOCP] Failed to sign USER_HELLO payload:', err);
      setAuth({ status: 'error', errorCode: 'SIGN_FAILED', errorDetail: String(err?.message || err) });
    }
  }, [publicKeyB64, privateKeyB64, userId, password, sendJsonMessage]);

  useEffect(() => {
    if (
      auth.status === 'pending' &&
      readyState === ReadyState.OPEN &&
      publicKeyB64 &&
      privateKeyB64 &&
      userId &&
      password
    ) {
      sendUserHello();
    }
  }, [auth.status, readyState, publicKeyB64, privateKeyB64, userId, password, sendUserHello]);

  // Message handlers
  const {
    onUserDeliver,
    onUserAdvertise,
    onPublicChannelKeyShare,
    onPublicChannelUpdated,
    onUserRemove,
    sendDirectDM,
    sendPublicMessage,
    sendFile,
    handleFileStart,
    handleFileChunk,
    handleFileEnd,
  } = useSocpMessageHandlers({
    userId,
    privateKeyB64,
    publicKeyB64,
    knownPubkeys,
    setKnownPubkeys,
    groupKeys,
    setGroupKeys,
    setOnlineUsers,
    setActivePeerId,
    setMessages,
    fileTransfers,
    setFileTransfers,
    sendJsonMessage,
  });

  // Wrap onUserAdvertise to detect our own advertisement as "login success"
  const handleUserAdvertise = useCallback((msg) => {
    try {
      const { user_id: uid } = msg?.payload || {};
      onUserAdvertise(msg);
      if (uid && uid === userId && auth.status === 'pending') {
        setAuth({ status: 'authenticated', errorCode: null, errorDetail: null });
      }
    } catch (e) {
      console.error('[SOCP] onUserAdvertise failed:', e);
    }
  }, [onUserAdvertise, userId, auth.status]);

  useEffect(() => {
    if (!lastJsonMessage) return;
    if (lastHandledRef.current === lastJsonMessage) return;
    lastHandledRef.current = lastJsonMessage;

    const messageType = lastJsonMessage.type;

    switch (messageType) {
      case MESSAGE_TYPES.USER_DELIVER:
        onUserDeliver(lastJsonMessage).then(result => {
          if (!result || result.senderId === userId) return;
          const roomKey = result.type === 'public' ? 'public' : result.senderId;
          setMessages(prev => {
            const arr = prev[roomKey] ? [...prev[roomKey]] : [];
            arr.push({ dir: 'in', text: result.text, ts: lastJsonMessage.ts, from: result.senderId });
            return { ...prev, [roomKey]: arr };
          });
        });
        break;

      case MESSAGE_TYPES.USER_ADVERTISE:
        handleUserAdvertise(lastJsonMessage);
        break;

      case MESSAGE_TYPES.USER_REMOVE:
        onUserRemove(lastJsonMessage, knownPubkeys);
        break;

      case MESSAGE_TYPES.PUBLIC_CHANNEL_KEY_SHARE:
        onPublicChannelKeyShare(lastJsonMessage);
        break;

      case MESSAGE_TYPES.PUBLIC_CHANNEL_UPDATED:
        onPublicChannelUpdated(lastJsonMessage);
        break;

      case MESSAGE_TYPES.FILE_START:
        handleFileStart(lastJsonMessage);
        break;

      case MESSAGE_TYPES.FILE_CHUNK:
        handleFileChunk(lastJsonMessage);
        break;

      case MESSAGE_TYPES.FILE_END:
        handleFileEnd(lastJsonMessage);
        break;

      case MESSAGE_TYPES.ERROR: {
        console.error('[SOCP] ← ERROR', lastJsonMessage);
        // Only treat as login error if we're authenticating
        const allowed = new Set(['USER_NOT_FOUND', 'INVALID_PUBLIC_KEY', 'INVALID_PASSWORD', 'NAME_IN_USE']);
        const code = lastJsonMessage?.payload?.code;
        const detail = lastJsonMessage?.payload?.detail || 'Unknown error';
        if (auth.status === 'pending' && allowed.has(code)) {
          setAuth({ status: 'error', errorCode: code, errorDetail: detail });
        }
        break;
      }

      default:
        console.warn('[SOCP] ← Unknown message type', lastJsonMessage);
        break;
    }
  }, [
    lastJsonMessage,
    onUserDeliver,
    handleUserAdvertise,
    onUserRemove,
    onPublicChannelKeyShare,
    onPublicChannelUpdated,
    handleFileStart,
    handleFileChunk,
    handleFileEnd,
    userId,
    knownPubkeys,
    auth.status,
  ]);

  const value = useMemo(() => ({
    // identity + auth
    userId,
    auth,
    login,
    logout,

    // connection state
    wsState,

    // chat state/actions
    onlineUsers,
    messages,
    activePeerId,
    fileTransfers,
    setActivePeerId,
    sendDirectDM,
    sendPublicMessage,
    sendFile,
  }), [
    userId, auth, login, logout,
    wsState, onlineUsers, messages, activePeerId, fileTransfers,
    sendDirectDM, sendPublicMessage, sendFile,
  ]);

  return <SocpCtx.Provider value={value}>{children}</SocpCtx.Provider>;
}

export function useSocpContext() {
  const ctx = useContext(SocpCtx);
  if (!ctx) throw new Error('useSocpContext must be used within SocpProvider');
  return ctx;
}
