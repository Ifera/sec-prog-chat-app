import React, {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  useRef,
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

  const { userId, privateKeyB64, publicKeyB64 } = useSocpIdentity();

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

  const sendUserHello = useCallback(() => {
    if (!publicKeyB64 || !privateKeyB64 || !userId) return;

    const payload = {
      client: 'local-cli-v1',
      pubkey: publicKeyB64,
      enc_pubkey: publicKeyB64,
    };

    try {
      const privKey = loadPrivateKey(privateKeyB64);
      const sig = computeTransportSig(privKey, payload);
      const body = createEnvelope(
        MESSAGE_TYPES.USER_HELLO,
        userId,
        'server',
        payload,
        sig,
      );
      sendJsonMessage(body);
      console.info('[SOCP] → USER_HELLO sent', body);
    } catch (err) {
      console.error('[SOCP] Failed to sign USER_HELLO payload:', err);
    }
  }, [publicKeyB64, privateKeyB64, userId, sendJsonMessage]);

  useEffect(() => {
    if (
      readyState === ReadyState.OPEN &&
      publicKeyB64 &&
      privateKeyB64 &&
      userId
    ) {
      console.log('[SOCP] Conditions met → sending USER_HELLO');
      sendUserHello();
    }
  }, [
    readyState,
    publicKeyB64,
    privateKeyB64,
    userId,
    sendUserHello,
  ]);

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

  useEffect(() => {
    if (!lastJsonMessage) return;
    const messageType = lastJsonMessage.type;
    
    if (lastHandledRef.current === lastJsonMessage) return;
    lastHandledRef.current = lastJsonMessage;
    switch (messageType) {
      case MESSAGE_TYPES.USER_DELIVER:
        onUserDeliver(lastJsonMessage).then(result => {
          if (!result || result.senderId === userId) return;
          const roomKey =
            result.type === 'public' ? 'public' : result.senderId;

          setMessages(prev => {
            const arr = prev[roomKey] ? [...prev[roomKey]] : [];
            arr.push({
              dir: 'in',
              text: result.text,
              ts: lastJsonMessage.ts,
              from: result.senderId,
            });
            return { ...prev, [roomKey]: arr };
          });
        });
        break;
      case MESSAGE_TYPES.USER_ADVERTISE:
        onUserAdvertise(lastJsonMessage);
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
        console.log("here");
        
        handleFileChunk(lastJsonMessage);
        break;
      case MESSAGE_TYPES.FILE_END:
        handleFileEnd(lastJsonMessage);
        break;
      case MESSAGE_TYPES.ERROR:
        console.error('[SOCP] ← ERROR', lastJsonMessage);
        break;
      default:
        console.warn('[SOCP] ← Unknown message type', lastJsonMessage);
        break;
    }
  }, [
    lastJsonMessage,
    onUserDeliver,
    onUserAdvertise,
    onUserRemove,
    onPublicChannelKeyShare,
    onPublicChannelUpdated,
    handleFileStart,
    handleFileChunk,
    handleFileEnd,
    userId,
  ]);

  const value = useMemo(
    () => ({
      userId,
      wsState,
      onlineUsers,
      messages,
      activePeerId,
      fileTransfers,
      setActivePeerId,
      sendDirectDM,
      sendPublicMessage,
      sendFile,
    }),
    [
      userId,
      wsState,
      onlineUsers,
      messages,
      activePeerId,
      fileTransfers,
      sendDirectDM,
      sendPublicMessage,
      sendFile,
    ],
  );

  return <SocpCtx.Provider value={value}>{children}</SocpCtx.Provider>;
}

export function useSocpContext() {
  const ctx = useContext(SocpCtx);
  if (!ctx) throw new Error('useSocpContext must be used within SocpProvider');
  return ctx;
}
