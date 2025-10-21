import { useMemo } from 'react';
import useWebSocket, { ReadyState } from 'react-use-websocket';

const READY_STATE_LABEL = {
  [ReadyState.UNINSTANTIATED]: 'idle',
  [ReadyState.CONNECTING]: 'connecting',
  [ReadyState.OPEN]: 'connected',
  [ReadyState.CLOSING]: 'closing',
  [ReadyState.CLOSED]: 'disconnected',
};

export const useSocpConnection = (
  serverUri,
  {
    share = true,
    reconnectAttempts = 3,
    reconnectInterval = 2000,
    onOpen,
    onClose,
    onError,
    shouldReconnect,
  } = {},
) => {
  const socket = useWebSocket(serverUri, {
    share,
    reconnectAttempts,
    reconnectInterval,
    shouldReconnect: shouldReconnect ?? (() => true),
    onOpen,
    onClose,
    onError,
  });

  const wsState = useMemo(() => READY_STATE_LABEL[socket.readyState], [socket.readyState]);

  return {
    ...socket,
    wsState,
  };
};

export { ReadyState } from 'react-use-websocket';
