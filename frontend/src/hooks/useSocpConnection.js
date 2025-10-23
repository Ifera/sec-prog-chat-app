// Group 59
// ----------------------------------
// Muhammad Tayyab Rashid - a1988298
// Nguyen Duc Tung Bui - a1976012
// Guilin Luo - a1989840
// Mazharul Islam Rakib - a1990942
// Masud Ahammad - a1993200

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
