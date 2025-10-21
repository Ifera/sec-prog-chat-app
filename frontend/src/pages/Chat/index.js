import React from 'react';
import { ChatContainer, MainContainer } from '@chatscope/chat-ui-kit-react';
import { useSocpContext } from '../../contexts/SocpContext';
import ContactSidebar from './components/ContactSidebar';
import renderChatHeader from './components/ChatHeader';
import renderChatMessages from './components/ChatMessages';
import renderChatInputBar from './components/ChatInputBar';
import { avatarFor } from './constants';

export default function ChatPage() {
  const {
    wsState,
    onlineUsers,
    userId,
    activePeerId,
    setActivePeerId,
    messages,
    sendDirectDM,
    sendPublicMessage,
    sendFile,
  } = useSocpContext();

  return (
    <div
      style={{ height: '100vh' }}
      className="d-flex flex-column overflow-hidden"
    >
      <MainContainer responsive>
        <ContactSidebar
          onlineUsers={onlineUsers}
          userId={userId}
          activePeerId={activePeerId}
          onSelectPeer={setActivePeerId}
          avatarFor={avatarFor}
        />
        <ChatContainer>
          {renderChatHeader({ activePeerId, avatarFor })}
          {renderChatMessages({ activePeerId, messages, avatarFor })}
          {renderChatInputBar({
            activePeerId,
            sendDirectDM,
            sendPublicMessage,
            sendFile,
          })}
        </ChatContainer>
      </MainContainer>
      <div
        className="text-center py-1"
        style={{ fontSize: 12, color: '#64748b' }}
      >
        SOCP WS: {wsState} | User: <b>{userId}</b>
      </div>
    </div>
  );
}
