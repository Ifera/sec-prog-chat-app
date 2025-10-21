import React, { useMemo } from 'react';
import {
  Avatar,
  Conversation,
  ConversationList,
  Sidebar,
} from '@chatscope/chat-ui-kit-react';
import { GROUP } from '../constants';

const dedupeUsers = (onlineUsers, userId) => {
  return Array.from(
    new Map(
      onlineUsers
        .filter(u => u.userId && u.userId !== userId)
        .map(u => [u.userId, u]),
    ).values(),
  );
};

export default function ContactSidebar({
  onlineUsers,
  userId,
  activePeerId,
  onSelectPeer,
  avatarFor,
}) {
  const contacts = useMemo(
    () => dedupeUsers(onlineUsers, userId),
    [onlineUsers, userId],
  );

  return (
    <Sidebar position="left">
      <ConversationList>
        <Conversation
          key={GROUP.id}
          name={GROUP.name}
          onClick={() => onSelectPeer(GROUP.id)}
          active={activePeerId === GROUP.id}
        >
          <Avatar name={GROUP.name} src={GROUP.avatar} />
        </Conversation>
        {contacts.map(contact => {
          const uid = contact.userId;
          const isActive = activePeerId === uid;

          return (
            <Conversation
              key={uid}
              name={uid}
              onClick={() => onSelectPeer(uid)}
              active={isActive}
            >
              <Avatar name={uid} src={avatarFor(uid)} status="available" />
            </Conversation>
          );
        })}
      </ConversationList>
    </Sidebar>
  );
}
