// Group 59
// ----------------------------------
// Muhammad Tayyab Rashid - a1988298
// Nguyen Duc Tung Bui - a1976012
// Guilin Luo - a1989840
// Mazharul Islam Rakib - a1990942
// Masud Ahammad - a1993200

import { Avatar, ConversationHeader } from '@chatscope/chat-ui-kit-react';
import { GROUP } from '../constants';

export default function renderChatHeader({ activePeerId, avatarFor }) {
  const isGroup = activePeerId === GROUP.id;
  const hasPeer = typeof activePeerId === 'string' && !!activePeerId;

  if (!hasPeer) {
    return (
      <ConversationHeader>
        <ConversationHeader.Back />
        <ConversationHeader.Content userName="Select a user..." />
      </ConversationHeader>
    );
  }

  if (isGroup) {
    return (
      <ConversationHeader>
        <ConversationHeader.Back />
        <Avatar name={GROUP.name} src={GROUP.avatar} />
        <ConversationHeader.Content userName={GROUP.name} />
      </ConversationHeader>
    );
  }

  return (
    <ConversationHeader>
      <ConversationHeader.Back />
      <Avatar name={activePeerId} src={avatarFor(activePeerId)} />
      <ConversationHeader.Content userName={activePeerId} />
    </ConversationHeader>
  );
}
