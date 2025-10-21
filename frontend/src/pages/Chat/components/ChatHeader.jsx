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
