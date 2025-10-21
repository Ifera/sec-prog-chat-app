import { MessageInput } from '@chatscope/chat-ui-kit-react';
import { GROUP } from '../constants';

const createFileInput = () => {
  const input = document.createElement('input');
  input.type = 'file';
  return input;
};

export default function renderChatInputBar({
  activePeerId,
  sendDirectDM,
  sendPublicMessage,
  sendFile,
}) {
  const handleSend = text => {
    if (!activePeerId || !text.trim()) return;
    if (activePeerId === GROUP.id) {
      sendPublicMessage(text.trim());
    } else {
      sendDirectDM(activePeerId, text.trim());
    }
  };

  const handleAttach = () => {
    if (!activePeerId) return;
    const input = createFileInput();
    input.onchange = event => {
      const file = event.target.files?.[0];
      if (!file) return;
      const mode = activePeerId === GROUP.id ? 'public' : 'dm';
      const target = activePeerId === GROUP.id ? GROUP.id : activePeerId;
      sendFile(target, file, mode);
    };
    input.click();
  };

  return (
    <MessageInput
      placeholder={
        activePeerId
          ? `Message ${activePeerId === GROUP.id ? GROUP.name : activePeerId}`
          : 'Select a user to start chatting...'
      }
      onSend={handleSend}
      onAttachClick={handleAttach}
      disabled={!activePeerId}
    />
  );
}
