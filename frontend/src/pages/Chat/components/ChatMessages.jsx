import { Fragment } from 'react';
import {
  Avatar,
  Message,
  MessageList,
  MessageSeparator,
} from '@chatscope/chat-ui-kit-react';
import { GROUP } from '../constants';

const senderStyle = {
  fontSize: '0.72em',
  color: '#64748b',
  margin: '2px 0 2px 48px',
};

const FILE_LABEL_PATTERN = /\[File\]\s*/i;

const buildUniqueKey = message => {
  return `${message.ts}-${message.from || 'me'}-${message.fileUrl || message.text}`;
};

const extractFileName = messageText =>
  (messageText || '').replace(FILE_LABEL_PATTERN, '').split(':')[0].trim() ||
  'download.bin';

const handleDownload = message => {
  const link = document.createElement('a');
  link.href = message.fileUrl;
  link.download = extractFileName(message.text);
  document.body.appendChild(link);
  link.click();
  link.remove();
};

export default function renderChatMessages({ activePeerId, messages, avatarFor }) {
  const roomMessages = activePeerId ? messages[activePeerId] || [] : [];
  const hasMessages = roomMessages.length > 0;
  const isGroup = activePeerId === GROUP.id;

  return (
    <MessageList>
      {!activePeerId && (
        <MessageSeparator content="Select a user to start chatting" />
      )}

      {activePeerId && !hasMessages && (
        <MessageSeparator content="No messages yet" />
      )}

      {activePeerId &&
        hasMessages &&
        roomMessages.map(message => {
          const uniqueKey = buildUniqueKey(message);
          const isOutgoing = message.dir === 'out';

          return (
            <Fragment key={uniqueKey}>
              {isGroup && !isOutgoing && (
                <div
                  key={`hdr-${uniqueKey}`}
                  className="cs-message__sender-name"
                  style={senderStyle}
                >
                  {message.from || 'someone'}
                </div>
              )}
              <Message
                key={`msg-${uniqueKey}`}
                model={{
                  direction: isOutgoing ? 'outgoing' : 'incoming',
                  position: 'single',
                  sentTime: new Date(message.ts).toLocaleTimeString(),
                  sender: isOutgoing
                    ? 'Me'
                    : isGroup
                      ? message.from || 'someone'
                      : activePeerId,
                }}
              >
                {!isOutgoing && (
                  <Avatar
                    name={message.from || activePeerId}
                    src={avatarFor(message.from || activePeerId)}
                  />
                )}
                <Message.CustomContent>
                  {message.fileUrl ? (
                    <div
                      style={{ display: 'flex', alignItems: 'center', gap: 6 }}
                    >
                      <span role="img" aria-label="file">
                        📎
                      </span>
                      <strong>
                        {message.text.replace(FILE_LABEL_PATTERN, '').split(':')[0]}
                      </strong>
                      <a
                        href="#"
                        onClick={event => {
                          event.preventDefault();
                          event.stopPropagation();
                          handleDownload(message);
                        }}
                        style={{
                          marginLeft: 6,
                          color: '#2563eb',
                          textDecoration: 'underline',
                        }}
                      >
                        Download
                      </a>
                    </div>
                  ) : (
                    <span>{message.text}</span>
                  )}
                </Message.CustomContent>
              </Message>
            </Fragment>
          );
        })}
    </MessageList>
  );
}
