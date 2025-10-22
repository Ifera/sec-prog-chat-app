import { useCallback } from 'react';
import {
  aesDecrypt,
  aesEncrypt,
  computeContentSig,
  computePublicContentSig,
  computeTransportSig,
  loadPrivateKey,
  loadPublicKey as loadPublicKeyOAEP,
  rsaDecrypt,
  rsaEncrypt,
  utf8ToBytes,
  verifyContentSig,
  verifyPublicContentSig,
} from '../services/crypto/cryptoService';
import { sha256 } from 'js-sha256';
import MESSAGE_TYPES from '../constants/messageTypes';
import { createEnvelope } from '../services/transport/envelopeService';
import { currentTimestamp } from '../utils/time';

export const useSocpMessageHandlers = ({
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
}) => {
  const createSignedEnvelope = useCallback(
    (type, to, payload, ts, privKeyOverride = null) => {
      if (!userId) {
        console.error('[SOCP] Cannot create envelope without userId');
        return null;
      }

      let signer = privKeyOverride;
      if (!signer) {
        if (!privateKeyB64) {
          console.error('[SOCP] Missing private key for transport signature');
          return null;
        }
        try {
          signer = loadPrivateKey(privateKeyB64);
        } catch (err) {
          console.error(
            '[SOCP] Failed to load private key for transport signature:',
            err,
          );
          return null;
        }
      }

      try {
        const sig = computeTransportSig(signer, payload);
        return createEnvelope(type, userId, to, payload, sig, ts);
      } catch (err) {
        console.error('[SOCP] Failed to compute transport signature:', err);
        return null;
      }
    },
    [privateKeyB64, userId],
  );

  const onUserDeliver = useCallback(
    async msg => {
      try {
        const {
          payload: { ciphertext, sender: senderId, sender_pub: senderPubB64, content_sig: contentSig } = {},
          to,
          ts,
        } = msg;
        const privKey = await loadPrivateKey(privateKeyB64);
        const senderPub = await loadPublicKeyOAEP(senderPubB64);

        try {
          const plaintext = await rsaDecrypt(privKey, ciphertext);
          const verified = await verifyContentSig(
            senderPub,
            ciphertext,
            senderId,
            to,
            ts,
            contentSig,
          );
          if (verified) {
            const text = new TextDecoder().decode(plaintext);
            console.info(`[DM] ${senderId}: ${text}`);
            return { type: 'dm', senderId, text };
          }
        } catch (err) {
          console.error('[SOCP] Failed to decrypt direct message:', err);
        }

        if (!groupKeys['public']) {
          console.error("[SOCP] No group key for 'public', message discarded");
          return null;
        }

        try {
          const aesKey = groupKeys['public'];
          const plaintext = await aesDecrypt(aesKey, ciphertext);
          const verified = await verifyPublicContentSig(
            senderPub,
            ciphertext,
            senderId,
            ts,
            contentSig,
          );
          if (verified) {
            console.info(`[PUB] ${senderId}: ${plaintext}`);
            return { type: 'public', senderId, text: plaintext };
          }
        } catch (err) {
          console.error('[SOCP] Failed to decrypt public message:', err);
        }

        console.error(
          '[SOCP] Unable to decrypt message: neither DM nor public',
        );
        return null;
      } catch (err) {
        console.error('[SOCP] message processing failed:', err);
        return null;
      }
    },
    [privateKeyB64, groupKeys],
  );

  const onUserAdvertise = useCallback(
    msg => {
      try {
        const { user_id: uid, pubkey: pub, meta } = msg.payload || {};
        if (!uid || !pub) return;

        setKnownPubkeys(prev => {
          return { ...prev, [uid]: pub };
        });

        if (uid === userId) return;

        setOnlineUsers(prev => {
          if (prev.some(u => u.userId === uid)) return prev;
          console.info('[SOCP] user online:', uid);
          return [...prev, { userId: uid, meta: meta || {} }];
        });
      } catch (err) {
        console.error('[SOCP] Failed to handle USER_ADVERTISE:', err);
      }
    },
    [userId, setKnownPubkeys, setOnlineUsers],
  );

  const onPublicChannelKeyShare = useCallback(
    async msg => {
      try {
        const payload = msg.payload || {};
        const shares = payload.shares || [];
        if (!privateKeyB64 || !Array.isArray(shares) || shares.length === 0)
          return;

        const myShare = shares.find(s => s.member === userId);
        if (!myShare || !myShare.wrapped_public_channel_key) return;

        try {
          const privKey = await loadPrivateKey(privateKeyB64);
          const groupKeyBuf = await rsaDecrypt(
            privKey,
            myShare.wrapped_public_channel_key,
          );

          setGroupKeys(prev => ({
            ...prev,
            public: groupKeyBuf,
          }));

          console.info('[SOCP] Received group key for public channel');
        } catch (e) {
          console.error('[SOCP] Failed to decrypt public channel key:', e);
        }
      } catch (err) {
        console.error('[SOCP] Bad PUBLIC_CHANNEL_KEY_SHARE payload:', err);
      }
    },
    [userId, privateKeyB64, setGroupKeys],
  );

  const onPublicChannelUpdated = useCallback(
    async msg => {
      try {
        const payload = msg.payload || {};
        const wraps = payload.wraps || [];
        if (!privateKeyB64 || !Array.isArray(wraps) || wraps.length === 0)
          return;

        const myWrap = wraps.find(wrap => wrap.member_id === userId);
        if (!myWrap || !myWrap.wrapped_key) return;

        try {
          const privKey = await loadPrivateKey(privateKeyB64);
          const groupKeyBuf = await rsaDecrypt(privKey, myWrap.wrapped_key);

          setGroupKeys(prev => ({
            ...prev,
            public: groupKeyBuf,
          }));

          console.info(
            '[SOCP] Received group key for public channel via update',
          );
        } catch (e) {
          console.error(
            '[SOCP] Failed to decrypt public channel key via update:',
            e,
          );
        }
      } catch (err) {
        console.error('[SOCP] Bad PUBLIC_CHANNEL_UPDATED payload:', err);
      }
    },
    [userId, privateKeyB64, setGroupKeys],
  );

  const onUserRemove = useCallback(
    (msg, knownPubkeys) => {
      try {
        const { user_id: uid } = msg.payload || {};
        if (!uid) return;
        const hadKey = Boolean(knownPubkeys[uid]);
        if (!hadKey) return;
        setKnownPubkeys(prev => {
          // eslint-disable-next-line no-unused-vars
          const { [uid]: _removedValue, ...rest } = prev;
          return rest;
        });

        console.info('[SOCP] User offline:', uid);

        setOnlineUsers(prev => prev.filter(u => u.userId !== uid));
        setActivePeerId(curr => (curr === uid ? null : curr));
      } catch (err) {
        console.error('[SOCP] Bad USER_REMOVE payload:', err);
      }
    },
    [setKnownPubkeys, setOnlineUsers, setActivePeerId],
  );

  const sendDirectDM = useCallback(
    async (targetId, messageText) => {
      if (!targetId || !messageText?.trim()) return;

      const targetPubB64 = knownPubkeys[targetId];
      if (!targetPubB64) {
        console.error(`[SOCP] Unknown user: ${targetId}`);
        return;
      }

      try {
        const targetPubKey = await loadPublicKeyOAEP(targetPubB64);
        const privKey = await loadPrivateKey(privateKeyB64);

        const ciphertext = await rsaEncrypt(targetPubKey, messageText);
        const ts = currentTimestamp();

        const contentSig = await computeContentSig(
          privKey,
          ciphertext,
          userId,
          targetId,
          ts,
        );

        const dmPayload = {
          ciphertext,
          sender_pub: publicKeyB64,
          content_sig: contentSig,
        };

        const body = createSignedEnvelope(
          MESSAGE_TYPES.MSG_DIRECT,
          targetId,
          dmPayload,
          ts,
          privKey,
        );

        if (body) {
          sendJsonMessage(body);
        }

        setMessages(prev => {
          const arr = prev[targetId] ? [...prev[targetId]] : [];
          arr.push({ dir: 'out', text: messageText.trim(), ts });
          return { ...prev, [targetId]: arr };
        });
      } catch (err) {
        console.error('[SOCP] sendDirectDM failed:', err);
      }
    },
    [
      knownPubkeys,
      privateKeyB64,
      publicKeyB64,
      userId,
      createSignedEnvelope,
      sendJsonMessage,
      setMessages,
    ],
  );

  const sendPublicMessage = useCallback(
    async messageText => {
      if (!messageText?.trim()) return;

      const pubKey = groupKeys['public'];
      if (!pubKey) {
        console.error('[SOCP] No group key for public channel');
        return;
      }

      try {
        const ciphertext = await aesEncrypt(pubKey, messageText);

        const ts = currentTimestamp();

        const privKey = await loadPrivateKey(privateKeyB64);
        const contentSig = await computePublicContentSig(
          privKey,
          ciphertext,
          userId,
          ts,
        );

        const pubPayload = {
          ciphertext,
          sender_pub: publicKeyB64,
          content_sig: contentSig,
        };

        const body = createSignedEnvelope(
          MESSAGE_TYPES.MSG_PUBLIC_CHANNEL,
          'public',
          pubPayload,
          ts,
          privKey,
        );

        if (body) {
          sendJsonMessage(body);
        }

        setMessages(prev => {
          const arr = prev.public ? [...prev.public] : [];
          arr.push({ dir: 'out', text: messageText.trim(), ts });
          return { ...prev, public: arr };
        });
      } catch (err) {
        console.error('[SOCP] sendPublicMessage failed:', err);
      }
    },
    [
      groupKeys,
      privateKeyB64,
      publicKeyB64,
      userId,
      createSignedEnvelope,
      sendJsonMessage,
      setMessages,
    ],
  );

  const sendFile = useCallback(
    async (targetIdOrPublic, file, mode = 'dm') => {
      try {
        if (!file || !(file instanceof File)) return;

        const to = mode === 'public' ? 'public' : targetIdOrPublic;
        const ts = currentTimestamp();
        const fileId = crypto.randomUUID();

        const privKey = await loadPrivateKey(privateKeyB64);
        let targetPubKey = null;
        let aesKey = null;

        if (mode === 'public') {
          aesKey = groupKeys['public'];
        } else {
          const targetPubB64 = knownPubkeys[targetIdOrPublic];
          if (!targetPubB64) {
            console.error(`[SOCP] Unknown user: ${targetIdOrPublic}`);
            return;
          }
          targetPubKey = await loadPublicKeyOAEP(targetPubB64);
        }

        const fileBuf = await file.arrayBuffer();
        const hash = sha256(new Uint8Array(fileBuf));

        const startPayload = {
          file_id: fileId,
          name: file.name,
          size: file.size,
          sha256: hash,
          mode,
        };

        const fileStart = createSignedEnvelope(
          MESSAGE_TYPES.FILE_START,
          to,
          startPayload,
          ts,
          privKey,
        );
        if (fileStart) {
          sendJsonMessage(fileStart);
        }

        const buf = await file.arrayBuffer();
        const u8 = new Uint8Array(buf);
        const chunkSize = 400;
        const totalChunks = Math.ceil(u8.length / chunkSize);

        for (let i = 0; i < totalChunks; i++) {
          const part = u8.subarray(
            i * chunkSize,
            Math.min((i + 1) * chunkSize, u8.length),
          );
          let ciphertext;
          let contentSig;
          const tsChunk = currentTimestamp();

          if (mode === 'public') {
            ciphertext = await aesEncrypt(aesKey, part);
            contentSig = await computePublicContentSig(
              privKey,
              ciphertext,
              userId,
              tsChunk,
            );
          } else {
            ciphertext = await rsaEncrypt(targetPubKey, part);
            contentSig = await computeContentSig(
              privKey,
              ciphertext,
              userId,
              to,
              tsChunk,
            );
          }

          const chunkPayload = {
            file_id: fileId,
            index: i,
            ciphertext,
            content_sig: contentSig,
          };

          const fileChunk = createSignedEnvelope(
            MESSAGE_TYPES.FILE_CHUNK,
            to,
            chunkPayload,
            tsChunk,
            privKey,
          );
          if (fileChunk) {
            sendJsonMessage(fileChunk);
          }
        }

        const endPayload = { file_id: fileId, total_chunks: totalChunks };
        const fileEnd = createSignedEnvelope(
          MESSAGE_TYPES.FILE_END,
          to,
          endPayload,
          ts,
          privKey,
        );
        if (fileEnd) {
          sendJsonMessage(fileEnd);
        }

        const url = URL.createObjectURL(
          new Blob([u8], { type: 'application/octet-stream' }),
        );
        const roomKey = mode === 'public' ? 'public' : targetIdOrPublic;
        setMessages(prev => {
          const arr = prev[roomKey] ? [...prev[roomKey]] : [];
          arr.push({
            dir: 'out',
            text: `[File] ${file.name}`,
            fileUrl: url,
            ts,
          });
          return { ...prev, [roomKey]: arr };
        });
      } catch (err) {
        console.error('[SOCP] sendFile failed:', err);
      }
    },
    [
      sendJsonMessage,
      userId,
      setMessages,
      privateKeyB64,
      knownPubkeys,
      groupKeys,
      createSignedEnvelope,
    ],
  );

  const handleFileStart = useCallback(
    msg => {
      if (msg.from === userId) return;
      const { file_id, name, size, mode } = msg.payload || {};
      if (!file_id || !name) return;
      console.info(
        '[FILE_START] id=%s name=%s size=%s mode=%s',
        file_id,
        name,
        size,
        mode,
      );
      setFileTransfers(prev => ({
        ...prev,
        [file_id]: { name, size: size ?? 0, mode, chunks: {} },
      }));
    },
    [userId, setFileTransfers],
  );

  const handleFileChunk = useCallback(
    msg => {
      if (msg.from === userId) return;
      const { file_id, index, ciphertext } = msg.payload || {};
      if (!file_id || typeof index !== 'number' || !ciphertext) return;

      (async () => {
        const ft = fileTransfers[file_id];
        if (!ft) {
          console.warn('[FILE_CHUNK] unknown file_id=', file_id);
          return;
        }

        try {
          let bytes;
          if (ft.mode === 'public') {
            const plain = await aesDecrypt(groupKeys['public'], ciphertext);
            bytes = utf8ToBytes(plain);
          } else {
            const privKey = await loadPrivateKey(privateKeyB64);
            bytes = await rsaDecrypt(privKey, ciphertext);
          }

          if (!(bytes instanceof Uint8Array)) {
            console.error(
              '[FILE_CHUNK] decrypted result is not bytes, got:',
              typeof bytes,
            );
            return;
          }

          setFileTransfers(prev => {
            const cur = prev[file_id];
            if (!cur) return prev;
            const chunks = { ...cur.chunks, [index]: bytes };
            return { ...prev, [file_id]: { ...cur, chunks } };
          });
        } catch (e) {
          console.error('[FILE_CHUNK] decrypt/handle failed:', e);
        }
      })();
    },
    [fileTransfers, groupKeys, privateKeyB64, userId, setFileTransfers],
  );

  const handleFileEnd = useCallback(
    msg => {
      if (msg.from === userId) return;

      const { file_id } = msg.payload || {};
      if (!file_id) return;

      setFileTransfers(prev => {
        const ft = prev[file_id];
        if (!ft) return prev;

        const ordered = Object.keys(ft.chunks)
          .sort((a, b) => Number(a) - Number(b))
          .map(k => ft.chunks[k]);

        const blob = new Blob(ordered, { type: 'application/octet-stream' });
        const url = URL.createObjectURL(blob);

        const roomKey = ft.mode === 'public' ? 'public' : msg.from;

        setMessages(prevMsgs => {
          const arr = prevMsgs[roomKey] ? [...prevMsgs[roomKey]] : [];
          const text = `[File] ${ft.name}: ${url}`;
          const incoming = {
            dir: 'in',
            text,
            fileUrl: url,
            ts: msg.ts,
            from: msg.from,
            fileId: file_id,
          };

          const exists = arr.some(
            m =>
              (m && m.fileId && m.fileId === file_id) ||
              (m &&
                m.from === msg.from &&
                typeof m.text === 'string' &&
                m.text === text &&
                m.ts === msg.ts),
          );
          const nextArr = exists ? arr : arr.concat(incoming);

          return { ...prevMsgs, [roomKey]: nextArr };
        });

        const rest = { ...prev };
        delete rest[file_id];
        return rest;
      });
    },
    [userId, setFileTransfers, setMessages],
  );

  return {
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
  };
};

export default useSocpMessageHandlers;
