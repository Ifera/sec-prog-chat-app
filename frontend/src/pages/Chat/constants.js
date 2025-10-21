export const AVATAR_URLS = [
  'https://chatscope.io/storybook/react/assets/lilly-aj6lnGPk.svg',
  'https://chatscope.io/storybook/react/assets/joe-v8Vy3KOS.svg',
  'https://chatscope.io/storybook/react/assets/emily-xzL8sDL2.svg',
  'https://chatscope.io/storybook/react/assets/kai-5wHRJGb2.svg',
  'https://chatscope.io/storybook/react/assets/akane-MXhWvx63.svg',
  'https://chatscope.io/storybook/react/assets/eliot-JNkqSAth.svg',
  'https://chatscope.io/storybook/react/assets/zoe-E7ZdmXF0.svg',
  'https://chatscope.io/storybook/react/assets/patrik-yC7svbAR.svg',
];

export const GROUP = Object.freeze({
  id: 'public',
  name: '#public',
  avatar: 'group.jpeg',
});

export const avatarFor = userId => {
  let hash = 0;
  for (let i = 0; i < userId.length; i++) {
    hash = (hash * 31 + userId.charCodeAt(i)) >>> 0;
  }
  return AVATAR_URLS[hash % AVATAR_URLS.length];
};
