// Group 59
// ----------------------------------
// Muhammad Tayyab Rashid - a1988298
// Nguyen Duc Tung Bui - a1976012
// Guilin Luo - a1989840
// Mazharul Islam Rakib - a1990942
// Masud Ahammad - a1993200

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
