import { BrowserRouter as Router, Routes, Route, Navigate } from 'react-router-dom';
import { SocpProvider, useSocpContext } from './contexts/SocpContext';

import 'bootstrap/dist/css/bootstrap.min.css';
import '@chatscope/chat-ui-kit-styles/dist/default/styles.min.css';

import Login from './pages/Login';
import ChatPage from './pages/Chat';
import { useEffect } from 'react';

function Gate() {
  const { auth } = useSocpContext();

  useEffect(() => {
    console.log('auth:', auth);
    document.title = 'Secure Chat';
  }, [auth]);

  if (auth.status === 'authenticated') {
    return <ChatPage />;
  }

  // Show login for idle, pending, or error
  return <Login />;
}

export default function App() {
  return (
    <SocpProvider>
      <Router>
        <Routes>
          <Route path="/" element={<Gate />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Routes>
      </Router>
    </SocpProvider>
  );
}
