import React from 'react';
import ReactDOM from 'react-dom/client';
import { RootErrorBoundary } from './components/RootErrorBoundary';
import { StartupGate } from './components/StartupGate';
import { listenForFrontendCrashes } from './services/crashReceipts';
import './styles.css';

const App = React.lazy(() => import('./App'));
const stopCrashListener = listenForFrontendCrashes(window);
if (import.meta.hot) import.meta.hot.dispose(stopCrashListener);

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <RootErrorBoundary>
      <StartupGate><React.Suspense fallback={<main className="app-shell" role="status">VKarmani…</main>}>
        <App />
      </React.Suspense></StartupGate>
    </RootErrorBoundary>
  </React.StrictMode>
);
