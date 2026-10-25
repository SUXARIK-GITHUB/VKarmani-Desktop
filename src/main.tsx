import React from 'react';
import ReactDOM from 'react-dom/client';
import { RootErrorBoundary } from './components/RootErrorBoundary';
// Keep the pre-lazy-import stylesheet order and the fallback fully styled.
import './styles/diagnostics.css';
import './styles/policyControls.css';
import './styles/policies.css';
import './styles.css';

function renderApp(safeStart: boolean) {
  // A rejected lazy import caches its rejection. Create a new lazy type when
  // the boundary explicitly retries, so a transient chunk failure can retry.
  const App = React.lazy(() => import('./App'));
  return <React.Suspense fallback={<main className="shell auth-shell" role="status">VKarmani…</main>}><App safeStart={safeStart} /></React.Suspense>;
}

ReactDOM.createRoot(document.getElementById('root')!).render(
  <React.StrictMode>
    <RootErrorBoundary>{renderApp}</RootErrorBoundary>
  </React.StrictMode>
);
