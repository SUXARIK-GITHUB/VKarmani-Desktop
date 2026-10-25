// Browser-only actual boundary/notice acceptance. No App, IPC or native session.
import React, { Suspense, useState } from 'react';
import { createRoot } from 'react-dom/client';
import { RootErrorBoundary } from '../../src/components/RootErrorBoundary';
import { StorageRecoveryNotice } from '../../src/components/StorageRecoveryNotice';
import { AuthScreen } from '../../src/components/AuthScreen';
import { LogoutConfirmModal } from '../../src/components/LogoutConfirmModal';
import '../../src/styles.css';

const query = new URLSearchParams(location.search);
const language = query.get('lang') === 'en' ? 'en' : 'ru';
document.documentElement.lang = language;
const noop = () => {};
function Notice() {
  const [confirmBackup, setConfirm] = useState(false);
  const [recovered, setRecovered] = useState(false);
  return <main className="shell auth-shell"><div className="window-frame desktop-frame">
    <StorageRecoveryNotice language={language} code={recovered ? undefined : 'STATE_RECOVERY_REQUIRED'} busy={false}
      safeStart confirmBackup={confirmBackup} onInspect={() => setConfirm(true)} onConfirm={() => setRecovered(true)} onCancel={() => setConfirm(false)} />
    <AuthScreen accessKey="https://sub.vkarmani.com/synthetic" authLoading={false} storageBlocked={!recovered} errorText="" language={language}
      integrationMeta={{} as never} onAccessKeyChange={noop} onAuthorize={noop} />
  </div></main>;
}
function Logout() {
  const [open, setOpen] = useState(false); const [confirmed, setConfirmed] = useState(0);
  return <main className="shell auth-shell"><button type="button" className="ghost-button" onClick={() => setOpen(true)}>Sign out</button>
    <p>CONFIRMED={confirmed}</p><LogoutConfirmModal open={open} language={language} busy={query.get('busy') === '1'}
      onCancel={() => setOpen(false)} onConfirm={() => { setConfirmed(value => value + 1); setOpen(false); }} />
  </main>;
}
function Content({ safeStart }: { safeStart: boolean }) {
  if (query.get('fault') === 'render' && !safeStart) throw new Error('synthetic-secret https://sub.vkarmani.com/private');
  return query.get('fault') === 'storage' ? <Notice /> : query.get('fault') === 'logout' ? <Logout />
    : <main className="shell auth-shell"><p>READY · {safeStart ? 'SAFE' : 'NORMAL'}</p></main>;
}
function render(safeStart: boolean) {
  const Lazy = React.lazy(() => query.get('fault') === 'import' && !safeStart
    ? Promise.reject(new Error('synthetic-import-secret')) : Promise.resolve({ default: Content }));
  return <Suspense fallback={<p>Loading…</p>}><Lazy safeStart={safeStart} /></Suspense>;
}
createRoot(document.getElementById('root')!).render(query.get('boundary') === 'off' ? <Content safeStart={false} />
  : <React.StrictMode><RootErrorBoundary>{render}</RootErrorBoundary></React.StrictMode>);
