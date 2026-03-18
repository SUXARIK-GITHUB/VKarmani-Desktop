import { Download, Globe2, Minus, RefreshCw, ShieldCheck, Square, X } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import { performWindowAction, startWindowDrag } from '../services/runtime';
import type { RemnawaveSession, UpdateInfo } from '../types/vpn';

interface WindowHeaderProps {
  session: RemnawaveSession | null;
  currentVersion: string;
  updateInfo: UpdateInfo;
  language: UiLanguage;
  minimizeToTray: boolean;
  onToggleLanguage: () => void;
  onCheckUpdates: () => void;
  onInstallUpdate?: () => void;
  onRequestHideToTray: () => void;
}

function getUpdateLabel(language: UiLanguage, updateInfo: UpdateInfo) {
  if (updateInfo.status === 'checking') {
    return tr(language, 'Проверяем обновления…', 'Checking for updates…');
  }

  if (updateInfo.status === 'downloading' || updateInfo.status === 'installing') {
    return updateInfo.downloadedPercent
      ? `${tr(language, 'Обновление', 'Updating')} ${updateInfo.downloadedPercent}%`
      : tr(language, 'Подготовка обновления…', 'Preparing update…');
  }

  if (updateInfo.available && updateInfo.version) {
    return tr(language, `Обновить до ${updateInfo.version}`, `Update to ${updateInfo.version}`);
  }

  if (updateInfo.status === 'updated') {
    return tr(language, 'Обновление подготовлено', 'Update prepared');
  }

  return tr(language, 'Версия актуальна', 'Up to date');
}

export function WindowHeader({
  session,
  currentVersion,
  updateInfo,
  language,
  minimizeToTray,
  onToggleLanguage,
  onCheckUpdates,
  onInstallUpdate,
  onRequestHideToTray
}: WindowHeaderProps) {
  const beginDrag = (event: React.MouseEvent<HTMLElement>) => {
    if (event.button !== 0) {
      return;
    }

    const target = event.target as HTMLElement | null;
    if (target?.closest('[data-no-drag="true"]')) {
      return;
    }

    void startWindowDrag();
  };

  const toggleMaximize = (event?: React.MouseEvent<HTMLElement>) => {
    event?.stopPropagation();
    void performWindowAction('maximize');
  };

  const handleCloseAction = (event: React.MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();

    if (minimizeToTray) {
      onRequestHideToTray();
      return;
    }

    void performWindowAction('close');
  };

  const handleUpdateAction = (event: React.MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();

    if (updateInfo.status === 'checking' || updateInfo.status === 'downloading' || updateInfo.status === 'installing') {
      return;
    }

    if (updateInfo.available && onInstallUpdate) {
      onInstallUpdate();
      return;
    }

    onCheckUpdates();
  };

  const updateActionable = updateInfo.available || updateInfo.status === 'idle' || updateInfo.status === 'error' || updateInfo.status === 'updated';
  return (
    <header className="titlebar">
      <div className="brand titlebar-drag-area" data-tauri-drag-region onMouseDown={beginDrag} onDoubleClick={toggleMaximize}>
        <img src="/assets/logo-dark.jpg" alt="VKarmani" className="brand-logo" />
        <div>
          <strong>VKarmani Desktop</strong>
          <span>{tr(language, 'Безопасный VPN-клиент для ПК', 'Secure VPN client for desktop')}</span>
        </div>
      </div>

      <div className="window-tools">
        <div className="titlebar-spacer titlebar-drag-area" data-tauri-drag-region onMouseDown={beginDrag} onDoubleClick={toggleMaximize} aria-hidden="true" />
        <span className="app-pill">
          <ShieldCheck size={14} />
          v{currentVersion}
        </span>
        <button
          type="button"
          data-no-drag="true"
          className={`app-pill app-pill-button ${updateInfo.available ? 'accent-pill update-available' : ''}`}
          onClick={handleUpdateAction}
          disabled={!updateActionable}
          title={minimizeToTray ? tr(language, 'При закрытии окно будет скрыто в трей.', 'Closing the window will hide it to tray.') : undefined}
        >
          {updateInfo.available ? <Download size={14} /> : <RefreshCw size={14} />}
          {getUpdateLabel(language, updateInfo)}
        </button>
        <button type="button" data-no-drag="true" className="app-pill app-pill-button" onClick={(event) => { event.stopPropagation(); onToggleLanguage(); }}>
          <Globe2 size={14} />
          {language.toUpperCase()}
        </button>

        <div className="window-control-group">
          <button type="button" data-no-drag="true" className="window-control" onClick={(event) => { event.stopPropagation(); void performWindowAction('minimize'); }} aria-label="Minimize">
            <Minus size={15} />
          </button>
          <button type="button" data-no-drag="true" className="window-control" onClick={(event) => { event.stopPropagation(); toggleMaximize(event); }} aria-label="Maximize">
            <Square size={12} />
          </button>
          <button type="button" data-no-drag="true" className="window-control danger" onClick={handleCloseAction} aria-label="Close">
            <X size={14} />
          </button>
        </div>
      </div>
    </header>
  );
}
