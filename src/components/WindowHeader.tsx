import type { MouseEvent } from 'react';
import { Minus, Square, X } from 'lucide-react';
import { performWindowAction } from '../services/runtime';
import type { UpdateInfo, RemnawaveSession } from '../types/vpn';
import type { UiLanguage } from '../i18n';

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

export function WindowHeader({ minimizeToTray, onRequestHideToTray }: WindowHeaderProps) {
  const closeWindow = (event: MouseEvent<HTMLButtonElement>) => {
    event.stopPropagation();
    if (minimizeToTray) {
      onRequestHideToTray();
      return;
    }
    void performWindowAction('close');
  };

  return (
    <header className="vk-titlebar" onDoubleClick={() => void performWindowAction('maximize')}>
      <div className="vk-titlebar-brand">
        <span>VKarmani</span>
      </div>
      <div className="vk-window-controls">
        <button type="button" aria-label="Minimize" onClick={(event) => { event.stopPropagation(); void performWindowAction('minimize'); }}>
          <Minus size={16} />
        </button>
        <button type="button" aria-label="Maximize" onClick={(event) => { event.stopPropagation(); void performWindowAction('maximize'); }}>
          <Square size={13} />
        </button>
        <button type="button" aria-label="Close" onClick={closeWindow}>
          <X size={17} />
        </button>
      </div>
    </header>
  );
}
