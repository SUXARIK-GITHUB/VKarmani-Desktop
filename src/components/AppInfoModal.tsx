import { CircleAlert, Copy, Download, MonitorCog, RefreshCw, X } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { NativeAppInfo, UpdateInfo } from '../types/vpn';

interface AppInfoModalProps {
  open: boolean;
  language: UiLanguage;
  info: NativeAppInfo | null;
  updateInfo: UpdateInfo;
  onCheckUpdates: () => void;
  onInstallUpdate?: () => void;
  onClose: () => void;
}

function valueOrDash(value: string | undefined | null) {
  const normalized = value?.trim();
  return normalized ? normalized : '—';
}

function InfoRow({ label, value, mono = false }: { label: string; value: string | undefined | null; mono?: boolean }) {
  return (
    <div className="vk-info-row">
      <span>{label}</span>
      <strong className={mono ? 'mono-value' : undefined}>{valueOrDash(value)}</strong>
    </div>
  );
}

export function AppInfoModal({ open, language, info, updateInfo, onCheckUpdates, onInstallUpdate, onClose }: AppInfoModalProps) {
  if (!open) {
    return null;
  }

  const osLine = info
    ? [info.osName, info.osVersion].map(valueOrDash).filter((value) => value !== '—').join(' · ')
    : '—';
  const deviceLine = info
    ? [info.deviceName, info.osArchitecture].map(valueOrDash).filter((value) => value !== '—').join(' · ')
    : '—';
  const updateBusy = ['checking', 'downloading', 'installing'].includes(updateInfo.status);
  const updateButtonLabel = updateBusy
    ? tr(language, 'Проверяем обновления…', 'Checking for updates…')
    : updateInfo.available
      ? tr(language, 'Есть обновление — обновить?', 'Update available — install?')
      : updateInfo.status === 'idle'
        ? tr(language, 'Проверить наличие обновлений', 'Check for updates')
        : updateInfo.status === 'error'
          ? tr(language, 'Проверить ещё раз', 'Check again')
          : tr(language, 'Обновлений нет', 'No updates available');

  return (
    <div className="vk-modal-backdrop" role="presentation" onMouseDown={onClose}>
      <section className="vk-modal-card vk-info-modal" role="dialog" aria-modal="true" aria-label={tr(language, 'Информация о приложении', 'Application information')} onMouseDown={(event) => event.stopPropagation()}>
        <header className="vk-modal-header">
          <div>
            <span className="section-kicker"><CircleAlert size={16} /> VKarmani</span>
            <h2>{tr(language, 'Информация', 'Information')}</h2>
          </div>
          <button type="button" className="vk-modal-close" onClick={onClose} aria-label={tr(language, 'Закрыть', 'Close')}>
            <X size={22} />
          </button>
        </header>

        <div className="vk-modal-scroll">
          <div className="vk-info-grid">
            <InfoRow label={tr(language, 'Версия ПО', 'Software version')} value={info?.appVersion} />
            <InfoRow label={tr(language, 'Версия Xray', 'Xray version')} value={info?.xrayVersion} />
            <InfoRow label={tr(language, 'Ваш HWID', 'Your HWID')} value={info?.hwid} mono />
            <InfoRow label={tr(language, 'Об устройстве', 'About this device')} value={deviceLine} />
            <InfoRow label={tr(language, 'Windows', 'Windows')} value={osLine} />
            <InfoRow label={tr(language, 'Сборка Windows', 'Windows build')} value={info?.osBuild} />
            <InfoRow label={tr(language, 'Разрядность', 'Bitness')} value={info?.osArchitecture} />
            <InfoRow label={tr(language, 'Путь Xray', 'Xray path')} value={info?.corePath} mono />
          </div>

          <div className="vk-info-note">
            <MonitorCog size={18} />
            <span>{tr(language, 'Эти данные нужны для диагностики и обращения в поддержку.', 'These details help with diagnostics and support requests.')}</span>
          </div>

          <div className="vk-info-actions">
            <button
              type="button"
              className="vk-copy-info-button"
              onClick={() => {
                const payload = [
                  `VKarmani: ${valueOrDash(info?.appVersion)}`,
                  `Xray: ${valueOrDash(info?.xrayVersion)}`,
                  `HWID: ${valueOrDash(info?.hwid)}`,
                  `Device: ${deviceLine}`,
                  `Windows: ${osLine}`,
                  `Build: ${valueOrDash(info?.osBuild)}`,
                  `Arch: ${valueOrDash(info?.osArchitecture)}`,
                  `Core: ${valueOrDash(info?.corePath)}`
                ].join('\n');
                void navigator.clipboard?.writeText(payload);
              }}
            >
              <Copy size={18} />
              {tr(language, 'Скопировать информацию', 'Copy information')}
            </button>

            <button
              type="button"
              className={`vk-copy-info-button ${updateInfo.available ? 'vk-update-available-button' : ''}`}
              onClick={updateInfo.available && onInstallUpdate ? onInstallUpdate : onCheckUpdates}
              disabled={updateBusy}
              title={updateInfo.message}
            >
              {updateBusy ? <RefreshCw size={18} className="spin-icon" /> : <Download size={18} />}
              {updateButtonLabel}
            </button>
          </div>
        </div>
      </section>
    </div>
  );
}
