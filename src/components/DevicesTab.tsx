import { Laptop2, ShieldCheck, Smartphone } from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { DeviceRecord } from '../types/vpn';

interface DevicesTabProps {
  devices: DeviceRecord[];
  language: UiLanguage;
  onRevokeDevice: (deviceId: string) => void;
}

function getDeviceIcon(platform: string | null | undefined) {
  const normalizedPlatform = `${platform ?? ''}`.toLowerCase();
  if (
    normalizedPlatform.includes('android')
    || normalizedPlatform.includes('iphone')
    || normalizedPlatform.includes('ios')
  ) {
    return Smartphone;
  }

  return Laptop2;
}

export function DevicesTab({ devices, language, onRevokeDevice }: DevicesTabProps) {
  const normalizedDevices = (Array.isArray(devices) ? devices : []).map((device, index) => ({
    id: device?.id || `device-${index}`,
    name: device?.name?.trim?.() || tr(language, 'Устройство', 'Device'),
    platform: device?.platform?.trim?.() || tr(language, 'Не указано', 'Unknown'),
    location: device?.location?.trim?.() || tr(language, 'Локация не указана', 'Location unavailable'),
    lastSeen: device?.lastSeen?.trim?.() || tr(language, 'Нет данных', 'No data'),
    status: device?.status === 'online' ? 'online' : 'offline',
    isCurrent: Boolean(device?.isCurrent),
    note: device?.note?.trim?.() || ''
  }));

  const sortedDevices = [...normalizedDevices].sort((left, right) => Number(right.isCurrent) - Number(left.isCurrent));

  return (
    <section className="panel">
      <div className="panel-header compact-header-row">
        <div>
          <span className="chip subdued">{tr(language, 'Устройства', 'Devices')}</span>
          <h3>{tr(language, 'Подключённые устройства', 'Connected devices')}</h3>
        </div>
      </div>

      <div className="device-list">
        {sortedDevices.length === 0 ? (
          <div className="empty-state">
            <strong>{tr(language, 'Устройства пока не найдены', 'No devices found yet')}</strong>
            <span>{tr(language, 'После первой успешной синхронизации здесь появится список устройств, связанных с вашим доступом.', 'After the first successful sync, devices linked to your access will appear here.')}</span>
          </div>
        ) : null}

        {sortedDevices.map((device) => {
          const Icon = getDeviceIcon(device.platform);

          return (
            <article key={device.id} className="device-card">
              <div className="device-main">
                <div className={`device-icon ${device.status}`}>
                  <Icon size={18} />
                </div>
                <div>
                  <strong>{device.name}</strong>
                  <span>
                    {device.platform} · {device.location}
                  </span>
                  <span className="muted">{tr(language, 'Последняя активность:', 'Last activity:')} {device.lastSeen}</span>
                  {device.note ? <span className="muted">{device.note}</span> : null}
                </div>
              </div>

              <div className="device-side">
                <span className={`runtime-badge ${device.status === 'online' ? 'ready' : 'waiting'}`}>
                  {device.status === 'online' ? tr(language, 'Онлайн', 'Online') : tr(language, 'Не в сети', 'Offline')}
                </span>
                {device.isCurrent ? (
                  <span className="recommend-pill">
                    <ShieldCheck size={13} />
                    {tr(language, 'Это устройство', 'This device')}
                  </span>
                ) : (
                  <button className="ghost-button danger-button" onClick={() => onRevokeDevice(device.id)}>
                    {tr(language, 'Отключить', 'Revoke')}
                  </button>
                )}
              </div>
            </article>
          );
        })}
      </div>
    </section>
  );
}
