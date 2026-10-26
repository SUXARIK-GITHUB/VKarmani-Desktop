import { tr, type UiLanguage } from '../i18n';
import type { SplitTunnelEntry, TunRoutingMode } from '../types/vpn';
import { PolicyChoice } from './PolicyChoice';

export function TunRoutingChoice({ language, mode, onChange }: {
  language: UiLanguage;
  mode: TunRoutingMode;
  entries: SplitTunnelEntry[];
  onChange: (mode: TunRoutingMode) => void;
}) {
  return <div className="settings-routing-control">
    <PolicyChoice label={tr(language, 'Маршрутизация приложений', 'App routing')} value={mode} onChange={onChange} options={[
      { value: 'all', label: tr(language, 'Все приложения', 'All applications') },
      { value: 'selected', label: tr(language, 'Только выбранные через VPN', 'Selected through VPN') },
      { value: 'exclude', label: tr(language, 'Все, кроме исключённых', 'All except excluded') }
    ]} />
  </div>;
}
