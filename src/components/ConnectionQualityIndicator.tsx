import type { VpnServer } from '../types/vpn';
import { connectionQuality, qualityLabel } from '../utils/connectionQuality';

export function ConnectionQualityIndicator({ server, language, checking = false }: { server: VpnServer | null; language: 'ru' | 'en'; checking?: boolean }) {
  const measurement = server ?? {};
  const quality = connectionQuality(measurement, checking);
  const label = qualityLabel(measurement, language, checking);
  return <svg viewBox="0 0 20 20" width="20" height="20" role="img" aria-label={label} className={`vk-quality-indicator ${quality.tone}`} data-quality={quality.state}>
    <title>{label}</title>
    {[0, 1, 2, 3].map(index => <rect key={index} x={2 + index * 4.5} y={14 - index * 3} width="3" height={4 + index * 3} rx="0.7" fill="currentColor" opacity={index < quality.level ? 1 : 0.2} />)}
  </svg>;
}
