import type { ReactNode } from 'react';
import type { VpnServer } from '../types/vpn';
import { getServerCountryCode } from '../utils/serverDisplay';

type ServerFlagSize = 'normal' | 'large';

interface ServerFlagProps {
  server: Pick<VpnServer, 'country' | 'countryCode' | 'rawLabel' | 'host' | 'flag'> | null | undefined;
  size?: ServerFlagSize;
}

const stripe = (y: number, height: number, fill: string) => <rect x="0" y={y} width="36" height={height} fill={fill} />;
const vertical = (x: number, width: number, fill: string) => <rect x={x} y="0" width={width} height="24" fill={fill} />;

function cross(fill: string, stroke = 0) {
  return <>
    {stroke > 0 ? <rect x={18 - stroke / 2} y="0" width={stroke} height="24" fill={fill} /> : null}
    <rect x="15" y="0" width="6" height="24" fill={fill} />
    <rect x="0" y="9" width="36" height="6" fill={fill} />
  </>;
}

const FLAGS: Record<string, ReactNode> = {
  NL: <>{stripe(0, 8, '#AE1C28')}{stripe(8, 8, '#FFFFFF')}{stripe(16, 8, '#21468B')}</>,
  SE: <><rect width="36" height="24" fill="#006AA7" /><rect x="10" y="0" width="5" height="24" fill="#FECC00" /><rect x="0" y="9" width="36" height="5" fill="#FECC00" /></>,
  CH: <><rect width="36" height="24" fill="#DA291C" /><rect x="15" y="5" width="6" height="14" fill="#FFFFFF" /><rect x="10" y="9" width="16" height="6" fill="#FFFFFF" /></>,
  US: <><rect width="36" height="24" fill="#B22234" />{Array.from({ length: 6 }, (_, index) => <rect key={index} x="0" y={2 + index * 4} width="36" height="2" fill="#FFFFFF" />)}<rect x="0" y="0" width="15" height="13" fill="#3C3B6E" />{Array.from({ length: 3 }, (_, row) => Array.from({ length: 4 }, (_, col) => <circle key={`${row}-${col}`} cx={2.5 + col * 3.3} cy={2.5 + row * 3.6} r=".55" fill="#FFFFFF" />))}</>,
  DE: <>{stripe(0, 8, '#000000')}{stripe(8, 8, '#DD0000')}{stripe(16, 8, '#FFCE00')}</>,
  FR: <>{vertical(0, 12, '#0055A4')}{vertical(12, 12, '#FFFFFF')}{vertical(24, 12, '#EF4135')}</>,
  IT: <>{vertical(0, 12, '#009246')}{vertical(12, 12, '#FFFFFF')}{vertical(24, 12, '#CE2B37')}</>,
  PL: <>{stripe(0, 12, '#FFFFFF')}{stripe(12, 12, '#DC143C')}</>,
  RU: <>{stripe(0, 8, '#FFFFFF')}{stripe(8, 8, '#0039A6')}{stripe(16, 8, '#D52B1E')}</>,
  UA: <>{stripe(0, 12, '#0057B7')}{stripe(12, 12, '#FFD700')}</>,
  FI: <><rect width="36" height="24" fill="#FFFFFF" /><rect x="10" y="0" width="5" height="24" fill="#002F6C" /><rect x="0" y="9" width="36" height="5" fill="#002F6C" /></>,
  NO: <><rect width="36" height="24" fill="#BA0C2F" /><rect x="9" y="0" width="7" height="24" fill="#FFFFFF" /><rect x="0" y="8" width="36" height="8" fill="#FFFFFF" /><rect x="11" y="0" width="3" height="24" fill="#00205B" /><rect x="0" y="10" width="36" height="4" fill="#00205B" /></>,
  DK: <><rect width="36" height="24" fill="#C60C30" /><rect x="10" y="0" width="4" height="24" fill="#FFFFFF" /><rect x="0" y="10" width="36" height="4" fill="#FFFFFF" /></>,
  GB: <><rect width="36" height="24" fill="#012169" /><path d="M0 0 L36 24 M36 0 L0 24" stroke="#FFFFFF" strokeWidth="5" /><path d="M0 0 L36 24 M36 0 L0 24" stroke="#C8102E" strokeWidth="2.4" /><rect x="15" y="0" width="6" height="24" fill="#FFFFFF" /><rect x="0" y="9" width="36" height="6" fill="#FFFFFF" /><rect x="16.5" y="0" width="3" height="24" fill="#C8102E" /><rect x="0" y="10.5" width="36" height="3" fill="#C8102E" /></>,
  ES: <>{stripe(0, 6, '#AA151B')}{stripe(6, 12, '#F1BF00')}{stripe(18, 6, '#AA151B')}</>,
  PT: <>{vertical(0, 15, '#006600')}{vertical(15, 21, '#FF0000')}<circle cx="15" cy="12" r="3.2" fill="#FFCC00" /></>,
  BE: <>{vertical(0, 12, '#000000')}{vertical(12, 12, '#FAE042')}{vertical(24, 12, '#ED2939')}</>,
  AT: <>{stripe(0, 8, '#ED2939')}{stripe(8, 8, '#FFFFFF')}{stripe(16, 8, '#ED2939')}</>,
  CZ: <><rect width="36" height="12" y="0" fill="#FFFFFF" /><rect width="36" height="12" y="12" fill="#D7141A" /><path d="M0 0 L18 12 L0 24 Z" fill="#11457E" /></>,
  SK: <>{stripe(0, 8, '#FFFFFF')}{stripe(8, 8, '#0B4EA2')}{stripe(16, 8, '#EE1C25')}</>,
  RO: <>{vertical(0, 12, '#002B7F')}{vertical(12, 12, '#FCD116')}{vertical(24, 12, '#CE1126')}</>,
  BG: <>{stripe(0, 8, '#FFFFFF')}{stripe(8, 8, '#00966E')}{stripe(16, 8, '#D62612')}</>,
  HU: <>{stripe(0, 8, '#CD2A3E')}{stripe(8, 8, '#FFFFFF')}{stripe(16, 8, '#436F4D')}</>,
  TR: <><rect width="36" height="24" fill="#E30A17" /><circle cx="15" cy="12" r="6" fill="#FFFFFF" /><circle cx="17.3" cy="12" r="4.8" fill="#E30A17" /><path d="M24 8.7 L25.1 11 L27.7 11.2 L25.7 12.9 L26.4 15.3 L24 14 L21.6 15.3 L22.3 12.9 L20.3 11.2 L22.9 11 Z" fill="#FFFFFF" /></>,
  CA: <>{vertical(0, 9, '#D52B1E')}{vertical(9, 18, '#FFFFFF')}{vertical(27, 9, '#D52B1E')}<path d="M18 6 L19.5 10 L23 9 L20.8 12 L23 15 L19.5 14 L18 18 L16.5 14 L13 15 L15.2 12 L13 9 L16.5 10 Z" fill="#D52B1E" /></>,
  JP: <><rect width="36" height="24" fill="#FFFFFF" /><circle cx="18" cy="12" r="6" fill="#BC002D" /></>,
  CN: <><rect width="36" height="24" fill="#DE2910" /><path d="M7 4 L8.1 7 L11.3 7 L8.7 8.8 L9.7 12 L7 10.1 L4.3 12 L5.3 8.8 L2.7 7 L5.9 7 Z" fill="#FFDE00" /></>,
  BR: <><rect width="36" height="24" fill="#009B3A" /><path d="M18 4 L32 12 L18 20 L4 12 Z" fill="#FFDF00" /><circle cx="18" cy="12" r="5" fill="#002776" /></>,
  AR: <>{stripe(0, 8, '#74ACDF')}{stripe(8, 8, '#FFFFFF')}{stripe(16, 8, '#74ACDF')}<circle cx="18" cy="12" r="2" fill="#F6B40E" /></>,
  KR: <><rect width="36" height="24" fill="#FFFFFF" /><circle cx="18" cy="12" r="5" fill="#CD2E3A" /><path d="M18 7 A5 5 0 0 1 18 17 A2.5 2.5 0 0 0 18 12 A2.5 2.5 0 0 1 18 7" fill="#0047A0" /></>,
  SG: <>{stripe(0, 12, '#EF3340')}{stripe(12, 12, '#FFFFFF')}<circle cx="8" cy="6" r="4" fill="#FFFFFF" /><circle cx="9.5" cy="6" r="3.3" fill="#EF3340" /></>,
  HK: <><rect width="36" height="24" fill="#DE2910" /><circle cx="18" cy="12" r="5" fill="#FFFFFF" opacity=".95" /></>,
  IN: <>{stripe(0, 8, '#FF9933')}{stripe(8, 8, '#FFFFFF')}{stripe(16, 8, '#138808')}<circle cx="18" cy="12" r="2.4" fill="none" stroke="#000080" strokeWidth=".8" /></>,
  AE: <>{vertical(0, 9, '#FF0000')}{stripe(0, 8, '#00732F')}{stripe(8, 8, '#FFFFFF')}{stripe(16, 8, '#000000')}</>,
  IL: <><rect width="36" height="24" fill="#FFFFFF" /><rect y="3" width="36" height="3" fill="#0038B8" /><rect y="18" width="36" height="3" fill="#0038B8" /><path d="M18 8 L21 14 L15 14 Z M18 16 L15 10 L21 10 Z" fill="none" stroke="#0038B8" strokeWidth="1" /></>,
  AU: <><rect width="36" height="24" fill="#00008B" /><rect x="0" y="0" width="16" height="12" fill="#012169" /><path d="M0 0 L16 12 M16 0 L0 12" stroke="#FFFFFF" strokeWidth="2" /><circle cx="27" cy="14" r="2" fill="#FFFFFF" /></>,
  NZ: <><rect width="36" height="24" fill="#00247D" /><rect x="0" y="0" width="16" height="12" fill="#012169" /><path d="M0 0 L16 12 M16 0 L0 12" stroke="#FFFFFF" strokeWidth="2" /><circle cx="27" cy="14" r="2" fill="#CC142B" /></>,
  KZ: <><rect width="36" height="24" fill="#00AFCA" /><circle cx="18" cy="12" r="4" fill="#FEC50C" /></>,
  GE: <><rect width="36" height="24" fill="#FFFFFF" />{cross('#FF0000')}</>,
  MD: <>{vertical(0, 12, '#003DA5')}{vertical(12, 12, '#FFD100')}{vertical(24, 12, '#C8102E')}</>,
  LT: <>{stripe(0, 8, '#FDB913')}{stripe(8, 8, '#006A44')}{stripe(16, 8, '#C1272D')}</>,
  LV: <>{stripe(0, 10, '#9E3039')}{stripe(10, 4, '#FFFFFF')}{stripe(14, 10, '#9E3039')}</>,
  EE: <>{stripe(0, 8, '#4891D9')}{stripe(8, 8, '#000000')}{stripe(16, 8, '#FFFFFF')}</>
};

export function ServerFlag({ server, size = 'normal' }: ServerFlagProps) {
  const code = server ? getServerCountryCode(server) : undefined;
  const normalizedCode = code?.toUpperCase();
  const flagContent = normalizedCode ? FLAGS[normalizedCode] : undefined;
  const sizeClass = size === 'large' ? 'vk-flag-svg--large' : 'vk-flag-svg--normal';

  if (flagContent) {
    return (
      <svg
        viewBox="0 0 36 24"
        role="img"
        aria-label={`Флаг ${normalizedCode}`}
        className={`vk-flag-svg ${sizeClass}`}
        focusable="false"
      >
        <title>{normalizedCode}</title>
        {flagContent}
      </svg>
    );
  }

  return <span className={`vk-flag-fallback ${sizeClass}`} title={normalizedCode || 'Unknown'}>{normalizedCode || '🌐'}</span>;
}
