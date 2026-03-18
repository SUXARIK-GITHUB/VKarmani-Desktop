import type { VpnServer } from '../types/vpn';

export const vpnServers: VpnServer[] = [
  {
    id: 'de-frankfurt-01',
    country: 'Германия',
    city: 'Франкфурт',
    flag: '🇩🇪',
    latency: 23,
    load: 41,
    protocol: 'Reality',
    isRecommended: true,
    tags: ['EU', 'низкий пинг', 'демо'],
    ipPool: '185.147.23.x',
    description: 'Оптимален для ежедневного использования и рабочих задач. Для реального runtime лучше импортировать live-профиль Remnawave.'
  },
  {
    id: 'nl-amsterdam-02',
    country: 'Нидерланды',
    city: 'Амстердам',
    flag: '🇳🇱',
    latency: 29,
    load: 36,
    protocol: 'Xray',
    tags: ['стриминг', 'стабильный', 'демо'],
    ipPool: '46.182.108.x',
    description: 'Сбалансированный узел для обычной нагрузки и браузинга.'
  },
  {
    id: 'fi-helsinki-01',
    country: 'Финляндия',
    city: 'Хельсинки',
    flag: '🇫🇮',
    latency: 34,
    load: 27,
    protocol: 'VLESS',
    tags: ['резерв', 'спокойная нагрузка', 'демо'],
    ipPool: '65.21.94.x',
    description: 'Подходит как резервная локация с аккуратной сетевой нагрузкой.'
  },
  {
    id: 'pl-warsaw-01',
    country: 'Польша',
    city: 'Варшава',
    flag: '🇵🇱',
    latency: 39,
    load: 33,
    protocol: 'Reality',
    tags: ['быстрый старт', 'демо'],
    ipPool: '31.186.80.x',
    description: 'Хороший вариант при первом подключении и для коротких сессий.'
  },
  {
    id: 'tr-istanbul-01',
    country: 'Турция',
    city: 'Стамбул',
    flag: '🇹🇷',
    latency: 47,
    load: 54,
    protocol: 'Sing-box',
    tags: ['маршрутизация', 'демо'],
    ipPool: '45.89.53.x',
    description: 'Локация с альтернативной маршрутизацией под отдельные сценарии.'
  },
  {
    id: 'sg-singapore-01',
    country: 'Сингапур',
    city: 'Сингапур',
    flag: '🇸🇬',
    latency: 129,
    load: 22,
    protocol: 'Xray',
    tags: ['Asia', 'резерв', 'демо'],
    ipPool: '103.172.116.x',
    description: 'Для дальних подключений и тестов по азиатскому направлению.'
  }
];
