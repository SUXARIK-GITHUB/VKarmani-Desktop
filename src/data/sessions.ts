import type { SessionRecord } from '../types/vpn';

export const demoSessionHistory: SessionRecord[] = [
  {
    id: 'hist-01',
    startedAt: 'Сегодня, 14:24',
    serverLabel: '🇩🇪 Германия, Франкфурт',
    durationLabel: '01:18:44',
    transferredGb: 3.4,
    status: 'current'
  },
  {
    id: 'hist-02',
    startedAt: 'Сегодня, 10:13',
    serverLabel: '🇳🇱 Нидерланды, Амстердам',
    durationLabel: '00:42:12',
    transferredGb: 1.1,
    status: 'completed'
  },
  {
    id: 'hist-03',
    startedAt: 'Вчера, 21:07',
    serverLabel: '🇫🇮 Финляндия, Хельсинки',
    durationLabel: '00:08:09',
    transferredGb: 0.2,
    status: 'interrupted'
  }
];
