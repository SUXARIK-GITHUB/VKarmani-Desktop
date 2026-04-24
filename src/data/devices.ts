import type { DeviceRecord } from '../types/vpn';

export const demoDevices: DeviceRecord[] = [
  {
    id: 'device-main-windows',
    name: 'Основной ПК',
    platform: 'Windows 11',
    location: 'Франкфурт',
    lastSeen: 'Только что',
    status: 'online',
    isCurrent: true
  },
  {
    id: 'device-laptop',
    name: 'Рабочий ноутбук',
    platform: 'Windows 11',
    location: 'Берлин',
    lastSeen: '15 минут назад',
    status: 'offline',
    isCurrent: false
  },
  {
    id: 'device-android',
    name: 'Смартфон',
    platform: 'Android',
    location: 'Прага',
    lastSeen: '2 часа назад',
    status: 'offline',
    isCurrent: false
  }
];
