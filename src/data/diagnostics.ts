import type { DiagnosticsSnapshot } from '../types/vpn';

export const demoDiagnostics: DiagnosticsSnapshot = {
  serviceStatus: 'ok',
  tunnelStatus: 'warning',
  routeMode: 'Системный маршрут + выборочный split-tunnel',
  dnsMode: 'Защищённый DNS через туннель',
  clientVersion: '0.13.8',
  lastConfigSync: 'Только что',
  logLines: [
    '[16:02:11] Проверка конфигурации завершена успешно.',
    '[16:02:12] Получен профиль пользователя из Remnawave gateway.',
    '[16:02:13] Обновлён список серверов, доступно 6 узлов.',
    '[16:02:18] Подготовлен профиль подключения Reality.',
    '[16:02:19] Последняя проверка обновлений: актуальная версия.'
  ]
};
