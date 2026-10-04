import type { RuntimeStatus } from '../types/vpn';

export function getRuntimePreparedServerId(runtime: RuntimeStatus | null | undefined) {
  return runtime?.lastPreparedServerId?.trim() ?? '';
}

export function getRuntimePreparedServerFingerprint(runtime: RuntimeStatus | null | undefined) {
  return runtime?.lastPreparedServerFingerprint?.trim() ?? '';
}

export function runtimeConfirmsTargetServer(
  runtime: RuntimeStatus | null | undefined,
  targetServerId: string,
  targetFingerprint = ''
) {
  const expectedId = targetServerId.trim();
  const expectedFingerprint = targetFingerprint.trim();
  const actualFingerprint = getRuntimePreparedServerFingerprint(runtime);

  return Boolean(
    runtime?.tunnelActive
      && expectedId
      && getRuntimePreparedServerId(runtime) === expectedId
      && (!expectedFingerprint || actualFingerprint === expectedFingerprint)
  );
}

export function assertNativeRuntimeServerMatches(
  nativeServerId: string | null | undefined,
  targetServerId: string,
  nativeFingerprint = '',
  targetFingerprint = ''
) {
  const actual = nativeServerId?.trim();
  const expected = targetServerId.trim();
  const actualFingerprint = nativeFingerprint.trim();
  const expectedFingerprint = targetFingerprint.trim();

  if (!actual || actual !== expected) {
    throw new Error(`Native runtime запустился не на выбранном сервере: ожидали ${expected}, получили ${actual}. Подключение остановлено для защиты от ложной галки.`);
  }

  if (expectedFingerprint && actualFingerprint !== expectedFingerprint) {
    throw new Error('Native runtime запустился с другим runtime-конфигом выбранного сервера. Подключение остановлено для защиты от случайного узла.');
  }
}
export function nativeConnectFailurePreservesRuntime(message: string): boolean {
  return /(?:SUBSCRIPTION_(?:UNAVAILABLE|REJECTED)|SESSION_CHANGED|OPERATION_CANCELLED|REQUEST_IDENTITY|CONNECT_PREFLIGHT):/.test(message)
    || message.includes('Подключение заняло больше')
    || message.includes('UI разблокирован')
    || message.includes('Runtime уже выполняет другое действие');
}
