import type { ReleaseChannel, UpdateInfo } from '../types/vpn';
import { appVersion, fetchRemoteText, isTauriRuntime, restartNativeApplication } from './runtime';

const wait = (value: number) => new Promise<void>((resolve) => window.setTimeout(resolve, value));

// Должен совпадать с src-tauri/tauri.conf.json -> plugins.updater.endpoints[0].
// Нужен не для установки, а для понятной диагностики, когда Tauri updater вернул общую ошибку.
const GITHUB_LATEST_JSON_URL = 'https://github.com/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest/download/latest.json';

function extractErrorMessage(error: unknown, depth = 0): string {
  if (depth > 4 || error == null) {
    return '';
  }

  if (typeof error === 'string') {
    return error.trim();
  }

  if (error instanceof Error) {
    return error.message?.trim() ?? '';
  }

  if (typeof error === 'object') {
    const record = error as Record<string, unknown>;
    for (const key of ['message', 'error', 'cause', 'details', 'reason']) {
      const nested = extractErrorMessage(record[key], depth + 1);
      if (nested) {
        return nested;
      }
    }

    try {
      const serialized = JSON.stringify(error);
      if (serialized && serialized !== '{}') {
        return serialized;
      }
    } catch {
      // ignore serialization errors
    }
  }

  return '';
}

function normalizeError(error: unknown) {
  return extractErrorMessage(error) || 'Не удалось проверить обновления.';
}

function explainCommonUpdaterError(message: string) {
  const normalized = message.toLowerCase();

  if (/404|not found/.test(normalized)) {
    return 'latest.json не найден на GitHub Releases. Нужно опубликовать не draft release с файлом latest.json в assets.';
  }

  if (/401|403|forbidden|unauthorized/.test(normalized)) {
    return 'GitHub Release недоступен без авторизации. Для автообновления endpoint latest.json должен быть публично доступен.';
  }

  if (/signature|sig|pubkey|public key/.test(normalized)) {
    return 'Не прошла проверка подписи. Проверь, что TAURI_SIGNING_PRIVATE_KEY соответствует pubkey в tauri.conf.json.';
  }

  if (/manifest|json|parse|invalid/.test(normalized)) {
    return 'latest.json доступен, но имеет неверный формат. В нём должны быть version, platforms.windows-x86_64.url и signature.';
  }

  if (/timed out|timeout|network|dns|fetch|request|sending/.test(normalized)) {
    return 'Не удалось скачать latest.json. Проверь интернет, доступность GitHub и что release assets опубликованы.';
  }

  return '';
}

async function diagnoseUpdaterManifest(): Promise<string> {
  try {
    const raw = await fetchRemoteText(GITHUB_LATEST_JSON_URL, 'application/json, text/plain');
    const json = JSON.parse(raw) as Record<string, unknown>;
    const version = typeof json.version === 'string' ? json.version : '';
    const platforms = json.platforms as Record<string, unknown> | undefined;
    const windows = platforms?.['windows-x86_64'] as Record<string, unknown> | undefined;
    const hasUrl = typeof windows?.url === 'string' && windows.url.length > 0;
    const hasSignature = typeof windows?.signature === 'string' && windows.signature.length > 0;

    if (!version || !hasUrl || !hasSignature) {
      return 'latest.json найден, но он неполный: нужны version, platforms.windows-x86_64.url и platforms.windows-x86_64.signature.';
    }

    return `latest.json доступен, версия в manifest: ${version}. Если Tauri всё равно ругается, проверь подпись .sig/pubkey и что версия выше текущей ${appVersion}.`;
  } catch (error) {
    const message = normalizeError(error);
    return `${explainCommonUpdaterError(message) || 'latest.json недоступен или повреждён.'} Техническая ошибка: ${message}`;
  }
}

async function normalizeUpdaterError(error: unknown) {
  const message = normalizeError(error);
  const common = explainCommonUpdaterError(message);
  const manifestDiagnostic = await diagnoseUpdaterManifest();
  return [common, manifestDiagnostic, `Tauri updater: ${message}`].filter(Boolean).join(' ');
}

export async function checkForUpdates(channel: ReleaseChannel): Promise<UpdateInfo> {
  if (isTauriRuntime) {
    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      const update = await check({ timeout: 20000 });

      if (!update) {
        return {
          available: false,
          currentVersion: appVersion,
          source: 'tauri',
          status: 'idle',
          message: 'Установлена актуальная версия.'
        };
      }

      return {
        available: true,
        currentVersion: update.currentVersion,
        version: update.version,
        notes: update.body ?? 'Доступно новое обновление VKarmani Desktop.',
        publishedAt: update.date,
        source: 'tauri',
        status: 'available',
        message: `Доступна версия ${update.version}. Нажми кнопку обновления для установки.`
      };
    } catch (error) {
      return {
        available: false,
        currentVersion: appVersion,
        source: 'tauri',
        status: 'error',
        message: await normalizeUpdaterError(error)
      };
    }
  }

  await wait(850);

  return {
    available: true,
    currentVersion: appVersion,
    version: channel === 'beta' ? '0.13.9-beta.1' : '0.13.9',
    notes:
      channel === 'beta'
        ? 'Бета-канал: улучшено окно диагностики, доработана проверка обновлений и подготовлены tray-события.'
        : 'Стабильный канал: улучшена надёжность подключения, добавлены быстрые действия и подготовка к автообновлениям.',
    publishedAt: '2026-03-10T10:30:00Z',
    source: 'mock',
    status: 'available',
    message: 'Демо-проверка обновлений завершена.'
  };
}

export async function installAvailableUpdate(
  onProgress: (percent: number) => void
): Promise<{ ok: true } | { ok: false; message: string }> {
  if (isTauriRuntime) {
    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      const update = await check({ timeout: 20000 });

      if (!update) {
        return { ok: false, message: 'Новой версии не найдено.' };
      }

      let downloaded = 0;
      let total = 0;

      await update.downloadAndInstall((event: unknown) => {
        const payload = event as
          | { event?: string; data?: { contentLength?: number; chunkLength?: number } }
          | undefined;

        if (!payload?.event) {
          return;
        }

        if (payload.event === 'Started') {
          total = payload.data?.contentLength ?? 0;
          downloaded = 0;
          onProgress(2);
          return;
        }

        if (payload.event === 'Progress') {
          downloaded += payload.data?.chunkLength ?? 0;
          if (total > 0) {
            onProgress(Math.min(100, Math.round((downloaded / total) * 100)));
          }
          return;
        }

        if (payload.event === 'Finished') {
          onProgress(100);
        }
      });

      try {
        await restartNativeApplication();
      } catch {
        // На Windows updater может сам закрыть приложение перед установкой.
      }

      return { ok: true };
    } catch (error) {
      return { ok: false, message: await normalizeUpdaterError(error) };
    }
  }

  for (let percent = 8; percent <= 100; percent += 8) {
    await wait(120);
    onProgress(percent);
  }

  return { ok: true };
}
