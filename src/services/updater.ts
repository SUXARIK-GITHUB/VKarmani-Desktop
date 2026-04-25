import type { ReleaseChannel, UpdateInfo } from '../types/vpn';
import { appVersion, isTauriRuntime } from './runtime';

const wait = (value: number) => new Promise<void>((resolve) => window.setTimeout(resolve, value));


function normalizeError(error: unknown) {
  return error instanceof Error ? error.message : 'Не удалось проверить обновления.';
}

function normalizeUpdaterError(error: unknown) {
  const message = normalizeError(error);
  const lowerMessage = message.toLowerCase();

  if (lowerMessage.includes('404') || lowerMessage.includes('not found')) {
    return [
      'Не удалось получить latest.json с GitHub Releases.',
      'Проверьте, что release опубликован, файл latest.json есть в Assets, а репозиторий или release-репозиторий публично доступен.',
      `Техническая ошибка: ${message}`
    ].join(' ');
  }

  if (/updater|endpoint|pubkey|signature|manifest|latest\.json/i.test(message)) {
    return [
      'Tauri updater не смог проверить обновления.',
      'Проверьте endpoint latest.json, pubkey, подпись .sig и публичную доступность GitHub Release.',
      `Техническая ошибка: ${message}`
    ].join(' ');
  }

  return message;
}

export async function checkForUpdates(channel: ReleaseChannel): Promise<UpdateInfo> {
  if (isTauriRuntime) {
    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      const update = await check({ timeout: 15000 });

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
        status: 'available'
      };
    } catch (error) {
      return {
        available: false,
        currentVersion: appVersion,
        source: 'tauri',
        status: 'error',
        message: normalizeUpdaterError(error)
      };
    }
  }

  await wait(450);

  return {
    available: false,
    currentVersion: appVersion,
    source: 'mock',
    status: 'idle',
    message: `Проверка обновлений доступна только в Tauri-сборке. Канал: ${channel}.`
  };
}

export async function installAvailableUpdate(
  onProgress: (percent: number) => void
): Promise<{ ok: true } | { ok: false; message: string }> {
  if (isTauriRuntime) {
    try {
      const { check } = await import('@tauri-apps/plugin-updater');
      const update = await check({ timeout: 15000 });

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

      return { ok: true };
    } catch (error) {
      return { ok: false, message: normalizeUpdaterError(error) };
    }
  }

  for (let percent = 8; percent <= 100; percent += 8) {
    await wait(120);
    onProgress(percent);
  }

  return { ok: true };
}
