import type { ReleaseChannel, UpdateInfo } from '../types/vpn';
import { appVersion, isTauriRuntime } from './runtime';

const GITHUB_RELEASES_API = 'https://api.github.com/repos/SUXARIK-GITHUB/VKarmani-Desktop/releases';
const GITHUB_LATEST_API = 'https://api.github.com/repos/SUXARIK-GITHUB/VKarmani-Desktop/releases/latest';

function normalizeError(error: unknown) {
  if (error instanceof Error) {
    return error.message;
  }
  if (typeof error === 'string') {
    return error;
  }
  return 'Не удалось проверить обновления.';
}

function normalizeUpdaterError(error: unknown) {
  const message = normalizeError(error);
  return /updater|endpoint|pubkey|signature|manifest|latest\.json/i.test(message)
    ? 'Tauri updater не настроен или release manifest недоступен. Проверьте tauri.conf.json, latest.json и pubkey.'
    : message;
}

function parseVersion(value: string) {
  const clean = value.trim().replace(/^v/i, '').split('-')[0];
  const [major = '0', minor = '0', patch = '0'] = clean.split('.');
  return [Number.parseInt(major, 10) || 0, Number.parseInt(minor, 10) || 0, Number.parseInt(patch, 10) || 0] as const;
}

function isVersionNewer(candidate: string, current: string) {
  const next = parseVersion(candidate);
  const now = parseVersion(current);

  for (let index = 0; index < 3; index += 1) {
    if (next[index] > now[index]) {
      return true;
    }
    if (next[index] < now[index]) {
      return false;
    }
  }

  return false;
}

async function parseGitHubError(response: Response) {
  try {
    const payload = (await response.json()) as { message?: string };
    if (payload.message) {
      return payload.message;
    }
  } catch {
    // ignore parsing issues
  }
  return `${response.status} ${response.statusText}`.trim();
}

type GitHubRelease = {
  tag_name?: string;
  name?: string;
  body?: string;
  prerelease?: boolean;
  draft?: boolean;
  published_at?: string;
};

function toUpdateInfo(release: GitHubRelease): UpdateInfo {
  const latestVersion = (release.tag_name ?? '').replace(/^v/i, '');

  if (!latestVersion) {
    return {
      available: false,
      currentVersion: appVersion,
      source: 'github',
      status: 'idle',
      message: 'Релизы на GitHub не найдены.'
    };
  }

  if (!isVersionNewer(latestVersion, appVersion)) {
    return {
      available: false,
      currentVersion: appVersion,
      source: 'github',
      status: 'idle',
      message: 'Новых релизов на GitHub не найдено.'
    };
  }

  return {
    available: true,
    currentVersion: appVersion,
    version: latestVersion,
    notes: release.body ?? release.name ?? 'Доступен новый релиз на GitHub.',
    publishedAt: release.published_at,
    source: 'github',
    status: 'available',
    message: 'Найден новый релиз в GitHub.'
  };
}

async function fetchWithTimeout(url: string) {
  const controller = new AbortController();
  const timeout = window.setTimeout(() => controller.abort(), 15000);
  try {
    return await fetch(url, {
      headers: { Accept: 'application/vnd.github+json' },
      signal: controller.signal
    });
  } finally {
    window.clearTimeout(timeout);
  }
}

async function fetchGitHubRelease(channel: ReleaseChannel): Promise<UpdateInfo> {
  const errors: string[] = [];

  if (channel !== 'beta') {
    const latestResponse = await fetchWithTimeout(GITHUB_LATEST_API);
    if (latestResponse.ok) {
      const release = (await latestResponse.json()) as GitHubRelease;
      return toUpdateInfo(release);
    }
    errors.push(`latest: ${await parseGitHubError(latestResponse)}`);
  }

  const releasesResponse = await fetchWithTimeout(GITHUB_RELEASES_API);
  if (!releasesResponse.ok) {
    errors.push(`list: ${await parseGitHubError(releasesResponse)}`);
    throw new Error(errors.join(' | '));
  }

  const releases = (await releasesResponse.json()) as GitHubRelease[];
  const filtered = releases.filter((release) => {
    if (release.draft) {
      return false;
    }
    return channel === 'beta' ? true : !release.prerelease;
  });

  const latest = filtered[0];
  if (!latest) {
    return {
      available: false,
      currentVersion: appVersion,
      source: 'github',
      status: 'idle',
      message: 'Релизы на GitHub не найдены.'
    };
  }

  return toUpdateInfo(latest);
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
      try {
        const githubResult = await fetchGitHubRelease(channel);
        return {
          ...githubResult,
          message: githubResult.available
            ? `Tauri updater недоступен: ${normalizeUpdaterError(error)}. Показываем релиз из GitHub.`
            : `Tauri updater недоступен: ${normalizeUpdaterError(error)}. ${githubResult.message ?? ''}`.trim()
        };
      } catch (githubError) {
        return {
          available: false,
          currentVersion: appVersion,
          source: 'tauri',
          status: 'error',
          message: `Не удалось проверить обновления через Tauri и GitHub: ${normalizeUpdaterError(error)} | ${normalizeError(githubError)}`
        };
      }
    }
  }

  try {
    return await fetchGitHubRelease(channel);
  } catch (error) {
    return {
      available: false,
      currentVersion: appVersion,
      source: 'github',
      status: 'error',
      message: `Не удалось получить релизы из GitHub: ${normalizeError(error)}`
    };
  }
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

  onProgress(0);
  return {
    ok: false,
    message:
      'Вы запущены в web-preview. Установка обновления доступна только в Tauri-сборке. Для кода из GitHub используйте git pull в репозитории.'
  };
}
