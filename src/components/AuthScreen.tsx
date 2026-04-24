import {
  ArrowUpRight,
  Bot,
  CheckCircle2,
  ClipboardPaste,
  KeyRound,
  Shield,
  X
} from 'lucide-react';
import { tr, type UiLanguage } from '../i18n';
import type { IntegrationMeta } from '../types/vpn';

interface AuthScreenProps {
  accessKey: string;
  authLoading: boolean;
  errorText: string;
  integrationMeta: IntegrationMeta;
  language: UiLanguage;
  onAccessKeyChange: (value: string) => void;
  onAuthorize: () => void;
}

function detectAccessKeyKind(value: string) {
  const normalized = value.trim();

  if (!normalized) {
    return 'empty' as const;
  }

  if (/^https?:\/\//i.test(normalized)) {
    return 'url' as const;
  }

  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(normalized)) {
    return 'uuid' as const;
  }

  if (/^[A-Za-z0-9_-]{5,64}$/.test(normalized)) {
    return 'short-uuid' as const;
  }

  return 'raw' as const;
}

function summarizeAccessKey(value: string) {
  const normalized = value.trim();
  if (!normalized) {
    return '';
  }

  if (/^https?:\/\//i.test(normalized)) {
    try {
      const url = new URL(normalized);
      const tail = url.pathname.split('/').filter(Boolean).pop() ?? '';
      return `${url.host}${tail ? ` / …${tail.slice(-8)}` : ''}`;
    } catch {
      return normalized.length > 42 ? `${normalized.slice(0, 26)}…${normalized.slice(-10)}` : normalized;
    }
  }

  if (normalized.length > 42) {
    return `${normalized.slice(0, 14)}…${normalized.slice(-10)}`;
  }

  return normalized;
}

export function AuthScreen({
  accessKey,
  authLoading,
  errorText,
  integrationMeta,
  language,
  onAccessKeyChange,
  onAuthorize
}: AuthScreenProps) {
  const normalizedKey = accessKey.trim();
  const accessKeyKind = detectAccessKeyKind(accessKey);
  const canSubmit = Boolean(normalizedKey) && !authLoading;
  const hasClipboard = typeof navigator !== 'undefined' && 'clipboard' in navigator;
  const keyPreview = summarizeAccessKey(accessKey);
  const isError = Boolean(errorText);
  const statusTone = authLoading ? 'loading' : isError ? 'error' : normalizedKey ? 'ready' : 'idle';

  const helperText = {
    empty: tr(language, 'Вставьте short UUID, UUID, subscription URL или raw-ключ.', 'Paste a short UUID, UUID, subscription URL, or raw key.'),
    url: '',
    uuid: tr(language, 'Обнаружен UUID. Клиент попробует разрешить его через live-интеграцию и подготовить рабочий профиль.', 'A UUID was detected. The client will try to resolve it through the live integration and prepare a working profile.'),
    'short-uuid': tr(language, 'Обнаружен short UUID. Это быстрый формат для входа и последующей синхронизации профиля.', 'A short UUID was detected. This is a quick format for sign-in and profile sync.'),
    raw: tr(language, 'Обнаружен raw-ключ. Клиент проверит его и определит подходящий маршрут авторизации.', 'A raw key was detected. The client will validate it and determine the proper authorization route.')
  }[accessKeyKind];

  const statusTitle = {
    idle: tr(language, 'Готово к входу', 'Ready to sign in'),
    ready: tr(language, 'Ключ готов к проверке', 'Key is ready to verify'),
    loading: tr(language, 'Проверяем доступ', 'Checking access'),
    error: tr(language, 'Не удалось подтвердить ключ', 'Could not verify the key')
  }[statusTone];

  const statusBody = {
    idle: tr(language, 'Вставьте ключ доступа. После проверки клиент синхронизирует профиль и список серверов.', 'Paste your access key. After verification the client will sync your profile and server list.'),
    ready: helperText,
    loading: tr(language, 'Пожалуйста, подождите. Мы проверяем ключ и готовим профиль подключения.', 'Please wait. We are verifying the key and preparing the connection profile.'),
    error: errorText || tr(language, 'Проверьте формат ключа, доступ к сети или запросите новый ключ в Telegram-боте.', 'Check the key format, network access, or request a new key in the Telegram bot.')
  }[statusTone];

  const accessKeyTypeLabel = accessKeyKind === 'url'
    ? 'Subscription URL'
    : accessKeyKind === 'uuid'
      ? 'UUID'
      : accessKeyKind === 'short-uuid'
        ? 'Short UUID'
        : accessKeyKind === 'raw'
          ? tr(language, 'Raw key', 'Raw key')
          : tr(language, 'Ожидаем ключ', 'Waiting for key');

  const onKeyDown = (event: React.KeyboardEvent<HTMLInputElement>) => {
    if (event.key === 'Enter' && canSubmit) {
      onAuthorize();
    }
  };

  const handlePasteFromClipboard = async () => {
    if (!hasClipboard) {
      return;
    }

    try {
      const text = await navigator.clipboard.readText();
      if (text) {
        onAccessKeyChange(text.replace(/\s+/g, ' ').trim());
      }
    } catch {
      // Clipboard access can fail in some desktop/browser contexts.
    }
  };

  return (
    <div className="auth-grid compact-auth-grid auth-grid-v2 auth-grid-v3 auth-grid-v4 auth-grid-v5">
      <section className="auth-panel hero-panel compact-hero-panel auth-hero-v2 auth-hero-v3 auth-hero-v4 auth-hero-v5">
        <div className="auth-brand-lockup auth-brand-lockup-v4 auth-brand-lockup-v5">
          <img src="/assets/logo-dark.jpg" alt="VKarmani" className="auth-brand-logo" />
          <div>
            <strong>VKarmani Desktop</strong>
            <span>{tr(language, 'Безопасный VPN-клиент для ПК', 'Secure VPN client for desktop')}</span>
          </div>
        </div>

        <div className="auth-hero-copy-v2 auth-hero-copy-v3 auth-hero-copy-v4 auth-hero-copy-v5">
          <span className="chip auth-hero-chip">{tr(language, 'Вход по ключу доступа', 'Access key sign-in')}</span>
          <h1>{tr(language, 'Вставьте ключ и подключайтесь без лишних шагов.', 'Paste the key and connect without extra steps.')}</h1>
          <p>
            {tr(
              language,
              'Клиент сам проверит доступ, синхронизирует профиль и подготовит доступные серверы к подключению.',
              'The client will verify access, sync the profile, and prepare available servers for connection.'
            )}
          </p>
        </div>

        <div className="auth-mini-benefits auth-mini-benefits-v5 auth-mini-benefits-compact">
          <span><CheckCircle2 size={15} />{tr(language, 'Быстрый вход по ключу', 'Fast key sign-in')}</span>
          <span><CheckCircle2 size={15} />{tr(language, 'Синхронизация профиля и серверов', 'Profile and server sync')}</span>
          <span><CheckCircle2 size={15} />{tr(language, 'Proxy и TUN доступны после входа', 'Proxy and TUN after sign-in')}</span>
        </div>

        <div className="auth-hero-actions auth-hero-actions-v4 auth-hero-actions-v5 auth-hero-actions-compact">
          <a
            className="primary-button auth-link-button"
            href="https://t.me/VKarmani_VPN_bot"
            target="_blank"
            rel="noreferrer"
          >
            <Bot size={16} />
            {tr(language, 'Получить ключ', 'Get a key')}
          </a>
          <a
            className="ghost-button auth-link-button"
            href="https://www.vkarmani.com/"
            target="_blank"
            rel="noreferrer"
          >
            <ArrowUpRight size={16} />
            VKarmani.com
          </a>
        </div>
      </section>

      <section className="auth-panel form-panel compact-form-panel auth-form-v2 auth-form-v3 auth-form-v4 auth-form-v5">
        <div className="auth-form-shell auth-form-shell-v3 auth-form-shell-v4 auth-form-shell-v5">
          <div className="form-header auth-form-header-v2 auth-form-header-v3 auth-form-header-v4 auth-form-header-v5">
            <span className="chip subdued">{tr(language, 'Вход по ключу', 'Key sign-in')}</span>
            <h2>{tr(language, 'Подключение к VKarmani', 'Connect to VKarmani')}</h2>
          </div>

          <div className={`auth-status-strip auth-status-strip-${statusTone}`}>
            <div className="auth-status-strip-main">
              {statusTone === 'error' ? <Shield size={16} /> : <CheckCircle2 size={16} />}
              <strong>{statusTitle}</strong>
            </div>
            {normalizedKey ? <span className="auth-status-strip-type">{accessKeyTypeLabel}</span> : null}
          </div>

          <div className="auth-field-block auth-field-block-v5 auth-field-block-compact">
            <label className="field-label" htmlFor="access-key">
              {tr(language, 'Ключ доступа', 'Access key')}
            </label>
            <div className={`key-input-row auth-key-row-v2 auth-key-row-v4 auth-key-row-v5 ${normalizedKey ? 'is-filled' : ''}`}>
              <KeyRound size={18} />
              <input
                id="access-key"
                value={accessKey}
                onChange={(event: React.ChangeEvent<HTMLInputElement>) => onAccessKeyChange(event.target.value.replace(/\s+/g, ' ').trimStart())}
                onKeyDown={onKeyDown}
                autoComplete="off"
                spellCheck={false}
                placeholder={tr(language, 'Например: https://sub.example.com/abc123', 'Example: https://sub.example.com/abc123')}
              />
            </div>
            {(statusTone === 'error' ? statusBody : helperText) ? (
              <div className="auth-field-caption-row auth-field-caption-row-v5 auth-field-caption-row-compact">
                <span className="auth-field-caption">{statusTone === 'error' ? statusBody : helperText}</span>
              </div>
            ) : null}
          </div>

          <div className="auth-input-actions auth-input-actions-v4 auth-input-actions-v5 auth-input-actions-compact">
            <div className="auth-input-tools">
              {hasClipboard ? (
                <button type="button" className="ghost-button auth-inline-button" onClick={() => void handlePasteFromClipboard()}>
                  <ClipboardPaste size={15} />
                  {tr(language, 'Вставить из буфера', 'Paste from clipboard')}
                </button>
              ) : null}
              {normalizedKey ? (
                <button type="button" className="ghost-button auth-inline-button" onClick={() => onAccessKeyChange('')}>
                  <X size={15} />
                  {tr(language, 'Очистить', 'Clear')}
                </button>
              ) : null}
            </div>
            <span className="auth-input-hint">{tr(language, 'Можно вставить ключ и нажать Enter.', 'Paste the key and press Enter.')}</span>
          </div>

          <div className="auth-submit-row auth-submit-row-v3 auth-submit-row-v4 auth-submit-row-v5 auth-submit-row-compact">
            <button className="primary-button auth-submit-button auth-submit-button-v4 auth-submit-button-compact" onClick={onAuthorize} disabled={!canSubmit}>
              {authLoading ? tr(language, 'Проверяем ключ…', 'Checking key…') : tr(language, 'Подключиться', 'Connect')}
            </button>
          </div>

          <div className="auth-support-inline auth-support-inline-v5 auth-support-inline-compact">
            <span>{tr(language, 'Нет ключа?', 'No key?')}</span>
            <a href="https://t.me/VKarmani_VPN_bot" target="_blank" rel="noreferrer">Telegram</a>
            <a href="https://www.vkarmani.com/" target="_blank" rel="noreferrer">Сайт</a>
          </div>
        </div>
      </section>
    </div>
  );
}
