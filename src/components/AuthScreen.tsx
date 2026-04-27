import { useRef, useState } from 'react';
import {
  ArrowRight,
  ArrowUpRight,
  CheckCircle2,
  ClipboardPaste,
  Eye,
  EyeOff,
  Globe2,
  KeyRound,
  LockKeyhole,
  Rocket,
  ServerCog,
  Shield,
  ShieldCheck,
  Sparkles,
  X,
  Zap
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

  if (normalized.startsWith('https://sub.vkarmani.com/')) {
    return 'url' as const;
  }

  return 'invalid' as const;
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
  const [showAccessKey, setShowAccessKey] = useState(false);
  const normalizedKey = accessKey.trim();
  const accessKeyKind = detectAccessKeyKind(accessKey);
  const inputRef = useRef<HTMLInputElement | null>(null);
  const canSubmit = Boolean(normalizedKey) && accessKeyKind === 'url' && !authLoading;
  const hasClipboard = typeof navigator !== 'undefined' && 'clipboard' in navigator;
  const keyPreview = summarizeAccessKey(accessKey);
  const isError = Boolean(errorText);
  const statusTone = authLoading ? 'loading' : isError ? 'error' : normalizedKey ? 'ready' : 'idle';

  const helperText = {
    empty: tr(language, 'Вставьте ключ доступа VKarmani, который начинается с https://sub.vkarmani.com/.', 'Paste a VKarmani access key that starts with https://sub.vkarmani.com/.'),
    url: tr(language, 'Обнаружена ссылка VKarmani. Проверим профиль и импортируем серверы.', 'VKarmani URL detected. We will verify the profile and import servers.'),
    invalid: tr(language, 'Принимаются только ключи VKarmani формата https://sub.vkarmani.com/....', 'Only VKarmani keys in the format https://sub.vkarmani.com/... are accepted.')
  }[accessKeyKind];

  const statusTitle = {
    idle: tr(language, 'Ожидаем ключ доступа', 'Waiting for access key'),
    ready: tr(language, 'Ключ готов к проверке', 'Key is ready to verify'),
    loading: tr(language, 'Проверяем доступ', 'Checking access'),
    error: tr(language, 'Не удалось подтвердить ключ', 'Could not verify the key')
  }[statusTone];

  const statusBody = {
    idle: tr(language, 'После проверки VKarmani синхронизирует профиль Remnawave и подготовит список серверов.', 'After verification VKarmani will sync the Remnawave profile and prepare the server list.'),
    ready: helperText,
    loading: tr(language, 'Проверяем ключ, импортируем профиль и подготавливаем защищённый маршрут.', 'Verifying the key, importing the profile, and preparing a secure route.'),
    error: errorText || tr(language, 'Проверьте формат ключа, доступ к сети или запросите новый ключ.', 'Check the key format, network access, or request a new key.')
  }[statusTone];

  const accessKeyTypeLabel = accessKeyKind === 'url'
    ? 'VKarmani URL'
    : accessKeyKind === 'invalid'
      ? tr(language, 'Неверный формат', 'Invalid format')
      : tr(language, 'Ключ не введён', 'No key entered');

  const onKeyDown = async (event: React.KeyboardEvent<HTMLInputElement>) => {
    const input = inputRef.current;
    const isShortcut = event.ctrlKey || event.metaKey;
    const key = event.key.toLowerCase();

    if (isShortcut && input) {
      if (key === 'v' && hasClipboard) {
        event.preventDefault();
        try {
          const text = await navigator.clipboard.readText();
          const start = input.selectionStart ?? accessKey.length;
          const end = input.selectionEnd ?? accessKey.length;
          onAccessKeyChange(`${accessKey.slice(0, start)}${text}${accessKey.slice(end)}`);
        } catch {
          // Native WebView can still handle paste if clipboard API is blocked.
        }
        return;
      }

      if (key === 'c' && hasClipboard) {
        const start = input.selectionStart ?? 0;
        const end = input.selectionEnd ?? 0;
        if (end > start) {
          event.preventDefault();
          await navigator.clipboard.writeText(accessKey.slice(start, end)).catch(() => undefined);
        }
        return;
      }

      if (key === 'x' && hasClipboard) {
        const start = input.selectionStart ?? 0;
        const end = input.selectionEnd ?? 0;
        if (end > start) {
          event.preventDefault();
          await navigator.clipboard.writeText(accessKey.slice(start, end)).catch(() => undefined);
          onAccessKeyChange(`${accessKey.slice(0, start)}${accessKey.slice(end)}`);
        }
        return;
      }
    }

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
    <div className="auth-redesign-screen">
      <section className="auth-redesign-hero">
        <div className="auth-orbital-bg" aria-hidden="true">
          <span />
          <span />
          <span />
        </div>

        <div className="auth-brand-lockup">
          <img src="/assets/logo-vkarmani.png" alt="VKarmani" className="auth-brand-logo" />
          <div>
            <strong>VKarmani</strong>
            <span>{tr(language, 'VPN без границ', 'VPN without borders')}</span>
          </div>
        </div>

        <div className="auth-hero-copy-v5">
          <span className="chip auth-hero-chip"><Sparkles size={14} />{tr(language, 'Доступ по ключу Remnawave', 'Remnawave key access')}</span>
          <h1>{tr(language, 'Активируйте защищённый интернет в один шаг.', 'Activate secure internet in one step.')}</h1>
          <p>
            {tr(
              language,
              'Вставьте ключ доступа: клиент сам проверит профиль, подтянет серверы и подготовит подключение без лишних окон.',
              'Paste your access key: the client will verify the profile, import servers, and prepare the connection without extra screens.'
            )}
          </p>
        </div>

        <div className="auth-step-strip">
          <article>
            <span>1</span>
            <strong>{tr(language, 'Получите ключ', 'Get a key')}</strong>
            <small>{tr(language, 'На сайте или в Telegram', 'On the website or Telegram')}</small>
          </article>
          <article>
            <span>2</span>
            <strong>{tr(language, 'Активируйте', 'Activate')}</strong>
            <small>{tr(language, 'Вставьте ключ ниже', 'Paste the key below')}</small>
          </article>
          <article>
            <span>3</span>
            <strong>{tr(language, 'Подключитесь', 'Connect')}</strong>
            <small>{tr(language, 'Нажмите одну кнопку', 'Press one button')}</small>
          </article>
        </div>
      </section>

      <section className="auth-redesign-card">
        <div className={`auth-status-strip auth-status-strip-${statusTone}`}>
          <div className="auth-status-strip-main">
            {statusTone === 'error' ? <Shield size={18} /> : statusTone === 'loading' ? <ServerCog size={18} /> : <CheckCircle2 size={18} />}
            <div>
              <strong>{statusTitle}</strong>
              <span>{statusBody}</span>
            </div>
          </div>
          <span className="auth-status-strip-type">{accessKeyTypeLabel}</span>
        </div>

        <div className="auth-field-block auth-field-block-v5">
          <label className="field-label" htmlFor="access-key">
            {tr(language, 'Ключ доступа', 'Access key')}
          </label>
          <div className={`key-input-row auth-key-row-v5 ${normalizedKey ? 'is-filled' : ''}`}>
            <KeyRound size={19} />
            <input
              id="access-key"
              ref={inputRef}
              type={showAccessKey ? 'text' : 'password'}
              value={accessKey}
              onChange={(event: React.ChangeEvent<HTMLInputElement>) => onAccessKeyChange(event.target.value.replace(/\s+/g, ' ').trimStart())}
              onKeyDown={onKeyDown}
              autoComplete="off"
              spellCheck={false}
              placeholder={tr(language, 'https://sub.vkarmani.com/ваш-ключ', 'https://sub.vkarmani.com/your-key')}
            />
            {normalizedKey ? (
              <button
                type="button"
                className="key-visibility-button"
                onClick={() => setShowAccessKey((current) => !current)}
                aria-label={showAccessKey ? tr(language, 'Скрыть ключ доступа', 'Hide access key') : tr(language, 'Показать ключ доступа', 'Show access key')}
                title={showAccessKey ? tr(language, 'Скрыть ключ доступа', 'Hide access key') : tr(language, 'Показать ключ доступа', 'Show access key')}
              >
                {showAccessKey ? <EyeOff size={17} /> : <Eye size={17} />}
              </button>
            ) : null}
            {hasClipboard ? (
              <button type="button" className="key-visibility-button" onClick={() => void handlePasteFromClipboard()} title={tr(language, 'Вставить из буфера', 'Paste from clipboard')}>
                <ClipboardPaste size={17} />
              </button>
            ) : null}
            {normalizedKey ? (
              <button type="button" className="key-visibility-button" onClick={() => onAccessKeyChange('')} title={tr(language, 'Очистить', 'Clear')}>
                <X size={17} />
              </button>
            ) : null}
          </div>
          <div className="auth-field-caption-row auth-field-caption-row-v5">
            <span className="auth-field-caption">{keyPreview || helperText}</span>
          </div>
        </div>

        <div className="auth-submit-row auth-submit-row-v5">
          <button className="primary-button auth-submit-button" onClick={onAuthorize} disabled={!canSubmit}>
            {authLoading ? <ServerCog size={18} /> : <Rocket size={18} />}
            {authLoading ? tr(language, 'Проверяем ключ…', 'Checking key…') : tr(language, 'Проверить ключ и войти', 'Verify key and sign in')}
            <ArrowRight size={18} />
          </button>
        </div>

        <div className="auth-info-grid">
          <article>
            <Zap size={18} />
            <strong>{tr(language, 'Быстро и надёжно', 'Fast and reliable')}</strong>
            <span>{tr(language, 'Серверы импортируются из вашего профиля Remnawave.', 'Servers are imported from your Remnawave profile.')}</span>
          </article>
          <article>
            <ShieldCheck size={18} />
            <strong>{tr(language, 'Приватность под защитой', 'Privacy protected')}</strong>
            <span>{tr(language, 'Ключ хранится в защищённом хранилище Windows.', 'The key is stored in protected Windows storage.')}</span>
          </article>
          <article>
            <Globe2 size={18} />
            <strong>{tr(language, 'Где взять ключ?', 'Where to get a key?')}</strong>
            <span>{integrationMeta.isConfigured ? integrationMeta.modeLabel : tr(language, 'Официальный сайт VKarmani и Telegram-бот.', 'VKarmani official website and Telegram bot.')}</span>
          </article>
        </div>

        <div className="auth-support-inline auth-support-inline-v5">
          <LockKeyhole size={16} />
          <span>{tr(language, 'Нет ключа?', 'No key?')}</span>
          <a href="https://t.me/VKarmani_VPN_bot" target="_blank" rel="noreferrer">Telegram</a>
          <a href="https://www.vkarmani.com/" target="_blank" rel="noreferrer">
            {tr(language, 'Перейти на сайт', 'Open website')}
            <ArrowUpRight size={14} />
          </a>
        </div>
      </section>
    </div>
  );
}
