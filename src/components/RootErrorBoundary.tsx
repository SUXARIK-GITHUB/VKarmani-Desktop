import { Component, type ReactNode } from 'react';
import { tr, type UiLanguage } from '../i18n';
import { copyInformation } from '../utils/clipboard';
import { createFrontendCrashReceipt, recordFrontendCrash, type FrontendCrashReceipt } from '../services/crashReceipts';

interface Props { children: ReactNode }
interface State { receipt: FrontendCrashReceipt | null; copied: boolean | null; handoffFailed: boolean }

export class RootErrorBoundary extends Component<Props, State> {
  state: State = { receipt: null, copied: null, handoffFailed: false };
  private disposed = false;
  private stopHandoff: (() => void) | null = null;

  static getDerivedStateFromError(failure: unknown): Partial<State> {
    return { receipt: createFrontendCrashReceipt('UI_RENDER_FAILED', failure) };
  }

  componentDidCatch() {
    if (this.state.receipt) recordFrontendCrash(this.state.receipt);
    // App's effects were unmounted by React. Keep its existing durable flush/
    // native ACK barrier available for an explicit tray Quit/Restart request.
    // Rendering the fallback itself never requests an exit or changes a VPN.
    void import('../services/stateHandoff').then(service => service.listenForStateHandoff({
      quiesce: () => undefined,
      resume: () => undefined,
      error: () => { if (!this.disposed) this.setState({ handoffFailed: true }); }
    })).then(stop => {
      if (this.disposed) stop();
      else this.stopHandoff = stop;
    }).catch(() => { if (!this.disposed) this.setState({ handoffFailed: true }); });
  }

  componentWillUnmount() { this.disposed = true; this.stopHandoff?.(); }

  render() {
    const receipt = this.state.receipt;
    if (!receipt) return this.props.children;
    const language: UiLanguage = typeof document !== 'undefined' && document.documentElement.lang === 'en' ? 'en' : 'ru';
    return (
      <main className="shell app-shell" aria-labelledby="crash-title">
        <section className="panel compact-panel" role="alert">
          <h1 id="crash-title">{tr(language, 'Не удалось открыть интерфейс VKarmani', 'VKarmani could not display its interface')}</h1>
          <p>{tr(language, 'Соединение может оставаться активным. Для штатного выхода или перезапуска используйте меню в трее.', 'Your connection may still be active. Use the tray menu for a normal exit or restart.')}</p>
          <p>{tr(language, 'Перезапуск сохранит только подтверждённые и доступные к записи изменения. Если сохранение невозможно, выход будет отменён.', 'Restart preserves acknowledged changes and pending writes that can be saved. If saving fails, exit is cancelled.')}</p>
          <p><code>{receipt.code}</code> · {receipt.appVersion} · <time dateTime={receipt.timestamp}>{new Date(receipt.timestamp).toLocaleString(language === 'en' ? 'en-US' : 'ru-RU')}</time></p>
          <button type="button" className="ghost-button" onClick={() => {
            void copyInformation(JSON.stringify(receipt, null, 2), navigator.clipboard).then(copied => { if (!this.disposed) this.setState({ copied }); });
          }}>{tr(language, 'Скопировать сведения об ошибке', 'Copy error details')}</button>
          {this.state.copied !== null && <p role="status">{this.state.copied ? tr(language, 'Скопировано', 'Copied') : tr(language, 'Копирование недоступно. Код ошибки указан выше.', 'Copy unavailable. The error code is shown above.')}</p>}
          {this.state.handoffFailed && <p>{tr(language, 'Безопасное завершение не подтверждено. Настройки не сбрасывались. Не запускайте второй экземпляр.', 'Safe shutdown was not confirmed. Settings were not reset. Do not start a second instance.')}</p>}
        </section>
      </main>
    );
  }
}
