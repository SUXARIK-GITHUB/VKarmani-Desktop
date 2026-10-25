import { Component, type ReactNode } from 'react';
import { tr } from '../i18n';
import packageJson from '../../package.json';

let incidentCounter = 0;
interface Props { children: (safeStart: boolean) => ReactNode }
interface State { failed: boolean; safeStart: boolean; incidentId: string; occurredAt: string }

export class RootErrorBoundary extends Component<Props, State> {
  state: State = { failed: false, safeStart: false, incidentId: '', occurredAt: '' };
  static getDerivedStateFromError(_error: unknown) {
    return { failed: true, incidentId: `ui-${Date.now().toString(36)}-${++incidentCounter}`, occurredAt: new Date().toISOString() };
  }
  render() {
    if (!this.state.failed) return this.props.children(this.state.safeStart);
    const language = typeof document !== 'undefined' && document.documentElement.lang.startsWith('en') ? 'en' : 'ru';
    // Never serialize the exception, stack, state, URLs, keys or native config.
    const report = JSON.stringify({ code: 'UI_RENDER_FAILED', incidentId: this.state.incidentId,
      occurredAt: this.state.occurredAt, version: packageJson.version, scope: 'renderer',
      fallbackStorageWrites: false, fallbackNetworkActions: false, nativeStatus: 'NOT_CHECKED' }, null, 2);
    return <main className="shell auth-shell"><section className="panel compact-panel" role="alert"
      style={{ position: 'relative', margin: 18, maxHeight: 'calc(100vh - 36px)', overflow: 'auto' }}>
      <h2>{tr(language, 'Интерфейс не удалось загрузить', 'The interface could not be loaded')}</h2>
      <p>{tr(language, 'Сохранённые данные не сбрасывались. Повторный запуск интерфейса отключит автоматические действия для этого сеанса.', 'Stored data was not reset. Retrying the interface disables automatic actions for this session.')}</p>
      <p>UI_RENDER_FAILED · {this.state.incidentId}</p>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}><button type="button" className="ghost-button" onClick={() => this.setState({ failed: false, safeStart: true })}>
        {tr(language, 'Повторить безопасно', 'Retry safely')}</button>
        <button type="button" className="ghost-button" onClick={() => {
          const url = URL.createObjectURL(new Blob([report], { type: 'application/json' }));
          const link = document.createElement('a'); link.href = url; link.download = 'VKarmani-ui-error.json';
          link.click(); window.setTimeout(() => URL.revokeObjectURL(url), 0);
        }}>{tr(language, 'Сохранить безопасный отчёт', 'Save safe report')}</button></div>
      <details><summary>{tr(language, 'Технические данные', 'Technical details')}</summary><pre>{report}</pre></details>
    </section></main>;
  }
}
