import { Component, type ErrorInfo, type ReactNode } from 'react';
import { tr, type UiLanguage } from '../i18n';

interface TabErrorBoundaryProps {
  language: UiLanguage;
  title?: string;
  children: ReactNode;
}

interface TabErrorBoundaryState {
  hasError: boolean;
  message?: string;
}

export class TabErrorBoundary extends Component<TabErrorBoundaryProps, TabErrorBoundaryState> {
  state: TabErrorBoundaryState = {
    hasError: false,
    message: undefined
  };

  static getDerivedStateFromError(error: Error): TabErrorBoundaryState {
    return {
      hasError: true,
      message: error.message
    };
  }

  componentDidCatch(error: Error, info: ErrorInfo) {
    console.error('TabErrorBoundary', error, info);
  }

  render() {
    if (this.state.hasError) {
      const { language, title } = this.props;
      return (
        <section className="panel compact-panel">
          <div className="panel-header compact compact-header-row">
            <div>
              <span className="chip subdued">{tr(language, 'Диагностика', 'Diagnostics')}</span>
              <h3>{title ?? tr(language, 'Раздел временно недоступен', 'Section is temporarily unavailable')}</h3>
            </div>
          </div>
          <div className="empty-state">
            <strong>{tr(language, 'Не удалось отрисовать раздел.', 'Failed to render this section.')}</strong>
            <span>{this.state.message ?? tr(language, 'Откройте раздел снова или перезапустите приложение.', 'Open the tab again or restart the app.')}</span>
          </div>
        </section>
      );
    }

    return this.props.children;
  }
}
