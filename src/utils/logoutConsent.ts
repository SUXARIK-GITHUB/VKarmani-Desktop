import { tr, type UiLanguage } from '../i18n';

export function confirmLogout(language: UiLanguage, confirm: (message: string)=>boolean): boolean {
  return confirm(tr(language,
    'Выйти из аккаунта? Сохранённый ключ будет удалён, а активное VPN-подключение завершено.',
    'Sign out? The saved key will be removed and any active VPN connection will be disconnected.'));
}
