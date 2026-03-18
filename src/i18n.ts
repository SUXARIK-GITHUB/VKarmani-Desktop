export type UiLanguage = 'ru' | 'en';

export function tr(language: UiLanguage, ru: string, en: string) {
  return language === 'en' ? en : ru;
}

export function localeFor(language: UiLanguage) {
  return language === 'en' ? 'en-US' : 'ru-RU';
}
