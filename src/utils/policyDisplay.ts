import { tr, type UiLanguage } from '../i18n';
import type { SplitTunnelEntry } from '../types/vpn';

export function policyEntryDisplay(entry: SplitTunnelEntry, language: UiLanguage) {
  const generic = entry.kind === 'app' ? tr(language, 'Приложение', 'Application') : tr(language, 'Служба', 'Service');
  // Quarantined malformed records have no trustworthy display identity. Do not
  // replace their stored originals or invent a name; show only a local status.
  if (entry.invalidReason && (entry.value.startsWith('<invalid ') || /^[{[]/.test(entry.value.trim()))) return { name: generic, detail: '' };
  const name = entry.value.split(/[\\/]/).pop()?.trim() || generic;
  return { name, detail: entry.value === name ? '' : entry.value };
}
